pub mod base_config;
pub mod layer2_info;
pub mod block_output;
pub mod building;
pub mod cli;
pub mod config;
pub mod order_input;
pub mod payload_events;
pub mod simulation;
pub mod watchdog;

use crate::{
    building::{
        builders::{BlockBuildingAlgorithm, UnfinishedBlockBuildingSinkFactory},
        BlockBuildingContext
    },
    live_builder::{
        order_input::{start_orderpool_jobs, OrderInputConfig},
        simulation::OrderSimulationPool,
        watchdog::spawn_watchdog_thread,
    },
    telemetry::inc_active_slots,
    utils::{error_storage::spawn_error_storage_writer, ProviderFactoryReopener, Signer},
};
use ahash::{HashMap, HashSet};
use alloy_chains::{Chain, ChainKind};
use alloy_primitives::{Address, B256, U256};
use building::BlockBuildingPool;
use eyre::Context;
use jsonrpsee::RpcModule;
use payload_events::MevBoostSlotData;
use reth::{
    primitives::Header,
    providers::{HeaderProvider, ProviderFactory},
};
use reth_chainspec::ChainSpec;
use reth_db::database::Database;
use reth_evm::provider;
use std::{cmp::min, path::PathBuf, sync::Arc, thread::sleep, time::Duration};
use time::OffsetDateTime;
use tokio::{sync::mpsc, task::spawn_blocking};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use layer2_info::Layer2Info;

/// Time the proposer have to propose a block from the beginning of the slot (https://www.paradigm.xyz/2023/04/mev-boost-ethereum-consensus Slot anatomy)
const SLOT_PROPOSAL_DURATION: std::time::Duration = Duration::from_secs(4);
/// Delta from slot time to get_header dead line. If we can't get the block header before slot_time + BLOCK_HEADER_DEAD_LINE_DELTA we cancel the slot.
/// Careful: It's signed and usually negative since we need de header BEFORE the slot time.
const BLOCK_HEADER_DEAD_LINE_DELTA: time::Duration = time::Duration::milliseconds(-2500);
/// Polling period while trying to get a block header
const GET_BLOCK_HEADER_PERIOD: time::Duration = time::Duration::milliseconds(250);

/// Trait used to trigger a new block building process in the slot.
pub trait SlotSource {
    fn recv_slot_channel(self) -> mpsc::UnboundedReceiver<MevBoostSlotData>;
}

/// Main builder struct.
/// Connects to the CL, get the new slots and builds blocks for each slot.
/// # Usage
/// Create and run()
#[derive(Debug)]
pub struct LiveBuilder<DB, BlocksSourceType: SlotSource> {
    pub watchdog_timeout: Duration,
    pub error_storage_path: Option<PathBuf>,
    pub simulation_threads: usize,
    pub order_input_config: OrderInputConfig,
    pub blocks_source: BlocksSourceType,

    pub chain_chain_spec: Arc<ChainSpec>,
    pub provider_factory: ProviderFactoryReopener<DB>,

    pub coinbase_signer: Signer,
    pub extra_data: Vec<u8>,
    pub blocklist: HashSet<Address>,

    pub global_cancellation: CancellationToken,

    pub sink_factory: Box<dyn UnfinishedBlockBuildingSinkFactory>,
    pub builders: Vec<Arc<dyn BlockBuildingAlgorithm<DB>>>,
    pub extra_rpc: RpcModule<()>,
    pub layer2_info: Layer2Info<DB>,
}

impl<DB: Database + Clone + 'static, BuilderSourceType: SlotSource>
    LiveBuilder<DB, BuilderSourceType>
{
    pub fn with_extra_rpc(self, extra_rpc: RpcModule<()>) -> Self {
        Self { extra_rpc, ..self }
    }

    pub fn with_builders_and_layer2_info(self, builders: Vec<Arc<dyn BlockBuildingAlgorithm<DB>>>) -> Self {
        Self { builders, ..self }
    }

    pub async fn run(self) -> eyre::Result<()> {
        info!("Builder block list size: {}", self.blocklist.len(),);
        info!(
            "Builder coinbase address: {:?}",
            self.coinbase_signer.address
        );

        if let Some(error_storage_path) = self.error_storage_path {
            spawn_error_storage_writer(error_storage_path, self.global_cancellation.clone())
                .await
                .with_context(|| "Error spawning error storage writer")?;
        }

        let mut inner_jobs_handles = Vec::new();
        let mut payload_events_channel = self.blocks_source.recv_slot_channel();

        let mut orderpool_subscribers = HashMap::default();
        let orderpool_subscriber = {
            let (handle, sub) = start_orderpool_jobs(
                self.order_input_config,
                self.provider_factory.clone(),
                self.extra_rpc,
                self.global_cancellation.clone(),
            )
            .await?;
            inner_jobs_handles.push(handle);
            sub
        };
        orderpool_subscribers.insert(self.chain_chain_spec.chain.id(), orderpool_subscriber);

        let mut provider_factories: HashMap<u64, ProviderFactoryReopener<DB>> = HashMap::default();
        provider_factories.insert(self.chain_chain_spec.chain.id(), self.provider_factory.clone());

        for (chain_id, node) in self.layer2_info.nodes.iter() {
            let orderpool_subscriber = {
                let (handle, sub) = start_orderpool_jobs(
                    node.order_input_config.clone(),
                    node.provider_factory.clone(),
                    RpcModule::new(()),
                    self.global_cancellation.clone(),
                )
                .await?;
                inner_jobs_handles.push(handle);
                sub
            };
            orderpool_subscribers.insert(*chain_id, orderpool_subscriber);
            provider_factories.insert(*chain_id, node.provider_factory.clone());
        }

        let order_simulation_pool = {
            OrderSimulationPool::new(
                provider_factories.clone(),
                self.simulation_threads,
                self.global_cancellation.clone(),
            )
        };

        let mut builder_pool = BlockBuildingPool::new(
            provider_factories.clone(),
            self.builders,
            self.sink_factory,
            orderpool_subscribers,
            order_simulation_pool,
        );

        let watchdog_sender = spawn_watchdog_thread(self.watchdog_timeout)?;

        println!("Dani debug: Waiting for payload_attributes events");
        while let Some(payload) = payload_events_channel.recv().await {
            println!("Dani debug: payload_attributes event received");

            // Example: Get the latest block from Gwyneth Exexe (chain ID 167010)
            // ACCESS GWYNETH DATA BEGINS
            let gwyneth_chain_id = 167010;
            match self.layer2_info.get_latest_block(gwyneth_chain_id).await {
                Ok(Some(latest_block)) => println!("Latest Gwyneth block: {:?}", latest_block),
                Ok(None) => println!("No block found for Gwyneth"),
                Err(e) => eprintln!("Error getting Gwyneth block: {:?}", e),
            }
            // ACCESS GWYNETH DATA END

            if self.blocklist.contains(&payload.fee_recipient()) {
                warn!(
                    slot = payload.slot(),
                    "Fee recipient is in blocklist: {:?}",
                    payload.fee_recipient()
                );
                continue;
            }
            // see if we can get parent header in a reasonable time

            let time_to_slot = payload.timestamp() - OffsetDateTime::now_utc();
            debug!(
                slot = payload.slot(),
                block = payload.block(),
                ?time_to_slot,
                "Received payload, time till slot timestamp",
            );

            let time_until_slot_end = time_to_slot + SLOT_PROPOSAL_DURATION;
            if time_until_slot_end.is_negative() {
                warn!(
                    slot = payload.slot(),
                    "Slot already ended, skipping block building"
                );
                continue;
            };

            println!("Dani debug: gather parent header");
            let parent_header = {
                // @Nicer
                let parent_block = payload.parent_block_hash();
                println!("Parent block's hash: {:?}", parent_block);
                let timestamp = payload.timestamp();
                let provider_factory = self.provider_factory.clone().provider_factory_unchecked();
                match wait_for_block_header(parent_block, timestamp, &provider_factory).await {
                    Ok(header) => header,
                    Err(err) => {
                        warn!("Failed to get parent header for new slot: {:?}", err);
                        continue;
                    }
                }
            };

            println!("Dani debug: gather block hashes");
            {
                let provider_factory = self.provider_factory.clone();
                let block = payload.block();
                match spawn_blocking(move || {
                    provider_factory.check_consistency_and_reopen_if_needed(block)
                })
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(err)) => {
                        error!(?err, "Failed to check historical block hashes");
                        // This error is unrecoverable so we restart.
                        break;
                    }
                    Err(err) => {
                        error!(?err, "Failed to join historical block hashes task");
                        continue;
                    }
                }
            }

            debug!(
                slot = payload.slot(),
                block = payload.block(),
                "Got header for slot"
            );

            inc_active_slots();


            println!("Dani debug: build block context");
            let block_ctx = BlockBuildingContext::from_attributes(
                payload.payload_attributes_event.clone(),
                &parent_header,
                self.coinbase_signer.clone(),
                self.chain_chain_spec.clone(),
                self.blocklist.clone(),
                Some(payload.suggested_gas_limit),
                self.extra_data.clone(),
                None,
            );

            // TODO(Brecht): hack to wait until latest L2 block is also created, which is later then when we get the payload build event
            sleep(Duration::from_millis(4000));

            // TODO: Brecht
            let mut ctxs = HashMap::default();
            for (chain_id, _) in provider_factories.iter() {
                println!("setting up {}", chain_id);
                let mut block_ctx = block_ctx.clone();
                let mut chain_spec = (*block_ctx.chain_spec).clone();
                println!("chain spec chain id: {}", chain_spec.chain.id());
                if chain_spec.chain.id() != *chain_id {
                    println!("updating ctx for {}", chain_id);
                    let latest_block = self.layer2_info.get_latest_block(gwyneth_chain_id).await?;
                    if let Some(latest_block) = latest_block {
                        block_ctx.attributes.parent = latest_block.header.hash;
                        block_ctx.block_env.number = U256::from(latest_block.header.number + 1);
                    } else {
                        println!("failed to get latest block for {}", chain_id);
                    }
                    chain_spec.chain = Chain::from(*chain_id);
                    block_ctx.chain_spec = chain_spec.into();
                }
                println!("Latest block hash for {} is {}", chain_id, block_ctx.attributes.parent);
                ctxs.insert(*chain_id, block_ctx);
            }

            println!("Dani debug: start building");
            builder_pool.start_block_building(
                payload,
                ctxs,
                self.global_cancellation.clone(),
                time_until_slot_end.try_into().unwrap_or_default(),
            );

            watchdog_sender.try_send(()).unwrap_or_default();
        }

        info!("Builder shutting down");
        self.global_cancellation.cancel();
        for handle in inner_jobs_handles {
            handle
                .await
                .map_err(|err| warn!("Job handle await error: {:?}", err))
                .unwrap_or_default();
        }
        Ok(())
    }
}

async fn get_layer2_infos(chain_id: U256) -> Result<(), Box<dyn std::error::Error>> {
    // Let's just pretend this info is already set up somewhere as Layer2Info but for now
    // i'm just constructing it here.
    // let urls = vec![
    //     "http://localhost:10110".to_string(),
    // ];

    // let (ipc_paths, data_dirs) = self.resolve_l2_paths()?;

    // let layer2_info = Some(Layer2Info::new(ipc_paths, data_dirs).await?);

    // match layer2_info.get_latest_block(chain_id).await? {
    //     Some(latest_block) => println!("Latest block: {:?}", latest_block),
    //     None => println!("Chain ID not found"),
    // }

    Ok(())
}

/// May fail if we wait too much (see [BLOCK_HEADER_DEAD_LINE_DELTA])
async fn wait_for_block_header<DB: Database>(
    block: B256,
    slot_time: OffsetDateTime,
    provider_factory: &ProviderFactory<DB>,
) -> eyre::Result<Header> {
    let dead_line = slot_time + BLOCK_HEADER_DEAD_LINE_DELTA;
    while OffsetDateTime::now_utc() < dead_line {
        if let Some(header) = provider_factory.header(&block)? {
            return Ok(header);
        } else {
            let time_to_sleep = min(
                dead_line - OffsetDateTime::now_utc(),
                GET_BLOCK_HEADER_PERIOD,
            );
            if time_to_sleep.is_negative() {
                break;
            }
            tokio::time::sleep(time_to_sleep.try_into().unwrap()).await;
        }
    }
    Err(eyre::eyre!("Block header not found"))
}
