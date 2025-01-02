pub mod base_config;
pub mod block_output;
pub mod building;
pub mod cli;
pub mod config;
pub mod layer2_info;
pub mod order_input;
pub mod payload_events;
pub mod simulation;
pub mod watchdog;
pub mod gwyneth;

use crate::{
    building::{
        builders::{BlockBuildingAlgorithm, UnfinishedBlockBuildingSinkFactory},
        BlockBuildingContext, ChainBlockBuildingContext,
    },
    live_builder::{
        order_input::{start_orderpool_jobs, OrderInputConfig},
        simulation::OrderSimulationPool,
        watchdog::spawn_watchdog_thread,
    },
    telemetry::inc_active_slots,
    utils::{error_storage::spawn_error_storage_writer, Signer},
};
use ahash::{HashMap, HashSet};
use alloy_chains::Chain;
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::{Address, B256, U256};
use building::BlockBuildingPool;
use ethers::core::k256::pkcs8::der::EncodeValue;
use eyre::Context;
use gwyneth::{EthApiStream, GwynethNodes};
use jsonrpsee::RpcModule;
use payload_events::MevBoostSlotData;
use reth::{primitives::Header, providers::HeaderProvider};
use reth_chainspec::ChainSpec;
use reth_db::Database;
use reth_provider::{DatabaseProviderFactory, StateProviderFactory};
use std::{cmp::min, path::PathBuf, sync::Arc, time::Duration};
use std::{fmt::Debug, thread::sleep};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

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
pub struct LiveBuilder<P, DB, BlocksSourceType>
where
    DB: Database + Clone + 'static,
    P: StateProviderFactory + Clone,
    BlocksSourceType: SlotSource,
{
    pub watchdog_timeout: Duration,
    pub error_storage_path: Option<PathBuf>,
    pub simulation_threads: usize,
    pub order_input_config: OrderInputConfig,
    pub blocks_source: BlocksSourceType,
    pub run_sparse_trie_prefetcher: bool,

    pub chain_chain_spec: Arc<ChainSpec>,
    pub provider: P,

    pub coinbase_signer: Signer,
    pub extra_data: Vec<u8>,
    pub blocklist: HashSet<Address>,

    pub global_cancellation: CancellationToken,
    pub l1_ethapi: Option<Arc<dyn EthApiStream>>,

    pub sink_factory: Box<dyn UnfinishedBlockBuildingSinkFactory>,
    pub builders: Vec<Arc<dyn BlockBuildingAlgorithm<P, DB>>>,
    pub extra_rpc: RpcModule<()>,

    pub gwyneth_nodes: GwynethNodes<P>,
}

impl<P, DB, BlocksSourceType: SlotSource> LiveBuilder<P, DB, BlocksSourceType>
where
    DB: Database + Clone + 'static,
    P: DatabaseProviderFactory<DB> + StateProviderFactory + HeaderProvider + Clone + 'static,
    BlocksSourceType: SlotSource,
{
    pub fn with_extra_rpc(self, extra_rpc: RpcModule<()>) -> Self {
        Self { extra_rpc, ..self }
    }

    pub fn with_builders(self, builders: Vec<Arc<dyn BlockBuildingAlgorithm<P, DB>>>) -> Self {
        Self { builders, ..self }
    }

    pub async fn run(mut self) -> eyre::Result<()> {
        println!("[rb] Cecilia ==> LiveBuilder::run");
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

        // Cecilia!: call start_orderpool_jobs L1
        let mut orderpool_subscribers = HashMap::default();
        let orderpool_subscriber = {
            self.order_input_config.skip = true;
            let (handle, sub) = start_orderpool_jobs(
                self.order_input_config,
                self.provider.clone(),
                self.l1_ethapi.clone(),
                self.extra_rpc,
                self.global_cancellation.clone(),
            )
            .await?;
            inner_jobs_handles.push(handle);
            sub
        };
        orderpool_subscribers.insert(self.chain_chain_spec.chain.id(), orderpool_subscriber);

        let mut providers = HashMap::default();
        providers.insert(self.chain_chain_spec.chain.id(), self.provider.clone());

        // Cecilia!: call start_orderpool_jobs L2
        println!("[rb] WTF how many nodes are there? {:?}", self.gwyneth_nodes.nodes.len());
        for (chain_id, node) in self.gwyneth_nodes.nodes.iter() {
            let orderpool_subscriber = {
                let (handle, sub) = start_orderpool_jobs(
                    node.order_input_config.clone(),
                    node.provider.clone(),
                    Some(node.ethapi.clone()),
                    RpcModule::new(()),
                    self.global_cancellation.clone(),
                )
                .await?;
                inner_jobs_handles.push(handle);
                sub
            };
            orderpool_subscribers.insert(*chain_id, orderpool_subscriber);
            providers.insert(*chain_id, node.provider.clone());
        }


        let order_simulation_pool = {
            OrderSimulationPool::new(
                providers.clone(),
                self.simulation_threads,
                self.global_cancellation.clone(),
            )
        };

        let mut builder_pool = BlockBuildingPool::new(
            providers.clone(),
            self.builders,
            self.sink_factory,
            orderpool_subscribers,
            order_simulation_pool,
            self.run_sparse_trie_prefetcher,
        );

        let watchdog_sender = spawn_watchdog_thread(self.watchdog_timeout)?;

        let mut all_chain_ids = vec![self.chain_chain_spec.chain.id()];
        all_chain_ids.append(&mut providers.keys().cloned().collect::<Vec<_>>());

        while let Some(payload) = payload_events_channel.recv().await {
            println!("[rb] Payload_attributes event received");
            println!("[rb] Parent block's hash: {:?}", payload.parent_block_hash());

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

            // this is the parent L1 block where we should build the L2 blocs upon
            let parent_header = { 
                // @Nicer
                let parent_block = payload.parent_block_hash();
                let timestamp = payload.timestamp();
                println!("[rb] LiveBuilder.run against 💥  {} {:?}", payload.block() - 1, parent_block);

                match wait_for_block_header(parent_block, timestamp, &self.provider).await {
                    Ok(header) => header, 
                    Err(err) => {
                        warn!("Failed to get parent header for new slot: {:?}", err);
                        continue;
                    }
                }
            };

            debug!(
                slot = payload.slot(),
                block = payload.block(),
                "Got header for slot"
            );

            inc_active_slots();

            println!("[rb] Dani debug: build block context");
            let mut all_block_ctxs = HashMap::default();
            let l1_block_ctx = ChainBlockBuildingContext::from_attributes(
                payload.payload_attributes_event.clone(),
                &parent_header,
                self.coinbase_signer.clone(),
                self.chain_chain_spec.clone(),
                self.blocklist.clone(),
                Some(payload.suggested_gas_limit),
                self.extra_data.clone(),
                None,
            );
            all_block_ctxs.insert(self.chain_chain_spec.chain.id(), l1_block_ctx.clone());
            // TODO(Brecht): hack to wait until latest L2 block is also created, which is later then when we get the payload build event
            // sleep(Duration::from_millis(4000));

            // TODO: Brecht

            for (idx, (&chain_id, _)) in providers.iter().enumerate() {
                if l1_block_ctx.chain_spec.chain.id() == chain_id {
                    continue;
                }
                // The first idx is L1, the rests should be in-order
                self.gwyneth_nodes.sync(idx - 1, parent_header.number, payload.parent_block_hash()).await?;

                println!("[rb] setting up {}", chain_id);
                let mut block_ctx = l1_block_ctx.clone();
                // This shoud be build upon the parent L1 block
                // query the synced L1 block inside this L2 node and see if they match
                // if it's sycned one is lower, then wait
                let latest_header = self
                    .gwyneth_nodes
                    .get_latest_header(chain_id) 
                    .await?;
                if let Some(latest_header) = latest_header {
                    // TODO: hash_slow?
                    block_ctx.attributes.parent = latest_header.hash();
                    block_ctx.block_env.number = U256::from(latest_header.number + 1);
                } else {
                    println!("[rb] failed to get latest block for {}", chain_id);
                }
                // TODO(Cecilia): should read ChainSpecs for different chains, not just changing the chain_id
                let mut chain_spec = (*block_ctx.chain_spec).clone();;
                chain_spec.chain = Chain::from(chain_id);
                block_ctx.chain_spec = chain_spec.into();
                
                println!(
                    "Latest block hash for {} is {}",
                    chain_id, block_ctx.attributes.parent
                );
                all_block_ctxs.insert(chain_id, block_ctx);
            }

            let super_block_ctx = BlockBuildingContext::from_attributes(
                self.chain_chain_spec.chain.id(),
                all_block_ctxs,
                Some(self.coinbase_signer.clone()),
            );

            println!("[rb] Start building");
            builder_pool.start_block_building(
                payload,
                super_block_ctx,
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

// async fn get_layer2_infos(chain_id: U256) -> Result<(), Box<dyn std::error::Error>> {
    // Let's just pretend this info is already set up somewhere as Layer2Info but for now
    // i'm just constructing it here.
    // let urls = vec![
    //     "http://localhost:10110".to_string(),
    // ];

    // let (ipc_paths, data_dirs) = self.resolve_l2_paths()?;

    // let layer2_info = Some(Layer2Info::new(ipc_paths, data_dirs).await?);

    // match layer2_info.get_latest_block(chain_id).await? {
    //     Some(latest_block) => println!("[rb] Latest block: {:?}", latest_block),
    //     None => println!("[rb] Chain ID not found"),
    // }

//     Ok(())
// }

/// May fail if we wait too much (see [BLOCK_HEADER_DEAD_LINE_DELTA])
async fn wait_for_block_header<P>(
    block: B256,
    slot_time: OffsetDateTime,
    provider: P,
) -> eyre::Result<Header>
where
    P: HeaderProvider,
{
    let dead_line = slot_time + BLOCK_HEADER_DEAD_LINE_DELTA;
    while OffsetDateTime::now_utc() < dead_line {
        if let Some(header) = provider.header(&block)? {
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
