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
        BlockBuildingContext, ChainBlockBuildingContext
    },
    live_builder::{
        order_input::{start_orderpool_jobs, OrderInputConfig},
        simulation::OrderSimulationPool,
        watchdog::spawn_watchdog_thread,
    },
    primitives::{MempoolTx, Order, TransactionSignedEcRecoveredWithBlobs},
    provider::StateProviderFactory,
    telemetry::inc_active_slots,
    utils::{
        error_storage::spawn_error_storage_writer, provider_head_state::ProviderHeadState, Signer,
    },
};
use ahash::{HashMap, HashSet};
use alloy_consensus::Header;
use alloy_chains::{Chain, ChainKind};
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::{Address, B256, U256};
use building::BlockBuildingPool;
use eyre::Context;
use jsonrpsee::RpcModule;
use order_input::ReplaceableOrderPoolCommand;
use payload_events::MevBoostSlotData;
use reth::transaction_pool::{
    BlobStore, EthPooledTransaction, Pool, TransactionListenerKind, TransactionOrdering,
    TransactionPool, TransactionValidator,
};
use reth_chainspec::ChainSpec;
use reth_evm::provider;
use revm_primitives::ChainAddress;
use reth_primitives::TransactionSignedEcRecovered;
use std::{cmp::min, fmt::Debug, path::PathBuf, sync::Arc, thread::sleep, time::Duration};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use layer2_info::Layer2Info;

#[derive(Debug, Clone)]
pub struct TimingsConfig {
    /// Time the proposer have to propose a block from the beginning of the
    /// slot (https://www.paradigm.xyz/2023/04/mev-boost-ethereum-consensus Slot anatomy)
    pub slot_proposal_duration: Duration,
    /// Delta from slot time to get_header dead line. If we can't get the block header
    /// before slot_time + BLOCK_HEADER_DEAD_LINE_DELTA we cancel the slot.
    /// Careful: It's signed and usually negative since we need de header BEFORE the slot time.
    pub block_header_deadline_delta: time::Duration,
    /// Polling period while trying to get a block header
    pub get_block_header_period: time::Duration,
}

impl TimingsConfig {
    /// Classic rbuilder
    pub fn ethereum() -> Self {
        Self {
            slot_proposal_duration: Duration::from_secs(4),
            block_header_deadline_delta: time::Duration::milliseconds(-2500),
            get_block_header_period: time::Duration::milliseconds(250),
        }
    }

    /// Configuration for OP-based chains with fast block times
    pub fn optimism() -> Self {
        Self {
            slot_proposal_duration: Duration::from_secs(0),
            block_header_deadline_delta: time::Duration::milliseconds(-25),
            get_block_header_period: time::Duration::milliseconds(25),
        }
    }
}

/// Trait used to trigger a new block building process in the slot.
pub trait SlotSource {
    fn recv_slot_channel(self) -> mpsc::UnboundedReceiver<MevBoostSlotData>;
}

/// Max headers sent to the cleaning task before the main loop blocks.
/// Cleaning task is super fast so it should never lag behind block building, even 1 should be enough, 10 is super safe.
const CLEAN_TASKS_CHANNEL_SIZE: usize = 10;

/// Main builder struct.
/// Connects to the CL, get the new slots and builds blocks for each slot.
/// # Usage
/// Create and run()
#[derive(Debug)]
pub struct LiveBuilder<P, BlocksSourceType>
where
    P: StateProviderFactory,
    BlocksSourceType: SlotSource,
{
    pub watchdog_timeout: Option<Duration>,
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

    pub sink_factory: Box<dyn UnfinishedBlockBuildingSinkFactory>,
    pub builders: Vec<Arc<dyn BlockBuildingAlgorithm<P>>>,
    pub extra_rpc: RpcModule<()>,

    /// Notify rbuilder of new [`ReplaceableOrderPoolCommand`] flow via this channel.
    pub orderpool_sender: mpsc::Sender<ReplaceableOrderPoolCommand>,
    pub orderpool_receiver: mpsc::Receiver<ReplaceableOrderPoolCommand>,
    pub sbundle_merger_selected_signers: Arc<Vec<Address>>,

    pub layer2_info: Layer2Info<DB>,
}

impl<P, BlocksSourceType: SlotSource> LiveBuilder<P, BlocksSourceType>
where
    P: StateProviderFactory + Clone + 'static,
    BlocksSourceType: SlotSource,
{
    pub fn with_extra_rpc(self, extra_rpc: RpcModule<()>) -> Self {
        Self { extra_rpc, ..self }
    }

    pub fn with_builders_and_layer2_info(self, builders: Vec<Arc<dyn BlockBuildingAlgorithm<P>>>) -> Self {
        Self { builders, ..self }
    }

    pub async fn run(self) -> eyre::Result<()> {
        info!("Builder block list size: {}", self.blocklist.len(),);
        info!(
            "Builder coinbase address: {:?}",
            self.coinbase_signer.address
        );
        let timings = self.timings();

        if let Some(error_storage_path) = self.error_storage_path {
            spawn_error_storage_writer(error_storage_path, self.global_cancellation.clone())
                .await
                .with_context(|| "Error spawning error storage writer")?;
        }

        let mut inner_jobs_handles = Vec::new();
        let mut payload_events_channel = self.blocks_source.recv_slot_channel();

        let mut orderpool_subscribers = HashMap::default();
        let (header_sender, header_receiver) = mpsc::channel(CLEAN_TASKS_CHANNEL_SIZE);

        let orderpool_subscriber = {
            let (handle, sub) = start_orderpool_jobs(
                self.order_input_config,
                self.provider.clone(),
                self.extra_rpc,
                self.global_cancellation.clone(),
                self.orderpool_sender,
                self.orderpool_receiver,
                header_receiver,
            )
            .await?;
            inner_jobs_handles.push(handle);
            sub
        };
        orderpool_subscribers.insert(self.chain_chain_spec.chain.id(), orderpool_subscriber);

        let mut provider_factories: HashMap<u64, ProviderFactoryReopener<DB>> = HashMap::default();
        provider_factories.insert(self.chain_chain_spec.chain.id(), self.provider.clone());

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
            self.run_sparse_trie_prefetcher,
            self.sbundle_merger_selected_signers.clone(),
        );

        let watchdog_sender = match self.watchdog_timeout {
            Some(duration) => Some(spawn_watchdog_thread(
                duration,
                "block build started".to_string(),
            )?),
            None => {
                info!("Watchdog not enabled");
                None
            }
        };

        let mut all_chain_ids = vec![self.chain_chain_spec.chain.id()];
        all_chain_ids.append(&mut provider_factories.keys().cloned().collect::<Vec<_>>());

        while let Some(payload) = payload_events_channel.recv().await {
            println!("Payload_attributes event received: {:?}", payload);

            if self.blocklist.contains(&payload.fee_recipient()) {
                warn!(
                    slot = payload.slot(),
                    "Fee recipient is in blocklist: {:?}",
                    payload.fee_recipient()
                );
                continue;
            }
            let current_time = OffsetDateTime::now_utc();
            // see if we can get parent header in a reasonable time
            let time_to_slot = payload.timestamp() - current_time;
            debug!(
                slot = payload.slot(),
                block = payload.block(),
                ?current_time,
                payload_timestamp = ?payload.timestamp(),
                ?time_to_slot,
                parent_hash = ?payload.parent_block_hash(),
                provider_head_state = ?ProviderHeadState::new(&self.provider),
                "Received payload, time till slot timestamp",
            );

            let time_until_slot_end = time_to_slot + timings.slot_proposal_duration;
            if time_until_slot_end.is_negative() {
                warn!(
                    slot = payload.slot(),
                    parent_hash = ?payload.parent_block_hash(),
                    "Slot already ended, skipping block building"
                );
                continue;
            };

            let parent_header = {
                // @Nicer
                let parent_block = payload.parent_block_hash();
                let timestamp = payload.timestamp();
                // TODO(Brecht)
                //let provider_factory = self.provider_factory.clone().provider_factory_unchecked();
                //match wait_for_block_header(parent_block, timestamp, &provider_factory).await {
                match wait_for_block_header(parent_block, timestamp, &self.provider, &timings).await
                {
                    Ok(header) => header,
                    Err(err) => {
                        warn!(parent_hash = ?payload.parent_block_hash(),"Failed to get parent header for new slot: {:?}", err);
                        continue;
                    }
                }
            };

            debug!(
                slot = payload.slot(),
                block = payload.block(),
                parent_hash = ?payload.parent_block_hash(),
                "Got header for slot"
            );

            // notify the order pool that there is a new header
            if let Err(err) = header_sender.send(parent_header.clone()).await {
                warn!("Failed to send header to builder pool: {:?}", err);
            }

            inc_active_slots();

            let root_hasher = Arc::from(self.provider.root_hasher(payload.parent_block_hash()));

            if let Some(block_ctx) = ChainBlockBuildingContext::from_attributes(
                payload.payload_attributes_event.clone(),
                &parent_header,
                self.coinbase_signer.clone(),
                self.chain_chain_spec.clone(),
                self.blocklist.clone(),
                Some(payload.suggested_gas_limit),
                self.extra_data.clone(),
                None,
                root_hasher,
            ) {
                builder_pool.start_block_building(
                    payload,
                    block_ctx,
                    self.global_cancellation.clone(),
                    time_until_slot_end.try_into().unwrap_or_default(),
                );

                // TODO(Brecht): hack to wait until latest L2 block is also created, which is later then when we get the payload build event
                sleep(Duration::from_millis(4000));

                println!("payload: {:?}", payload);

                // TODO: Brecht
                let mut chains = HashMap::default();
                for (&chain_id, _) in provider_factories.iter() {
                    println!("setting up {}", chain_id);
                    let mut block_ctx = block_ctx.clone();
                    let mut chain_spec = (*block_ctx.chain_spec).clone();
                    println!("chain spec chain id: {}", chain_spec.chain.id());
                    if chain_spec.chain.id() != chain_id {
                        println!("updating ctx for {}", chain_id);
                        let latest_block = self.layer2_info.get_latest_block(chain_id, BlockId::Number(BlockNumberOrTag::Latest)).await?;
                        if let Some(latest_block) = latest_block {
                            println!("[{}] Building on top of {:?}", chain_id, latest_block.header.hash);
                            //let reth_block: Block = latest_block.try_into().unwrap();
                            block_ctx = ChainBlockBuildingContext::from_attributes(
                                payload.payload_attributes_event.clone(),
                                &latest_block.header.clone().try_into().unwrap(),
                                self.coinbase_signer.clone(),
                                self.chain_chain_spec.clone(),
                                self.blocklist.clone(),
                                None,
                                Vec::new(),
                                None,
                            );
                            block_ctx.attributes.parent = latest_block.header.hash;
                            //block_ctx.attributes.parent_beacon_block_root = Some(B256::ZERO);
                            block_ctx.block_env.number = U256::from(latest_block.header.number + 1);
                            //block_ctx.block_env.basefee = U256::from(latest_block.header.base_fee_per_gas.unwrap_or_default()); // TODO(Brecht): need to calculate the new one?
                            //block_ctx.block_env.prevrandao = Some(B256::ZERO);
                            //block_ctx.block_env.difficulty = U256::ZERO;
                            //block_ctx.block_env.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::new(0));
                            block_ctx.block_env.coinbase = ChainAddress(chain_id, block_ctx.block_env.coinbase.1);
                        } else {
                            println!("failed to get latest block for {}", chain_id);
                        }
                        chain_spec.chain = Chain::from(chain_id);
                        chain_spec.genesis.config.chain_id = chain_id;
                        block_ctx.chain_spec = chain_spec.into();
                    }
                    println!("Latest block hash for {} is {}", chain_id, block_ctx.attributes.parent);
                    println!("[{}] attributes: {:?}", chain_id, block_ctx.attributes);
                    println!("[{}] block_env: {:?}", chain_id, block_ctx.block_env);
                    //println!("[{}]  block_ctx.chain_spec: {:?}", chain_id, block_ctx.chain_spec);
                    chains.insert(chain_id, block_ctx);
                }

                let super_block_ctx = BlockBuildingContext::from_attributes(
                    self.chain_chain_spec.chain.id(),
                    chains,
                    Some(self.coinbase_signer.clone()),
                );

                println!("Start building");
                builder_pool.start_block_building(
                    payload,
                    super_block_ctx,
                    self.global_cancellation.clone(),
                    time_until_slot_end.try_into().unwrap_or_default(),
                );

                if let Some(watchdog_sender) = watchdog_sender.as_ref() {
                    watchdog_sender.try_send(()).unwrap_or_default();
                };
            }
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

    /// Connect the builder to a reth [`TransactionPool`].
    ///
    /// This will
    /// 1. Add pending and queued transactions to the [`OrderPool`]
    /// 2. Subscribe to the pool directly, so the builder is not reliant on
    ///    IPC to be notified of new transactions.
    pub async fn connect_to_transaction_pool<V, T, S>(
        &self,
        pool: Pool<V, T, S>,
    ) -> Result<(), eyre::Error>
    where
        V: TransactionValidator<Transaction = EthPooledTransaction> + 'static,
        T: TransactionOrdering<Transaction = <V as TransactionValidator>::Transaction>,
        S: BlobStore,
    {
        // Initialize the orderpool with every item in the reth pool.
        for tx in pool
            .all_transactions()
            .pending_recovered()
            .chain(pool.all_transactions().queued_recovered())
        {
            try_send_to_orderpool(tx, self.orderpool_sender.clone(), pool.clone()).await;
        }

        // Subscribe to new transactions in-process.
        let mut recv = pool.new_transactions_listener_for(TransactionListenerKind::All);
        let orderpool_sender = self.orderpool_sender.clone();
        tokio::spawn(async move {
            while let Some(e) = recv.recv().await {
                let tx = e.transaction.transaction.transaction().clone();
                try_send_to_orderpool(tx, orderpool_sender.clone(), pool.clone()).await;
            }
        });

        Ok(())
    }

    // Currently we only need two timings config, depending on whether rbuilder is being
    // used in the optimism context. If further customisation is required in the future
    // this should be improved on.
    fn timings(&self) -> TimingsConfig {
        if cfg!(feature = "optimism") {
            TimingsConfig::optimism()
        } else {
            TimingsConfig::ethereum()
        }
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
async fn wait_for_block_header<P>(
    block: B256,
    slot_time: OffsetDateTime,
    provider: &P,
    timings: &TimingsConfig,
) -> eyre::Result<Header>
where
    P: StateProviderFactory,
{
    let deadline = slot_time + timings.block_header_deadline_delta;
    while OffsetDateTime::now_utc() < deadline {
        if let Some(header) = provider.header(&block)? {
            return Ok(header);
        } else {
            let time_to_sleep = min(
                deadline - OffsetDateTime::now_utc(),
                timings.get_block_header_period,
            );
            if time_to_sleep.is_negative() {
                break;
            }
            tokio::time::sleep(time_to_sleep.try_into().unwrap()).await;
        }
    }
    Err(eyre::eyre!("Block header not found"))
}

/// Attempts to forward a [`TransactionSignedEcRecovered`] to an orderpool.
///
/// Helper for [`LiveBuilder::connect_to_transaction_pool`].
///
/// Errors are handled internally with a log.
async fn try_send_to_orderpool<V, T, S>(
    tx: TransactionSignedEcRecovered,
    orderpool_sender: mpsc::Sender<ReplaceableOrderPoolCommand>,
    pool: Pool<V, T, S>,
) where
    V: TransactionValidator<Transaction = EthPooledTransaction> + 'static,
    T: TransactionOrdering<Transaction = <V as TransactionValidator>::Transaction>,
    S: BlobStore,
{
    match TransactionSignedEcRecoveredWithBlobs::try_from_tx_without_blobs_and_pool(tx, pool) {
        Ok(tx) => {
            let order = Order::Tx(MempoolTx::new(tx));
            let command = ReplaceableOrderPoolCommand::Order(order);
            if let Err(e) = orderpool_sender.send(command).await {
                error!("Error sending order to orderpool: {:#}", e);
            }
        }
        Err(e) => {
            error!("Error creating order from transaction: {:#}", e);
        }
    }
}
