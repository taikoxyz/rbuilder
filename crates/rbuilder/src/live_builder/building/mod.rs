use std::{marker::PhantomData, sync::Arc, time::Duration};

use crate::{
    building::{
        builders::{
            BlockBuildingAlgorithm, BlockBuildingAlgorithmInput, UnfinishedBlockBuildingSinkFactory,
        },
        BlockBuildingContext,
    },
    live_builder::{payload_events::MevBoostSlotData, simulation::SlotOrderSimResults},
    roothash::run_trie_prefetcher,
};
use ahash::HashMap;
use reth_db::Database;
use reth_provider::{DatabaseProviderFactory, StateProviderFactory};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use super::{
    order_input::{
        self, order_replacement_manager::OrderReplacementManager, orderpool::OrdersForBlock,
    },
    payload_events,
    simulation::OrderSimulationPool,
};

#[derive(Debug)]
pub struct BlockBuildingPool<P, DB> {
    providers: HashMap<u64, P>,
    builders: Vec<Arc<dyn BlockBuildingAlgorithm<P, DB>>>,
    sink_factory: Box<dyn UnfinishedBlockBuildingSinkFactory>,
    orderpool_subscribers: HashMap<u64, order_input::OrderPoolSubscriber>,
    order_simulation_pool: OrderSimulationPool<P>,
    run_sparse_trie_prefetcher: bool,
    phantom: PhantomData<DB>,
}

impl<P, DB> BlockBuildingPool<P, DB>
where
    DB: Database + Clone + 'static,
    P: DatabaseProviderFactory<DB> + StateProviderFactory + Clone + 'static,
{
    pub fn new(
        providers: HashMap<u64, P>,
        builders: Vec<Arc<dyn BlockBuildingAlgorithm<P, DB>>>,
        sink_factory: Box<dyn UnfinishedBlockBuildingSinkFactory>,
        orderpool_subscribers: HashMap<u64, order_input::OrderPoolSubscriber>,
        order_simulation_pool: OrderSimulationPool<P>,
        run_sparse_trie_prefetcher: bool,
    ) -> Self {
        BlockBuildingPool {
            providers,
            builders,
            sink_factory,
            orderpool_subscribers,
            order_simulation_pool,
            run_sparse_trie_prefetcher,
            phantom: PhantomData,
        }
    }

    /// Connects OrdersForBlock->OrderReplacementManager->Simulations and calls start_building_job
    pub fn start_block_building(
        &mut self,
        payload: payload_events::MevBoostSlotData,
        block_ctx: BlockBuildingContext,
        global_cancellation: CancellationToken,
        max_time_to_build: Duration,
    ) {
        let block_cancellation: CancellationToken = global_cancellation.child_token();

        let cancel = block_cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(max_time_to_build).await;
            cancel.cancel();
        });

        // add OrderReplacementManager to manage replacements and cancellations
        // sink removal is automatic via OrderSink::is_alive false
        let mut orders_for_blocks = HashMap::default();
        for (chain_id, orderpool_subscriber) in self.orderpool_subscribers.iter_mut() {
            let (orders_for_block, sink) = OrdersForBlock::new_with_sink();
            let _block_sub = orderpool_subscriber.add_sink(
                block_ctx.chains[chain_id].block_env.number.to(),
                Box::new(OrderReplacementManager::new(Box::new(sink))),
            );
            orders_for_blocks.insert(*chain_id, orders_for_block);
        }

        let simulations_for_block = self.order_simulation_pool.spawn_simulation_job(
            block_ctx.clone(),
            orders_for_blocks,
            block_cancellation.clone(),
        );
        self.start_building_job(
            block_ctx,
            payload,
            simulations_for_block,
            block_cancellation,
        );
    }

    /// Per each BlockBuildingAlgorithm creates BlockBuildingAlgorithmInput and Sinks and spawn a task to run it
    fn start_building_job(
        &mut self,
        ctx: BlockBuildingContext,
        slot_data: MevBoostSlotData,
        input: SlotOrderSimResults,
        cancel: CancellationToken,
    ) {
        // Brecht: start building
        let builder_sink = self.sink_factory.create_sink(slot_data, cancel.clone());
        let (broadcast_input, _) = broadcast::channel(10_000);

        for builder in self.builders.iter() {
            let builder_name = builder.name();

            debug!(
                /* block = block_number,  */ builder_name,
                "Spawning builder job"
            );
            let input = BlockBuildingAlgorithmInput::<P> {
                providers: self.providers.clone(),
                ctx: ctx.clone(),
                input: broadcast_input.subscribe(),
                sink: builder_sink.clone(),
                cancel: cancel.clone(),
            };
            let builder = builder.clone();
            tokio::task::spawn_blocking(move || {
                builder.build_blocks(input);
            });
        }

        if self.run_sparse_trie_prefetcher {
            let input = broadcast_input.subscribe();

            // Spawn a prefetcher task for each chain
            for (chain_id, provider) in self.providers.clone() {
                let chain_input = input.resubscribe();
                let chain_cancel = cancel.clone();
                let chain_ctx = ctx.clone();

                tokio::task::spawn_blocking(move || {
                    run_trie_prefetcher(
                        chain_ctx.chains[&chain_id].attributes.parent,
                        chain_ctx.chains[&chain_id].shared_sparse_mpt_cache.clone(),
                        provider,
                        chain_input,
                        chain_cancel,
                    );
                    debug!(chain = chain_id, "Stopped trie prefetcher job");
                });
            }
        }

        tokio::spawn(multiplex_job(input.orders, broadcast_input));
    }
}

async fn multiplex_job<T>(mut input: mpsc::Receiver<T>, sender: broadcast::Sender<T>) {
    // we don't worry about waiting for input forever because it will be closed by producer job
    while let Some(input) = input.recv().await {
        // we don't create new subscribers to the broadcast so here we can be sure that err means end of receivers
        if sender.send(input).is_err() {
            return;
        }
    }
    trace!("Cancelling multiplex job");
}
