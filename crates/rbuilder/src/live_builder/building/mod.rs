use std::{sync::Arc, time::Duration};

use crate::{
    building::{
        builders::{
            BlockBuildingAlgorithm, BlockBuildingAlgorithmInput, UnfinishedBlockBuildingSinkFactory,
        },
        BlockBuildingContext,
    },
    live_builder::{payload_events::MevBoostSlotData, simulation::SlotOrderSimResults},
    utils::ProviderFactoryReopener,
};
use ahash::HashMap;
use reth_db::database::Database;
use reth_provider::ProviderFactory;
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
pub struct BlockBuildingPool<DB> {
    provider_factory: HashMap<u64, ProviderFactoryReopener<DB>>,
    builders: Vec<Arc<dyn BlockBuildingAlgorithm<DB>>>,
    sink_factory: Box<dyn UnfinishedBlockBuildingSinkFactory>,
    orderpool_subscribers: HashMap<u64, order_input::OrderPoolSubscriber>,
    order_simulation_pool: OrderSimulationPool<DB>,
}

impl<DB: Database + Clone + 'static> BlockBuildingPool<DB> {
    pub fn new(
        provider_factory: HashMap<u64, ProviderFactoryReopener<DB>>,
        builders: Vec<Arc<dyn BlockBuildingAlgorithm<DB>>>,
        sink_factory: Box<dyn UnfinishedBlockBuildingSinkFactory>,
        orderpool_subscribers: HashMap<u64, order_input::OrderPoolSubscriber>,
        order_simulation_pool: OrderSimulationPool<DB>,
    ) -> Self {
        BlockBuildingPool {
            provider_factory,
            builders,
            sink_factory,
            orderpool_subscribers,
            order_simulation_pool,
        }
    }

    /// Connects OrdersForBlock->OrderReplacementManager->Simulations and calls start_building_job
    pub fn start_block_building(
        &mut self,
        payload: payload_events::MevBoostSlotData,
        block_ctx: HashMap<u64, BlockBuildingContext>,
        global_cancellation: CancellationToken,
        max_time_to_build: Duration,
    ) {
        let block_cancellation = global_cancellation.child_token();

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
                block_ctx[chain_id].block_env.number.to(),
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
        ctx: HashMap<u64, BlockBuildingContext>,
        slot_data: MevBoostSlotData,
        input: SlotOrderSimResults,
        cancel: CancellationToken,
    ) {
        // Brecht: start building
        let builder_sink = self.sink_factory.create_sink(slot_data, cancel.clone());
        let (broadcast_input, _) = broadcast::channel(10_000);

        let provider_factories: HashMap<u64, ProviderFactory<DB>> = self
            .provider_factory.iter().map(|(chain_id, provider_factory)| {
                let block_number = ctx[chain_id].block_env.number.to::<u64>();
                match provider_factory.check_consistency_and_reopen_if_needed(block_number)
                {
                    Ok(provider_factory) => (*chain_id, provider_factory),
                    Err(err) => {
                        panic!("Error while reopening provider factory");
                    }
                }
            }).collect();

        for builder in self.builders.iter() {
            //let builder_name = builder.name();
            //debug!(block = block_number, builder_name, "Spawning builder job");
            let input = BlockBuildingAlgorithmInput::<DB> {
                provider_factory: provider_factories.clone(),
                ctx: ctx.clone(),
                input: broadcast_input.subscribe(),
                sink: builder_sink.clone(),
                cancel: cancel.clone(),
            };
            let builder = builder.clone();
            tokio::task::spawn_blocking(move || {
                builder.build_blocks(input);
                //debug!(block = block_number, builder_name, "Stopped builder job");
            });
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
