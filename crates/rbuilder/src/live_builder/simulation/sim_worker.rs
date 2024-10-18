use crate::{
    building::{
        sim::{NonceKey, OrderSimResult, SimulatedResult},
        simulate_order, BlockState,
    },
    live_builder::simulation::CurrentSimulationContexts,
    telemetry,
    telemetry::add_sim_thread_utilisation_timings,
    utils::ProviderFactoryReopener,
};
use ahash::HashMap;
use reth_db::database::Database;
use reth_payload_builder::database::SyncCachedReads as CachedReads;
use reth_provider::StateProvider;
use revm_primitives::ChainAddress;
use std::{
    sync::{Arc, Mutex},
    thread::sleep,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::error;

/// Function that continuously looks for a SimulationContext on ctx and when it finds one it polls its "request for simulation" channel (SimulationContext::requests).
/// When the channel closes it goes back to waiting for a new SimulationContext.
/// It's blocking so it's expected to run in its own thread.
pub fn run_sim_worker<DB: Database + Clone + Send + 'static>(
    worker_id: usize,
    ctx: Arc<Mutex<CurrentSimulationContexts>>,
    provider_factory: HashMap<u64, ProviderFactoryReopener<DB>>,
    global_cancellation: CancellationToken,
) {
    loop {
        if global_cancellation.is_cancelled() {
            return;
        }
        let current_sim_context = loop {
            let next_ctx = {
                let ctxs = ctx.lock().unwrap();
                ctxs.contexts.iter().next().map(|(_, c)| c.clone())
            };
            // @Perf chose random context so its more fair when we have 2 instead of 1
            if let Some(ctx) = next_ctx {
                break ctx;
            } else {
                // contexts are created for a duration of the slot so this is not a problem
                sleep(Duration::from_millis(50));
            }
            sleep(Duration::from_millis(500));
        };

        //TODO Brecht: fix
        let chain_id = 167010;

        println!("Brecht: simming 3");

        let provider_factory = match provider_factory[&chain_id].check_consistency_and_reopen_if_needed(
            current_sim_context.block_ctx[&chain_id].block_env.number.to(),
        ) {
            Ok(provider_factory) => provider_factory,
            Err(err) => {
                error!(?err, "Error while reopening provider factory");
                continue;
            }
        };

        let mut cached_reads = CachedReads::default();
        let mut last_sim_finished = Instant::now();
        while let Ok(task) = current_sim_context.requests.recv() {
            let sim_thread_wait_time = last_sim_finished.elapsed();
            let sim_start = Instant::now();

            // let state_provider = match provider_factory
            //     .history_by_block_hash(current_sim_context.block_ctx[&chain_id].attributes.parent)
            // {
            //     Ok(state_provider) => state_provider,
            //     Err(err) => {
            //         error!(?err, "Error while getting state for block");
            //         // break here so we can try to get new context
            //         // @Metric
            //         break;
            //     }
            // };
            let start_time = Instant::now();
            //let providers: HashMap = HashMap::default();
            //providers.insert(chain_id, Arc::new(state_provider.clone()));
            //providers.insert(160010, Arc::new(state_provider));

            let mut state_for_sim: HashMap<u64, Arc<dyn StateProvider>> = HashMap::default();
            println!("sim 2 chain_id: {}", chain_id);
            // TODO(Brecht)
            state_for_sim.insert(
                160010,
                Arc::<dyn StateProvider>::from(provider_factory.history_by_block_hash(current_sim_context.block_ctx[&chain_id].attributes.parent).expect("failed to open state provider")),
            );
            state_for_sim.insert(
                167010,
                Arc::<dyn StateProvider>::from(provider_factory.history_by_block_hash(current_sim_context.block_ctx[&chain_id].attributes.parent).expect("failed to open state provider")),
            );

            let mut block_state = BlockState::new_arc(state_for_sim).with_cached_reads(cached_reads);
            let sim_result = simulate_order(
                task.parents.clone(),
                task.order.clone(),
                &current_sim_context.block_ctx[&chain_id],
                &mut block_state,
            );
            match sim_result {
                Ok(sim_result) => {
                    let sim_ok = match &sim_result.result {
                        OrderSimResult::Success(simulated_order, nonces_after) => {
                            println!("sim okay for: {:?} -> {:?}", task, sim_result);
                            let result = SimulatedResult {
                                id: task.id,
                                simulated_order: simulated_order.clone(),
                                previous_orders: task.parents,
                                nonces_after: nonces_after
                                    .into_iter()
                                    .map(|(address, nonce)| NonceKey { address: ChainAddress(task.order.chain_id().unwrap(), address.clone()), nonce: nonce.clone() })
                                    .collect(),
                                simulation_time: start_time.elapsed(),
                            };
                            let result_send = current_sim_context
                                .results
                                .try_send(result);
                            println!("sending result: {:?}", result_send);
                            true
                        }
                        OrderSimResult::Failed(_) => false,
                    };
                    telemetry::inc_simulated_orders(sim_ok);
                    telemetry::inc_simulation_gas_used(sim_result.gas_used);
                }
                Err(err) => {
                    error!(?err, "Critical error while simulating order");
                    // @Metric
                    break;
                }
            }
            (cached_reads, _, _) = block_state.into_parts();

            last_sim_finished = Instant::now();
            let sim_thread_work_time = sim_start.elapsed();
            add_sim_thread_utilisation_timings(
                sim_thread_work_time,
                sim_thread_wait_time,
                worker_id,
            );
        }
    }
}
