use crate::{
    building::{
        sim::{NonceKey, OrderSimResult, SimulatedResult},
        simulate_order, BlockState,
    },
    live_builder::simulation::CurrentSimulationContexts,
    telemetry,
    telemetry::add_sim_thread_utilisation_timings,
};
use ahash::HashMap;
use reth_payload_builder::database::SyncCachedReads as CachedReads;
use reth_provider::StateProviderFactory;
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
pub fn run_sim_worker<P>(
    worker_id: usize,
    ctx: Arc<Mutex<CurrentSimulationContexts>>,
    providers: HashMap<u64, P>,
    global_cancellation: CancellationToken,
) where
    P: StateProviderFactory,
{
    loop {
        if global_cancellation.is_cancelled() {
            return;
        }
        let current_sim_context = loop {
            let next_ctx = {
                let ctxs = ctx.lock().unwrap();
                ctxs.contexts.iter().next().map(|(_, c)| c.clone())
            };
            if let Some(ctx) = next_ctx {
                break ctx;
            } else {
                sleep(Duration::from_millis(50));
            }
            sleep(Duration::from_millis(500));
        };

        let state_providers = providers
            .iter()
            .map(|(chain_id, provider)| {
                let provider = provider
                    .history_by_block_hash(
                        current_sim_context
                            .block_ctx
                            .chains
                            .get(chain_id)
                            .unwrap()
                            .attributes
                            .parent,
                    )
                    .unwrap();
                (*chain_id, Arc::from(provider))
            })
            .collect::<HashMap<_, _>>();

        let mut cached_reads = CachedReads::default();
        let mut last_sim_finished = Instant::now();
        while let Ok(task) = current_sim_context.requests.recv() {
            let sim_thread_wait_time = last_sim_finished.elapsed();
            let sim_start = Instant::now();

            let start_time = Instant::now();
            let mut block_state =
                BlockState::new_arc(state_providers.clone()).with_cached_reads(cached_reads);
            let sim_result = simulate_order(
                task.parents.clone(),
                task.order.clone(),
                &current_sim_context.block_ctx,
                &mut block_state,
            );
            match sim_result {
                Ok(sim_result) => {
                    let sim_ok = match &sim_result.result {
                        OrderSimResult::Success(simulated_order, nonces_after) => {
                            println!("[rb] sim okay for: {:?} -> {:?}", task, sim_result);
                            let result = SimulatedResult {
                                id: task.id,
                                simulated_order: simulated_order.clone(),
                                previous_orders: task.parents,
                                nonces_after: nonces_after
                                    .iter()
                                    .map(|(address, nonce)| NonceKey {
                                        address: ChainAddress(
                                            task.order.chain_id().unwrap(),
                                            *address,
                                        ),
                                        nonce: *nonce,
                                    })
                                    .collect(),
                                simulation_time: start_time.elapsed(),
                            };
                            let result_send = current_sim_context.results.try_send(result);
                            println!("[rb] sending result: {:?}", result_send);
                            true
                        }
                        OrderSimResult::Failed(_) => false,
                    };
                    telemetry::inc_simulated_orders(sim_ok);
                    telemetry::inc_simulation_gas_used(sim_result.gas_used);
                }
                Err(err) => {
                    error!(?err, "Critical error while simulating order");
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
