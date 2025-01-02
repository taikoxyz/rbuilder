use gwyneth::{
    cli::{create_gwyneth_nodes, GwynethArgs}, exex::{GwynethFullNode, L1ParentStates},
};
use rbuilder::{
    live_builder::{base_config::load_config_toml_and_env, cli::LiveBuilderConfig, config::{Config, RethInput}, gwyneth::{EthApiStream, EthTxSender, GwynethMempoolReciever}},
    telemetry,
};
use reth::{network::NetworkEventListenerProvider, rpc::{api::{eth::helpers::EthTransactions, NetApiClient}, eth::EthApiServer, types::Header}, transaction_pool::TransactionPool};
use reth_db_api::Database;
use reth_node_builder::{EngineNodeLauncher, NodeConfig};
use reth_provider::{
    providers::{BlockchainProvider, BlockchainProvider2},
    DatabaseProviderFactory, HeaderProvider, StateProviderFactory,
};
use std::{borrow::Borrow, path::PathBuf, pin::pin, process, sync::Arc};
use tokio::task;
use tracing::{error, instrument::WithSubscriber};

// Prefer jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> eyre::Result<()> {
    use clap::Parser;
    use reth::cli::Cli;
    use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};

    reth_cli_util::sigsegv_handler::install();

    if let Err(err) = Cli::<GwynethArgs>::parse().run(|builder, arg| async move {
        let l1_node_config = builder.config().clone();
        let task_executor = builder.task_executor().clone();
        let gwyneth_nodes = create_gwyneth_nodes(&arg, task_executor.clone(), &l1_node_config).await;
        let l1_parents = L1ParentStates::new(gwyneth_nodes.len());

        let enable_engine2 = arg.experimental;
        match enable_engine2 {
            true => {
                let (l2_providers, l2_ethapis) = gwyneth_nodes
                    .iter()
                    .map(|node| match node {
                        GwynethFullNode::Provider1(_) => {
                            panic!("Unexpected Provider: expect BlockchainProvider1")
                        }
                        GwynethFullNode::Provider2(n) => {
                            let ethapi: Arc<dyn EthApiStream> = Arc::new(n.rpc_registry.eth_handlers().pubsub.clone());
                            (n.provider.clone(), ethapi)
                        },
                    })
                    .collect::<(Vec<_>, Vec<_>)>();

                let l1_parents_ = l1_parents.clone();
                let handle = builder
                    .with_types_and_provider::<EthereumNode, BlockchainProvider2<_>>()
                    .with_components(EthereumNode::components())
                    .with_add_ons::<EthereumAddOns>()
                    .on_rpc_started(move |ctx, handles| {
                        println!("[rb] Cecilia ==> on_rpc_started");
                        let reth_input = RethInput {
                            l1_provider: ctx.provider().clone(),
                            l2_providers: l2_providers.clone(),
                            l1_parents: l1_parents_.clone(),
                            l1_ethapi: Some(Arc::new(ctx.registry.eth_handlers().pubsub.clone())),
                            l2_ethapis: Some(l2_ethapis.clone()),
                            l1_client: handles.rpc.http_client()
                        };
                        spawn_rbuilder(&arg, &l1_node_config, reth_input)
                    })
                    .install_exex("Rollup", move |ctx| async {
                        let rollup = gwyneth::exex::Rollup::new(ctx, gwyneth_nodes, l1_parents).await?;
                        Ok(rollup.start())
                    })
                    .launch_with_fn(|builder| {
                        let launcher = EngineNodeLauncher::new(
                            task_executor,
                            builder.config().datadir(),
                        );
                        builder.launch_with(launcher)
                    })
                    .await?;
                handle.node_exit_future.await
            }
            false => {
                let (l2_providers, l2_ethapis) = gwyneth_nodes
                    .iter()
                    .map(|node| match node {
                        GwynethFullNode::Provider1(n) => {
                            let ethapi: Arc<dyn EthApiStream> = Arc::new(n.rpc_registry.eth_handlers().pubsub.clone());
                            (n.provider.clone(), ethapi)
                        }
                        GwynethFullNode::Provider2(_) => {
                            panic!("Unexpected Provider: expect BlockchainProvider2")
                        }
                    })
                    .collect::<(Vec<_>, Vec<_>)>();

                let l1_parents_ = l1_parents.clone();
                let handle = builder
                    .with_types_and_provider::<EthereumNode, BlockchainProvider<_>>()
                    .with_components(EthereumNode::components())
                    .with_add_ons::<EthereumAddOns>()
                    .install_exex("Rollup", move |ctx| async {
                        Ok(gwyneth::exex::Rollup::new(ctx, gwyneth_nodes, l1_parents_)
                            .await?
                            .start())
                    })
                    .on_rpc_started(move |ctx, handles| {
                        let reth_input = RethInput {
                            l1_provider: ctx.provider().clone(),
                            l2_providers: l2_providers.clone(),
                            l1_parents: l1_parents.clone(),
                            l1_ethapi: Some(Arc::new(ctx.registry.eth_handlers().pubsub.clone())),
                            l2_ethapis: Some(l2_ethapis.clone()),
                            l1_client: handles.rpc.http_client()
                        };
                        spawn_rbuilder(&arg, &l1_node_config, reth_input)
                    })
                    .launch()
                    .await?;
                handle.node_exit_future.await
            }
        }
    }) {
        eprintln!("[rb] Error: {err:?}");
        std::process::exit(1);
    }
    Ok(())
}

/// Spawns a tokio rbuilder task.
///
/// Takes down the entire process if the rbuilder errors or stops.
fn spawn_rbuilder<P, DB>(
    arg: &GwynethArgs,
    l1_node_config: &NodeConfig,
    reth_input: RethInput<P>
) -> eyre::Result<()>
where
    DB: Database + Clone + 'static,
    P: DatabaseProviderFactory<DB> + StateProviderFactory + HeaderProvider + Clone + 'static,
{   
    let arg = arg.clone();
    let l1_node_config = l1_node_config.clone();
    let _handle = task::spawn(async move {
        let result = async {
            let mut config: Config = load_config_toml_and_env(
                arg.rbuilder_config.clone().expect("Gwyneth-rbuilder needs config path")
            )?;
            // Where we set L1 rpc, proposer pk and rollup contract address
            config.l1_config.update_in_process_setting(&l1_node_config);
            config.base_config.update_in_process_setting(arg);

            println!("[rb] Cecilia ==> spawn_rbuilder {:?}", config);

            // Spawn redacted server that is safe for tdx builders to expose
            telemetry::servers::redacted::spawn(
                config.base_config().redacted_telemetry_server_address(),
            )
            .await?;

            // Spawn debug server that exposes detailed operational information
            telemetry::servers::full::spawn(
                config.base_config.full_telemetry_server_address(),
                config.version_for_telemetry(),
                config.base_config.log_enable_dynamic,
            )
            .await?;
            let builder = config
                .new_builder(reth_input, Default::default())
                .await?;

            builder.run().await?;

            Ok::<(), eyre::Error>(())
        }
        .await;

        if let Err(e) = result {
            error!("Fatal rbuilder error: {}", e);
            process::exit(1);
        }

        error!("rbuilder stopped unexpectedly");
        process::exit(1);
    });
    Ok(())
}