//! `rbuilder` running in-process with vanilla reth.
//!
//! Usage: `cargo run -r --bin reth-rbuilder -- node --rbuilder.config <path-to-your-config-toml>`
//!
//! Note this method of running rbuilder is not quite ready for production.
//! See <https://github.com/flashbots/rbuilder/issues/229> for more information.

use clap::{Args, Parser};
use rbuilder::{
    live_builder::{base_config::load_config_toml_and_env, cli::LiveBuilderConfig, config::Config, layer2_info::{create_gwyneth_providers, create_gwyneth_providers_legacy}},
    provider::reth_prov::StateProviderFactoryFromRethProvider,
    telemetry,
};
use reth::{chainspec::EthereumChainSpecParser, cli::Cli};
use reth_node_builder::{
    engine_tree_config::{
        TreeConfig, DEFAULT_MEMORY_BLOCK_BUFFER_TARGET, DEFAULT_PERSISTENCE_THRESHOLD,
    },
    EngineNodeLauncher,
};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};
use reth_provider::{
    providers::{BlockchainProvider, BlockchainProvider2},
    BlockReader, DatabaseProviderFactory, HeaderProvider,
};
use reth_transaction_pool::{blobstore::DiskFileBlobStore, EthTransactionPool};
use std::{path::PathBuf, process};
use tokio::task;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use ahash::HashMap;

// Prefer jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Debug, Clone, Args, PartialEq, Eq, Default)]
pub struct ExtraArgs {
    /// Path of the rbuilder config to use
    #[arg(long = "rbuilder.config")]
    pub rbuilder_config: PathBuf,

    /// Enable the experimental engine features on reth binary
    ///
    /// DEPRECATED: experimental engine is default now, use --engine.legacy to enable the legacy
    /// functionality
    #[arg(long = "engine.experimental", default_value = "false")]
    pub experimental: bool,

    /// Enable the legacy engine on reth binary
    #[arg(long = "engine.legacy", default_value = "false")]
    pub legacy: bool,

    /// Configure persistence threshold for engine experimental.
    #[arg(long = "engine.persistence-threshold", conflicts_with = "legacy", default_value_t = DEFAULT_PERSISTENCE_THRESHOLD)]
    pub persistence_threshold: u64,

    /// Configure the target number of blocks to keep in memory.
    #[arg(long = "engine.memory-block-buffer-target", conflicts_with = "legacy", default_value_t = DEFAULT_MEMORY_BLOCK_BUFFER_TARGET)]
    pub memory_block_buffer_target: u64,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    info!("🚀 Starting rbuilder");

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("🚀 Please provide an argument");
        return;
    }
    let arg = &args[1];
    println!("🚀 Argument provided: {}", arg);
    let config_path = PathBuf::from(arg);
    let config = load_config_toml_and_env::<Config>(config_path).unwrap();


    let (l1_provider, l2_providers) = create_gwyneth_providers(config.base_config().gwyneth_chain_ids.clone()).unwrap();
    println!("🏡 before spawn_rbuilder");
    spawn_rbuilder(l1_provider, l2_providers, None, config).await;

    // if let Err(err) =
    //     Cli::<EthereumChainSpecParser, ExtraArgs>::parse().run(|builder, extra_args| async move {
    //         if extra_args.experimental {
    //             warn!(target: "reth::cli", "Experimental engine is default now, and the --engine.experimental flag is deprecated. To enable the legacy functionality, use --engine.legacy.");
    //         }

    //         // BlockchainProvider<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>

    //         let use_legacy_engine = extra_args.legacy;
    //         match use_legacy_engine {
    //             false => {
    //                 let engine_tree_config = TreeConfig::default()
    //                     .with_persistence_threshold(extra_args.persistence_threshold)
    //                     .with_memory_block_buffer_target(extra_args.memory_block_buffer_target);
    //                 let handle = builder
    //                     .with_types_and_provider::<EthereumNode, BlockchainProvider2<_>>()
    //                     .with_components(EthereumNode::components())
    //                     .with_add_ons(EthereumAddOns::default())
    //                     .on_node_started(move |node| {
    //                         let l2_providers = create_gwyneth_providers_legacy(
    //                             load_config_toml_and_env::<Config>(extra_args.rbuilder_config.clone()).unwrap().base_config().gwyneth_chain_ids.clone()
    //                         ).unwrap();
    //                         spawn_rbuilder(node.provider().clone(), l2_providers, node.pool().clone(), extra_args.rbuilder_config.clone());
    //                         Ok(())
    //                     })
    //                     .launch_with_fn(|builder| {
    //                         let launcher = EngineNodeLauncher::new(
    //                             builder.task_executor().clone(),
    //                             builder.config().datadir(),
    //                             engine_tree_config,
    //                         );
    //                         builder.launch_with(launcher)
    //                     })
    //                     .await?;
    //                 handle.node_exit_future.await
    //             }
    //             true => {
    //                 info!(target: "reth::cli", "Running with legacy engine");
    //                 let handle = builder
    //                     .with_types_and_provider::<EthereumNode, BlockchainProvider<_>>()
    //                     .with_components(EthereumNode::components())
    //                     .with_add_ons::<EthereumAddOns<_>>(Default::default())
    //                     .on_node_started(move |node| {
    //                         let l2_providers = create_gwyneth_providers(
    //                             load_config_toml_and_env::<Config>(extra_args.rbuilder_config.clone()).unwrap().base_config().gwyneth_chain_ids.clone()
    //                         ).unwrap();                            
    //                         spawn_rbuilder(node.provider().clone(), l2_providers, node.pool().clone(), extra_args.rbuilder_config);
    //                         Ok(())
    //                     })
    //                     .launch().await?;
    //                 handle.node_exit_future.await
    //             }
    //         }
    //     })
    // {
    //     eprintln!("Error: {err:?}");
    //     std::process::exit(1);
    // }
}

/// Spawns a tokio rbuilder task.
///
/// Takes down the entire process if the rbuilder errors or stops.
async fn spawn_rbuilder<P>(
    provider: P,
    l2_providers: HashMap<u64, P>,
    // pool: EthTransactionPool<P, DiskFileBlobStore>,
    // config_path: PathBuf,
    pool: Option<EthTransactionPool<P, DiskFileBlobStore>>,
    config: Config,
) where
    P: DatabaseProviderFactory<Provider: BlockReader>
        + reth_provider::StateProviderFactory
        + HeaderProvider
        + Clone
        + 'static,
{
    // println!("🚀 Spawning rbuilder");
    // let _handle = task::spawn(async move {
        println!("🏡 before result");
        let result = async {
            // println!("🏡 before setup_tracing_subscriber");
            // config.base_config().setup_tracing_subscriber().unwrap();

            // println!("🏡 setup_tracing_subscriber");
            // Spawn redacted server that is safe for tdx builders to expose
            telemetry::servers::redacted::spawn(
                config.base_config().redacted_telemetry_server_address(),
            )
            .await.unwrap();

            println!("🏡 Spawn debug server that exposes detailed operational information");
            telemetry::servers::full::spawn(
                config.base_config.full_telemetry_server_address(),
                config.version_for_telemetry(),
                config.base_config.log_enable_dynamic,
            )
            .await.unwrap();

        
            println!("🏡 Spawn debug server that exposes detailed operational information");
            let l2_providers = l2_providers
                .iter()
                .map(|(k, v)| (*k, StateProviderFactoryFromRethProvider::new(v.clone(), config.base_config().live_root_hash_config().unwrap())))
                .collect::<HashMap<_,_>>();

            println!("🛼 spawn_rbuilder {:?}", l2_providers.keys().collect::<Vec<_>>());

            let builder = config
                .new_builder(
                    StateProviderFactoryFromRethProvider::new(
                        provider,
                        config.base_config().live_root_hash_config().unwrap(),
                    ),
                    l2_providers,
                    CancellationToken::new(),
                )
                .await.unwrap();
            println!("🏡 builder");
            if let Some(pool) = pool {
                builder.connect_to_transaction_pool(pool).await.unwrap();
            }
            builder.run().await.unwrap();
            println!("🏡 builder.run().await?");
            Ok::<(), eyre::Error>(())
        }
        .await;

        if let Err(e) = result {
            error!("Fatal rbuilder error: {:#}", e);
            process::exit(1);
        }

        // error!("rbuilder stopped unexpectedly");
        // process::exit(1);
    // });
}
