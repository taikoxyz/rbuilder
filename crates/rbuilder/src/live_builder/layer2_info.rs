use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use ahash::HashMap;
use alloy_primitives::U256;
use alloy_provider::{IpcConnect, ProviderBuilder, Provider, RootProvider};
use alloy_rpc_types::{Block, BlockNumberOrTag, BlockTransactionsKind};
use alloy_eips::BlockId;
use alloy_pubsub::PubSubFrontend;
use eyre::Result;
use reth::chainspec::chain_value_parser;
use reth_db::{Database, DatabaseEnv};
use reth_node_api::{NodeTypesWithDB, NodeTypesWithDBAdapter};
use reth_node_ethereum::EthereumNode;
use reth_provider::providers::{BlockchainProvider, BlockchainProvider2};
use tracing::warn;

use crate::provider::StateProviderFactory;
use crate::utils::ProviderFactoryReopener;

use super::config::create_provider_factory;
use super::order_input::OrderInputConfig;


pub fn create_gwyneth_providers(
    chain_ids: Vec<u64>
) -> Result<(BlockchainProvider<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>, HashMap<u64, BlockchainProvider<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>>)>
{
    let l1_datadir: &str = "/data/reth/execution-data";
    let datadir_base = "/data/reth/gwyneth";
    let chain = chain_value_parser("/network-configs/genesis.json").expect("failed to load gwyneth chain spec");
    // let l1_datadir = "mainnet";
    // let datadir_base = "aaa/g";
    // let chain = chain_value_parser("dev").expect("failed to load gwyneth chain spec");

    let l1_provider = create_provider_factory(
        Some(Path::new(l1_datadir)),
        None,
        None,
        chain.clone(),
        None,
    )?
    .check_consistency_and_reopen_if_needed()?;
    let l1_provider = 
        BlockchainProvider::<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>::new(
        l1_provider,
        Arc::new(reth::blockchain_tree::noop::NoopBlockchainTree::default())
    )?;

    let mut providers = HashMap::default();
    for chain_id in chain_ids {
        println!("🏡 chain_id {:?}", format!("{}-{}", datadir_base, chain_id));
        let provider_factory = create_provider_factory(
            Some(Path::new(&format!("{}-{}", datadir_base, chain_id).to_owned())),
            Some(Path::new(&format!("{}-{}/db", datadir_base, chain_id).to_owned())),
None,
chain.clone(),
            None,
        )?
        .check_consistency_and_reopen_if_needed()?;
        let blockchain_provider = 
            BlockchainProvider::<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>::new(
                provider_factory, 
                Arc::new(reth::blockchain_tree::noop::NoopBlockchainTree::default())
            )?;
        providers.insert(chain_id, blockchain_provider);
    }

    Ok((l1_provider, providers))
}

pub fn create_gwyneth_providers_legacy(
    chain_ids: Vec<u64>
) -> Result<HashMap<u64, BlockchainProvider2<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>>>
{
    let datadir_base = "/data/reth/gwyneth";
    let chain = chain_value_parser("/network-configs/genesis.json").expect("failed to load gwyneth chain spec");

    let mut providers = HashMap::default();
    for chain_id in chain_ids {
        let provider_factory = create_provider_factory(
            Some(Path::new(&format!("{}-{}", datadir_base, chain_id).to_owned())),
            Some(Path::new(&format!("{}-{}/db", datadir_base, chain_id).to_owned())),
None,
chain.clone(),
            None,
        )?
        .check_consistency_and_reopen_if_needed()?;
        let blockchain_provider = 
            BlockchainProvider2::<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>::new(provider_factory)?;
        providers.insert(chain_id, blockchain_provider);

    }

    Ok(providers)
}


#[derive(Debug)]
pub struct GwynethNode<P> {
    pub provider_factory: P,
    pub order_input_config: OrderInputConfig,
}

#[derive(Debug)]
pub struct Layer2Info<P> {
    pub ipc_providers: Arc<RwLock<HashMap<u64, (RootProvider<PubSubFrontend>, String)>>>,  // Changed to RwLock
    pub data_dirs: HashMap<u64, PathBuf>,
    pub nodes: HashMap<u64, GwynethNode<P>>,
}

impl<P> PartialEq for Layer2Info<P> {
    fn eq(&self, other: &Self) -> bool {
        self.data_dirs == other.data_dirs
    }
}

impl<P> Eq for Layer2Info<P> {}

impl<P> Layer2Info<P>
where
    P: StateProviderFactory + Clone + 'static,
{
    pub async fn new(chain_ids: Vec<u64>, provider_factories: HashMap<u64, P>) -> Result<Self> {
        let mut ipc_providers = HashMap::default();
        let mut data_dirs_map = HashMap::default();

        let datadir_base = "/data/reth/gwyneth";
        let ipc_base: &str = "/tmp/reth.ipc";

        let chain = chain_value_parser("/network-configs/genesis.json").expect("failed to load gwyneth chain spec");

        println!("🛼 {:?}", chain_ids);
        println!("🛼 {:?}", provider_factories.keys().collect::<Vec<_>>());

        let mut nodes = HashMap::default();
        for (idx, chain_id) in chain_ids.iter().enumerate() {
            let ipc_path = format!("{}-{}", ipc_base, idx + 2).to_owned();
            let data_dir = format!("{}-{}", datadir_base, chain_id).to_owned();


            let ipc = IpcConnect::new(ipc_path.clone());
            let ipc_provider = ProviderBuilder::new().on_ipc(ipc).await?;
            //let chain_id = U256::from(provider.get_chain_id().await?);
            ipc_providers.insert(*chain_id, (ipc_provider, ipc_path.clone()));
            data_dirs_map.insert(*chain_id, PathBuf::from(data_dir));

            nodes.insert(*chain_id, GwynethNode {
                provider_factory: provider_factories[&chain_id].clone(),
                order_input_config: OrderInputConfig::new(
                    true,
                    false,
                    Some(Path::new(&ipc_path).into()),
                    9646 + ((chain_id + 1) - 167010) as u16,
                    Ipv4Addr::new(0, 0, 0, 0),
                    4096,
                    Duration::from_millis(50),
                    10_000,
                ),
            });
        }

        Ok(Self {
            ipc_providers: Arc::new(RwLock::new(ipc_providers)),
            data_dirs: data_dirs_map,
            nodes,
        })
    }

    async fn ensure_connection(&self, chain_id: &u64) -> bool {
        // let mut providers = self.ipc_providers.try_write().unwrap();
        // if let Some((provider, ipc_path)) = providers.get_mut(chain_id) {
        //     match provider.get_chain_id().await {
        //         Ok(_) => true,
        //         Err(_) => {
        //             warn!("Connection lost for chain_id: {}. Attempting to reconnect...", chain_id);
        //             match self.reconnect( provider, ipc_path).await {
        //                 Ok(_) => true,
        //                 Err(e) => {
        //                     warn!("Failed to reconnect for chain_id: {}. Error: {:?}", chain_id, e);
        //                     false
        //                 }
        //             }
        //         }
        //     }
        // } else {
        //     false
        // }
        true
    }

    pub async fn get_latest_block(&self, chain_id: u64, block_id: BlockId) -> Result<Option<Block>> {
        if self.ensure_connection(&chain_id).await {
            // Take a copy of the provider under a shorter lock
            let provider = {
                let providers = self.ipc_providers.read().unwrap();
                providers.get(&chain_id).map(|(p, _)| p.clone())
            };

            if let Some(provider) = provider {
                let transactions_kind = BlockTransactionsKind::Full;
                let latest_block = provider.get_block(block_id, transactions_kind).await?;
                Ok(latest_block)
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub async fn get_chain_id(&self, chain_id: &u64) -> Result<Option<U256>> {
        if self.ensure_connection(chain_id).await {
            let providers = self.ipc_providers.try_read().unwrap();
            if let Some((provider, _)) = providers.get(chain_id) {
                let chain_id = U256::from(provider.get_chain_id().await?);
                Ok(Some(chain_id))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn get_data_dir(&self, chain_id: &u64) -> Option<&PathBuf> {
        self.data_dirs.get(chain_id)
    }

    async fn reconnect(&self, provider: &mut RootProvider<PubSubFrontend>, ipc_path: &str) -> Result<()> {
        let ipc = IpcConnect::new(ipc_path.to_string());
        *provider = ProviderBuilder::new().on_ipc(ipc).await?;
        Ok(())
    }
}