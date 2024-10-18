use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ahash::HashMap;
use alloy_primitives::U256;
use alloy_provider::{IpcConnect, ProviderBuilder, Provider, RootProvider};
use alloy_rpc_types::{Block, BlockNumberOrTag, BlockTransactionsKind};
use alloy_eips::BlockId;
use alloy_pubsub::PubSubFrontend;
use eyre::Result;
use reth_db::DatabaseEnv;
use tracing::warn;
use reth_node_core::args::utils::chain_value_parser;

use crate::utils::ProviderFactoryReopener;

use super::config::create_provider_factory;
use super::order_input::OrderInputConfig;


pub fn create_gwyneth_providers(chain_ids: Vec<u64>) -> eyre::Result<HashMap<u64, ProviderFactoryReopener<Arc<DatabaseEnv>>>> {
    let datadir_base = "/data/reth/gwyneth";
    let chain = chain_value_parser("/network-configs/genesis.json").expect("failed to load gwyneth chain spec");

    let mut nodes = HashMap::default();
    for chain_id in chain_ids {
        let provider_factory = create_provider_factory(
            Some(Path::new(&format!("{}-{}", datadir_base, chain_id).to_owned())),
            Some(Path::new(&format!("{}-{}/db", datadir_base, chain_id).to_owned())),
            Some(Path::new(&format!("{}-{}/static_files", datadir_base, chain_id).to_owned())),
            chain.clone(),
        )?;
        nodes.insert(chain_id, provider_factory);
    }

    Ok(nodes)
}

#[derive(Debug)]
pub struct GwynethNode<DB> {
    pub provider_factory: ProviderFactoryReopener<DB>,
    pub order_input_config: OrderInputConfig,
}

#[derive(Debug)]
pub struct Layer2Info<DB> {
    pub ipc_providers: Arc<Mutex<HashMap<u64, (RootProvider<PubSubFrontend>, String)>>>,
    pub data_dirs: HashMap<u64, PathBuf>,
    pub nodes: HashMap<u64, GwynethNode<DB>>,
}

impl<DB> PartialEq for Layer2Info<DB> {
    fn eq(&self, other: &Self) -> bool {
        self.data_dirs == other.data_dirs
    }
}

impl<DB> Eq for Layer2Info<DB> {}

impl<DB: Clone> Layer2Info<DB> {
    pub async fn new(chain_ids: Vec<u64>, provider_factories: HashMap<u64, ProviderFactoryReopener<DB>>) -> Result<Self> {
        let mut providers = HashMap::default();
        let mut data_dirs_map = HashMap::default();

        let datadir_base = "/data/reth/gwyneth";
        let ipc_base: &str = "/tmp/reth.ipc";

        let chain = chain_value_parser("/network-configs/genesis.json").expect("failed to load gwyneth chain spec");

        let mut nodes = HashMap::default();
        for chain_id in chain_ids {
            let ipc_path = format!("{}-{}", ipc_base, chain_id).to_owned();
            let data_dir = format!("{}-{}", datadir_base, chain_id).to_owned();

            let ipc = IpcConnect::new(ipc_path.clone());
            let provider = ProviderBuilder::new().on_ipc(ipc).await?;
            //let chain_id = U256::from(provider.get_chain_id().await?);
            providers.insert(chain_id, (provider, ipc_path));
            data_dirs_map.insert(chain_id, PathBuf::from(data_dir));

            // let provider_factory = create_provider_factory(
            //     Some(Path::new(&format!("{}-{}", datadir_base, chain_id).to_owned())),
            //     Some(Path::new(&format!("{}-{}/db", datadir_base, chain_id).to_owned())),
            //     Some(Path::new(&format!("{}-{}/static_files", datadir_base, chain_id).to_owned())),
            //     chain.clone(),
            // )?;

            nodes.insert(chain_id, GwynethNode {
                provider_factory: provider_factories[&chain_id].clone(),
                order_input_config: OrderInputConfig::new(
                    true,
                    false,
                    Path::new(&format!("{}-{}", ipc_base, chain_id).to_owned()).into(),
                    9646 + ((chain_id + 1) - 167010) as u16,
                    Ipv4Addr::new(0, 0, 0, 0),
                    4096,
                    Duration::from_millis(50),
                    10_000,
                ),
            });
        }

        Ok(Self { 
            ipc_providers: Arc::new(Mutex::new(providers)),
            data_dirs: data_dirs_map,
            nodes,
        })
    }

    async fn ensure_connection(&self, chain_id: &u64) -> bool {
        let mut providers = self.ipc_providers.lock().unwrap();
        if let Some((provider, ipc_path)) = providers.get_mut(chain_id) {
            match provider.get_chain_id().await {
                Ok(_) => true,
                Err(_) => {
                    warn!("Connection lost for chain_id: {}. Attempting to reconnect...", chain_id);
                    match self.reconnect( provider, ipc_path).await {
                        Ok(_) => true,
                        Err(e) => {
                            warn!("Failed to reconnect for chain_id: {}. Error: {:?}", chain_id, e);
                            false
                        }
                    }
                }
            }
        } else {
            false
        }
    }

    pub async fn get_latest_block(&self, chain_id: u64) -> Result<Option<Block>> {
        if self.ensure_connection(&chain_id).await {
            let providers = self.ipc_providers.lock().unwrap();
            if let Some((provider, _)) = providers.get(&chain_id) {
                let block_id = BlockId::Number(BlockNumberOrTag::Latest);
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
            let providers = self.ipc_providers.lock().unwrap();
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