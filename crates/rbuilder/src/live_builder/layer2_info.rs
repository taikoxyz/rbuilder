use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use ahash::HashMap;
use alloy_primitives::U256;
use alloy_provider::{IpcConnect, ProviderBuilder, Provider, RootProvider};
use alloy_rpc_types::{Block, BlockTransactionsKind};
use alloy_eips::BlockId;
use alloy_pubsub::PubSubFrontend;
use eyre::Result;
use reth_db::{DatabaseEnv, Database};
use reth_provider::{DatabaseProviderFactory, StateProviderFactory};
use tracing::warn;
use reth_node_core::args::utils::chain_value_parser;

use crate::utils::ProviderFactoryReopener;
use super::config::create_provider_factory;
use super::order_input::OrderInputConfig;

pub fn create_gwyneth_providers<P, DB>(chain_ids: Vec<u64>) -> eyre::Result<HashMap<u64, P>>
where
    DB: Database + Clone + 'static,
    P: DatabaseProviderFactory<DB> + StateProviderFactory + Clone + 'static,
    P: From<ProviderFactoryReopener<Arc<DatabaseEnv>>>,
{
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
        nodes.insert(chain_id, provider_factory.into());
    }

    Ok(nodes)
}

#[derive(Debug)]
pub struct GwynethNode<P, DB> {
    pub provider_factory: P,
    pub order_input_config: OrderInputConfig,
    _phantom: PhantomData<DB>,
}

#[derive(Debug)]
pub struct Layer2Info<P, DB> {
    pub ipc_providers: Arc<RwLock<HashMap<u64, (RootProvider<PubSubFrontend>, String)>>>,  // Changed to RwLock
    pub data_dirs: HashMap<u64, PathBuf>,
    pub nodes: HashMap<u64, GwynethNode<P, DB>>,
    _phantom: PhantomData<DB>,
}

impl<P, DB> PartialEq for Layer2Info<P, DB> {
    fn eq(&self, other: &Self) -> bool {
        self.data_dirs == other.data_dirs
    }
}

impl<P, DB> Eq for Layer2Info<P, DB> {}

impl<P, DB> Layer2Info<P, DB> 
where
    DB: Database + Clone + 'static,
    P: DatabaseProviderFactory<DB> + StateProviderFactory + Clone + 'static,
{
    pub async fn new(
        chain_ids: Vec<u64>,
        provider_factory: P,
    ) -> Result<Self> {
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
            providers.insert(chain_id, (provider, ipc_path));
            data_dirs_map.insert(chain_id, PathBuf::from(data_dir));
    
            nodes.insert(chain_id, GwynethNode::<P, DB> {
                provider_factory: provider_factory.clone(),
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
                _phantom: PhantomData,
            });
        }
    
        Ok(Self {
            ipc_providers: Arc::new(RwLock::new(providers)),  // Changed to RwLock
            data_dirs: data_dirs_map,
            nodes,
            _phantom: PhantomData,
        })
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

    pub async fn ensure_connection(&self, chain_id: &u64) -> bool {
        let provider_and_path = {
            let providers = self.ipc_providers.read().unwrap();
            providers.get(chain_id).map(|(p, path)| (p.clone(), path.clone()))
        };

        if let Some((provider, ipc_path)) = provider_and_path {
            match provider.get_chain_id().await {
                Ok(_) => true,
                Err(_) => {
                    warn!("Connection lost for chain_id: {}. Attempting to reconnect...", chain_id);
                    match self.reconnect(&provider, &ipc_path).await {
                        Ok(new_provider) => {
                            // Update the provider with write lock
                            let mut providers = self.ipc_providers.write().unwrap();
                            if let Some((existing_provider, _)) = providers.get_mut(chain_id) {
                                *existing_provider = new_provider;
                            }
                            true
                        }
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

    pub async fn get_chain_id(&self, chain_id: &u64) -> Result<Option<U256>> {
        if self.ensure_connection(chain_id).await {
            // Take a copy of the provider under a shorter lock
            let provider = {
                let providers = self.ipc_providers.read().unwrap();
                providers.get(chain_id).map(|(p, _)| p.clone())
            };

            if let Some(provider) = provider {
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

    async fn reconnect(&self, provider: &RootProvider<PubSubFrontend>, ipc_path: &str) -> Result<RootProvider<PubSubFrontend>> {
        let ipc = IpcConnect::new(ipc_path.to_string());
        let new_provider = ProviderBuilder::new().on_ipc(ipc).await?;
        Ok(new_provider)
    }
}