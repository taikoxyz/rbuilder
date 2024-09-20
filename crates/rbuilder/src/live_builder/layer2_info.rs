use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use alloy_primitives::U256;
use alloy_provider::{IpcConnect, ProviderBuilder, Provider, RootProvider};
use alloy_rpc_types::{Block, BlockNumberOrTag, BlockTransactionsKind};
use alloy_eips::BlockId;
use alloy_pubsub::PubSubFrontend;
use eyre::Result;
use tracing::warn;

#[derive(Debug)]
pub struct Layer2Info {
    providers: Arc<Mutex<HashMap<U256, (RootProvider<PubSubFrontend>, String)>>>,
    data_dirs: HashMap<U256, PathBuf>,
}

impl PartialEq for Layer2Info {
    fn eq(&self, other: &Self) -> bool {
        self.data_dirs == other.data_dirs
    }
}

impl Eq for Layer2Info {}

impl Layer2Info {
    pub async fn new(ipc_paths: Vec<String>, data_dirs: Vec<String>) -> Result<Self> {
        let mut providers = HashMap::new();
        let mut data_dirs_map = HashMap::new();

        for (ipc_path, data_dir) in ipc_paths.into_iter().zip(data_dirs.into_iter()) {
            let ipc = IpcConnect::new(ipc_path.clone());
            let provider = ProviderBuilder::new().on_ipc(ipc).await?;
            let chain_id = U256::from(provider.get_chain_id().await?);
            providers.insert(chain_id, (provider, ipc_path));
            data_dirs_map.insert(chain_id, PathBuf::from(data_dir));
        }

        Ok(Self { 
            providers: Arc::new(Mutex::new(providers)),
            data_dirs: data_dirs_map 
        })
    }

    async fn ensure_connection(&self, chain_id: &U256) -> bool {
        let mut providers = self.providers.lock().unwrap();
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

    pub async fn get_latest_block(&self, chain_id: U256) -> Result<Option<Block>> {
        if self.ensure_connection(&chain_id).await {
            let providers = self.providers.lock().unwrap();
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

    pub async fn get_chain_id(&self, chain_id: &U256) -> Result<Option<U256>> {
        if self.ensure_connection(chain_id).await {
            let providers = self.providers.lock().unwrap();
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

    pub fn get_data_dir(&self, chain_id: &U256) -> Option<&PathBuf> {
        self.data_dirs.get(chain_id)
    }

    async fn reconnect(&self, provider: &mut RootProvider<PubSubFrontend>, ipc_path: &str) -> Result<()> {
        let ipc = IpcConnect::new(ipc_path.to_string());
        *provider = ProviderBuilder::new().on_ipc(ipc).await?;
        Ok(())
    }
}