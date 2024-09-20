use std::collections::HashMap;
use std::path::PathBuf;
use alloy_primitives::U256;
use alloy_provider::{IpcConnect, ProviderBuilder, Provider};
use alloy_rpc_types::{Block, BlockNumberOrTag, BlockTransactionsKind};
use alloy_eips::BlockId;
use eyre::Result;
use alloy_pubsub::PubSubFrontend;

#[derive(Debug, Clone)]
pub struct Layer2Info {
    ipc_connections: HashMap<U256, IpcConnect<String>>,
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
        let mut ipc_connections = HashMap::new();
        let mut data_dirs_map = HashMap::new();

        for (ipc_path, data_dir) in ipc_paths.into_iter().zip(data_dirs.into_iter()) {
            let ipc = IpcConnect::new(ipc_path.clone());
            let provider = ProviderBuilder::new().on_ipc(ipc.clone()).await?;
            let chain_id = U256::from(provider.get_chain_id().await?);
            ipc_connections.insert(chain_id, ipc);
            data_dirs_map.insert(chain_id, PathBuf::from(data_dir));
        }

        Ok(Self { ipc_connections, data_dirs: data_dirs_map })
    }

    pub async fn get_latest_block(&self, chain_id: U256) -> Result<Option<Block>> {
        if let Some(ipc) = self.ipc_connections.get(&chain_id) {
            let provider = ProviderBuilder::new().on_ipc(ipc.clone()).await?;
            let block_id = BlockId::Number(BlockNumberOrTag::Latest);
            let transactions_kind = BlockTransactionsKind::Full;
            let latest_block = provider.get_block(block_id, transactions_kind).await?;
            Ok(latest_block)
        } else {
            Ok(None)
        }
    }

    pub async fn get_chain_id(&self, ipc: &IpcConnect<String>) -> Result<U256> {
        let provider = ProviderBuilder::new().on_ipc(ipc.clone()).await?;
        let chain_id = U256::from(provider.get_chain_id().await?);
        Ok(chain_id)
    }

    pub fn get_data_dir(&self, chain_id: &U256) -> Option<&PathBuf> {
        self.data_dirs.get(chain_id)
    }
}