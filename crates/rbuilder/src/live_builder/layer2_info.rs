use std::collections::HashMap;
use std::path::PathBuf;
use ethers::{
    prelude::*,
    types::{Block, BlockNumber, H256, U256},
    providers::{Ipc as EthersIpc, Provider as EthersProvider},
};
use eyre::Result;

#[derive(Debug, Clone)]
pub struct Layer2Info {
    rpc_providers: HashMap<U256, EthersProvider<EthersIpc>>,
    data_dirs: HashMap<U256, PathBuf>,
}

impl PartialEq for Layer2Info {
    fn eq(&self, other: &Self) -> bool {
        self.data_dirs == other.data_dirs
    }
}

impl Eq for Layer2Info {}

impl Layer2Info {
    pub async fn new(ipc_paths: Vec<String>, data_dirs: Vec<String>) -> eyre::Result<Self>  {
        let mut rpc_providers = HashMap::new();
        let mut data_dirs_map = HashMap::new();

        for (ipc_path, data_dir) in ipc_paths.into_iter().zip(data_dirs.into_iter()) {
            let provider = EthersProvider::connect_ipc(&ipc_path).await?;
            let chain_id = provider.get_chainid().await?;
            rpc_providers.insert(chain_id, provider);
            data_dirs_map.insert(chain_id, PathBuf::from(data_dir));
        }

        Ok(Self { rpc_providers, data_dirs: data_dirs_map })
    }

    pub async fn get_latest_block(&self, chain_id: U256) -> eyre::Result<Option<Block<H256>>> {
        if let Some(provider) = self.rpc_providers.get(&chain_id) {
            let latest_block = provider.get_block(BlockNumber::Latest).await?;
            Ok(latest_block)
        } else {
            Ok(None)
        }
    }

    pub fn get_data_dir(&self, chain_id: &U256) -> Option<&PathBuf> {
        self.data_dirs.get(chain_id)
    }
}