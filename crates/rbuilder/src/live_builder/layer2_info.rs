use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use ahash::HashMap;
use alloy_primitives::U256;
use alloy_provider::{IpcConnect, ProviderBuilder, Provider, RootProvider};
use alloy_rpc_types::{Block, BlockNumberOrTag, BlockTransactionsKind};
use alloy_eips::BlockId;
use alloy_pubsub::PubSubFrontend;
use alloy_transport::TransportResult;
use eyre::Result;
use reth_db::DatabaseEnv;
use reth_provider::{HeaderProvider, StageCheckpointReader};
use revm_primitives::hex;
use tracing::warn;
use reth_node_core::args::utils::chain_value_parser;
use reth_stages::StageId;

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

impl<DB: Clone + reth_db::Database> Layer2Info<DB> {
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

    pub async fn get_latest_block(&self, chain_id: u64, block_id: BlockId) -> Result<Option<Block>> {
        if self.ensure_connection(&chain_id).await {
            let providers = self.ipc_providers.lock().unwrap();
            if let Some((provider, _)) = providers.get(&chain_id) {
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

    pub async fn wait_until_synced(&self, target_block: u64) {
        let providers = self.ipc_providers.lock().unwrap();
        for (chain_id, (ipc_provider, _)) in providers.iter() {
            println!("waiting on L2: {}", chain_id);

            loop {
                let result: TransportResult<String>  = ipc_provider.client().request_noparams("eth_getSyncedL1BlockIdx").await;
                if result.is_ok() {
                    let res = result.unwrap();
                    let without_prefix = res.trim_start_matches("0x");
                    // Parse as base 16
                    let l1_block = u64::from_str_radix(without_prefix, 16).expect("Invalid hex input");
                    println!("l1_block: {:?}", l1_block);
                    if l1_block < target_block {
                        println!("waiting on L2 to sync... ({} < {})", l1_block, target_block);
                        sleep(Duration::from_millis(100));
                    } else {
                        println!("L2 synced to {}", target_block);
                        break;
                    }
                } else {
                    println!("error getting sync data: {:?}", result);
                }
            }

            let res: String = ipc_provider.client().request_noparams("eth_getSyncedL2BlockIdx").await.expect("failed to get L2 sync block idx");
            let without_prefix = res.trim_start_matches("0x");
            // Parse as base 16
            let l2_block = u64::from_str_radix(without_prefix, 16).expect("Invalid hex input");
            println!("l2_block: {:?}", l2_block);

            let node = self.nodes.get(chain_id).unwrap();
            let provider_factory = node.provider_factory.clone().provider_factory_unchecked();

            loop {
                if let Some(latest_block_number_synced) = provider_factory.get_stage_checkpoint(StageId::Finish).expect("failed to get header") {
                    if latest_block_number_synced.block_number >= l2_block {
                        println!("Waiting for {} to pipeline done.", l2_block);
                        break;
                    }
                }
                println!("waiting on L2 block {} to pipeline...", l2_block);
                sleep(Duration::from_millis(100));
            }

            loop {
                if let Some(_) = provider_factory.header_by_number(l2_block.into()).expect("failed to get header") {
                    println!("Waiting for {} done.", l2_block);
                    break;
                } else {
                    println!("waiting on L2 block {} to process...", l2_block);
                    sleep(Duration::from_millis(100));
                }
            }
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