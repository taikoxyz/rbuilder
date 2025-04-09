use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::sleep;
use std::time::Duration;
use ahash::HashMap;
use alloy_primitives::U256;
use alloy_provider::{IpcConnect, ProviderBuilder, Provider, RootProvider};
use alloy_rpc_types::{BlockId, Block, BlockNumberOrTag, BlockTransactionsKind};
use alloy_pubsub::PubSubFrontend;
use alloy_transport::TransportResult;
use eyre::Result;
use reth::chainspec::chain_value_parser;
use reth_db::{Database, DatabaseEnv};
use reth_node_api::{NodeTypesWithDB, NodeTypesWithDBAdapter};
use reth_node_ethereum::EthereumNode;
use reth_provider::providers::{BlockchainProvider, BlockchainProvider2};
// use reth_stages::StageId;

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

    pub async fn wait_until_synced(&self, target_block: u64) {
        let providers = self.ipc_providers.read().unwrap();
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
            loop {
                if let Ok(latest_block_number_synced) = node.provider_factory.last_block_number() {
                    if latest_block_number_synced >= l2_block {
                        println!("Waiting for {} to pipeline done.", l2_block);
                        break;
                    }
                }
                println!("waiting on L2 block {} to pipeline...", l2_block);
                sleep(Duration::from_millis(100));
            }
            
            // let provider_factory = node.provider_factory.clone().provider_factory_unchecked();

            // loop {
            //     if let Some(latest_block_number_synced) = provider_factory.get_stage_checkpoint(StageId::Finish).expect("failed to get header") {
            //         if latest_block_number_synced.block_number >= l2_block {
            //             println!("Waiting for {} to pipeline done.", l2_block);
            //             break;
            //         }
            //     }
            //     println!("waiting on L2 block {} to pipeline...", l2_block);
            //     sleep(Duration::from_millis(100));
            // }

            // loop {
            //     if let Some(_) = provider_factory.header_by_number(l2_block.into()).expect("failed to get header") {
            //         println!("Waiting for {} done.", l2_block);
            //         break;
            //     } else {
            //         println!("waiting on L2 block {} to process...", l2_block);
            //         sleep(Duration::from_millis(100));
            //     }
            // }
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