use ahash::HashMap;
use alloy_eips::BlockId;
use alloy_primitives::U256;
use alloy_provider::{IpcConnect, Provider, ProviderBuilder, RootProvider};
use alloy_pubsub::PubSubFrontend;
use alloy_rpc_types::{Block, BlockTransactionsKind};
use eyre::Result;
use reth_db::{Database, DatabaseEnv};
use reth_node_core::args::utils::chain_value_parser;
use reth_provider::{DatabaseProviderFactory, StateProviderFactory};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::warn;

use super::order_input::OrderInputConfig;

#[derive(Debug)]
pub struct GwynethNode<P> {
    pub provider: P,
    pub order_input_config: OrderInputConfig,
}

#[derive(Debug, Default)]
pub struct Layer2Info<P> {
    pub ipc_providers: Arc<RwLock<HashMap<u64, (RootProvider<PubSubFrontend>, PathBuf)>>>, // Changed to RwLock
    pub nodes: HashMap<u64, GwynethNode<P>>,
}

impl<P> Layer2Info<P>
where
    P: StateProviderFactory + Clone + 'static,
{
    pub async fn new(
        providers: Vec<P>,
        ipc_paths: &Vec<PathBuf>,
        server_ports: &Vec<u16>,
    ) -> Result<Self> {
        let mut ipc_providers = HashMap::default();
        let mut nodes = HashMap::default();
        for ((provider, ipc_path), port) in providers
            .iter()
            .zip(ipc_paths.iter())
            .zip(server_ports.iter())
        {
            let ipc: IpcConnect<_> = IpcConnect::new(ipc_path.clone());
            let ipc_provider = ProviderBuilder::new().on_ipc(ipc).await?;
            let chain_id = ipc_provider.get_chain_id().await?;
            ipc_providers.insert(chain_id, (ipc_provider, ipc_path.clone()));
            nodes.insert(
                chain_id,
                GwynethNode::<P> {
                    provider: provider.clone(),
                    order_input_config: OrderInputConfig::new(
                        true,
                        false,
                        ipc_path.clone(),
                        *port,
                        Ipv4Addr::new(0, 0, 0, 0),
                        4096,
                        Duration::from_millis(50),
                        10_000,
                        false,
                    ),
                },
            );
        }

        Ok(Self {
            ipc_providers: Arc::new(RwLock::new(ipc_providers)),
            nodes,
        })
    }

    pub async fn get_latest_block(
        &self,
        chain_id: u64,
        block_id: BlockId,
    ) -> Result<Option<Block>> {
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
            providers
                .get(chain_id)
                .map(|(p, path)| (p.clone(), path.clone()))
        };

        if let Some((provider, ipc_path)) = provider_and_path {
            match provider.get_chain_id().await {
                Ok(_) => true,
                Err(_) => {
                    warn!(
                        "Connection lost for chain_id: {}. Attempting to reconnect...",
                        chain_id
                    );
                    match self.reconnect(&provider, ipc_path.to_str().unwrap()).await {
                        Ok(new_provider) => {
                            // Update the provider with write lock
                            let mut providers = self.ipc_providers.write().unwrap();
                            if let Some((existing_provider, _)) = providers.get_mut(chain_id) {
                                *existing_provider = new_provider;
                            }
                            true
                        }
                        Err(e) => {
                            warn!(
                                "Failed to reconnect for chain_id: {}. Error: {:?}",
                                chain_id, e
                            );
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

    async fn reconnect(
        &self,
        provider: &RootProvider<PubSubFrontend>,
        ipc_path: &str,
    ) -> Result<RootProvider<PubSubFrontend>> {
        let ipc = IpcConnect::new(ipc_path.to_string());
        let new_provider = ProviderBuilder::new().on_ipc(ipc).await?;
        Ok(new_provider)
    }
}
