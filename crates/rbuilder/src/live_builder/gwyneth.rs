use ahash::HashMap;
use alloy_eips::{BlockHashOrNumber, BlockId};
use alloy_primitives::U256;
use alloy_provider::{IpcConnect, Provider, ProviderBuilder, RootProvider};
use alloy_pubsub::PubSubFrontend;
use alloy_rpc_types::{Block, BlockTransactionsKind, Header as RpcHeader, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use eyre::Result;
use futures::future::IntoStream;
use futures::stream::TakeUntil;
use futures::{FutureExt, Stream, StreamExt};
use gwyneth::exex::{L1ParentState, L1ParentStates};
use reth::network::NetworkInfo;
use reth::rpc::eth::EthPubSub;
use reth::transaction_pool::{EthPoolTransaction, EthPooledTransaction, NewTransactionEvent, TransactionPool};
use reth_db::{Database, DatabaseEnv};
use reth_evm::provider;
use reth_node_core::args::utils::chain_value_parser;
use reth_node_core::rpc::eth::helpers::{EthApiSpec, EthTransactions, FullEthApi, LoadFee};
use reth_primitives::{Header, Receipt, SealedHeader, TransactionMeta, TransactionSignedEcRecovered, TxHash};
use reth_provider::{BlockReader, CanonStateSubscriptions, DatabaseProviderFactory, EvmEnvProvider, HeaderProvider, ReceiptProvider, StateProvider, StateProviderFactory};
use revm_primitives::{Address, B256};
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use tracing::instrument::WithSubscriber;
use std::fmt::Debug;
use std::future::Future;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex, RwLock};
use std::task::Poll;
use std::time::Duration;
use tracing::{event, warn};

use crate::primitives::TransactionSignedEcRecoveredWithBlobs;

use super::order_input::OrderInputConfig;

pub type GwynethMempoolReciever = Receiver<NewTransactionEvent<EthPooledTransaction>>;

#[derive(Debug)]
pub struct GwynethNode<P> {
    pub ethapi: Arc<dyn EthApiStream>,
    pub provider: P,
    pub order_input_config: OrderInputConfig,
}

#[derive(Debug)]
pub struct GwynethNodes<P> {
    pub l1_parents: L1ParentStates,
    pub nodes: HashMap<u64, GwynethNode<P>>,
}

impl<P> Default for GwynethNodes<P> {
    fn default() -> Self {
        Self {
            l1_parents: L1ParentStates::default(),
            nodes: HashMap::default(),
        }
    }
}

impl<P> GwynethNodes<P> 
where 
    P: StateProviderFactory + HeaderProvider + Clone + 'static,

{

    pub fn new(
        chain_ids: Vec<u64>,
        providers: Vec<P>,
        l1_parents: L1ParentStates,
        ethapis: Vec<Arc<dyn EthApiStream>>,
        server_ports: Vec<u16>,
    ) -> Result<Self> {
        println!("[rb] Cecilia ==> GwynethNodes::new {:?} {:?} {:?}", providers.len(), ethapis.len(), server_ports);
        let mut nodes = HashMap::default();
        for (((provider, ethapi), port), chain_id) in providers
            .into_iter()
            .zip(ethapis.into_iter())
            .zip(server_ports.iter())
            .zip(chain_ids.iter())
        {
            nodes.insert(
                *chain_id,
                GwynethNode::<P> {
                    ethapi,
                    provider: provider,
                    order_input_config: OrderInputConfig::new(
                        true,
                        false,
                        PathBuf::new(),
                        *port,
                        Ipv4Addr::new(0, 0, 0, 0),
                        4096,
                        Duration::from_millis(50),
                        10_000,
                        false,
                    ),
                },
            );
            println!("[rb] inside the fuckin loop {:?}", port)
        }
        println!("[rb] WTF how many {:?}", nodes.len());
        Ok(Self {
            l1_parents,
            nodes,
        })
    }

    pub async fn get_latest_header(&self, chain_id: u64) -> Result<Option<SealedHeader>> {
        println!("[rb] Cecilia ==> GwynethNodes::get_latest_header {:?}", chain_id);
        if let Some(provider) = self.nodes.get(&chain_id).map(|n| n.provider.clone()) {
            let number = provider.last_block_number()?;
            provider
                .sealed_header(number)
                .map_err(|e| eyre::eyre!("Error getting latest header for chain_id {}: {:?}", chain_id, e))
                
        } else {
            eyre::bail!("No provider found for chain_id: {}", chain_id)
        }
    }

    pub async fn sync(&self, node_idx: usize, target_parent: u64, target_parent_hash: B256) -> Result<()> {
        println!("[rb] waiting for node {:?} syncing to target parent {:?}", node_idx, target_parent);
        while let (parent, hash) = self.l1_parents.get(node_idx) {
            if parent != target_parent || hash.is_none() || hash.unwrap().hash() != target_parent_hash {
                tokio::time::sleep(Duration::from_millis(300)).await;
            } else {
                return Ok(());
            }
        }
        Ok(())
    } 
}

pub trait EthApiStream: Send + Sync + Debug {  
    fn new_headers_stream(&self) -> Pin<Box<dyn Stream<Item = RpcHeader> + Send>>;

    fn full_pending_transaction_stream(  
        &self,  
    ) -> Pin<Box<dyn Stream<Item = NewTransactionEvent<EthPooledTransaction>> + Send>>;
}

pub trait EthTxSender: Send + Sync + Debug {  
    fn send_raw_transaction(&self, tx: alloy_primitives::Bytes) ->  Result<B256>;
    fn receipt_by_hash(&self, hash: TxHash) -> Result<(TransactionMeta, Receipt)>;
    fn get_nounce(&self, addr: Address) -> Result<u64>;
}

impl<T> EthTxSender for T 
where 
    T: FullEthApi + Send + Sync + Debug,
{

    fn send_raw_transaction(&self, tx: alloy_primitives::Bytes) ->  Result<B256>{
        println!("[rb] Cecilia ==> EthTxSender::send_raw_transaction {:?}", tx);
        futures::executor::block_on(self.send_raw_transaction(tx))
            .map_err(|e| eyre::eyre!("Error sending transaction: {:?}", e))
    }
    

    fn receipt_by_hash(&self, hash: TxHash) -> Result<(TransactionMeta, Receipt)> {
        println!("[rb] Cecilia ==> EthTxSender::receipt_by_hash {:?}", hash);
        loop {
            match futures::executor::block_on(self.load_transaction_and_receipt(hash)) {
                Ok(Some((tx, meta, receipt))) => return Ok((meta, receipt)),
                Ok(None) => {
                    continue;
                },
                Err(e) => return Err(eyre::eyre!("Error getting receipt by hash: {:?}", e)),
            }
        }
    }

    fn get_nounce(&self, addr: Address) -> Result<u64> {
        loop {
            match self.latest_state().unwrap().account_nonce(addr) {
                Ok(Some(nonce)) => return Ok(nonce),
                Ok(None) => {
                    continue;
                },
                Err(e) => return Err(eyre::eyre!("Error getting nonce: {:?}", e)),
            }
        }
    }
}

impl<Provider, Pool, Events, Network> EthApiStream for EthPubSub<Provider, Pool, Events, Network>
where
    Provider: BlockReader + EvmEnvProvider + Clone + 'static,
    Network: NetworkInfo + Clone + 'static,  
    Events: CanonStateSubscriptions + Clone + 'static,
    Pool: TransactionPool<Transaction = EthPooledTransaction> + Clone + 'static,  
{

    fn new_headers_stream(&self) -> Pin<Box<dyn Stream<Item = RpcHeader> + Send>> {
        Box::pin(self.new_headers_stream().map(|header| header )) 
    }

    fn full_pending_transaction_stream(&self) -> Pin<Box<dyn Stream<Item = NewTransactionEvent<EthPooledTransaction>> + Send>> {
        Box::pin(self.full_pending_transaction_stream()) 
    }
}
