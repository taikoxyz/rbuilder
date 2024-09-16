use crate::primitives::{
    serialize::CancelShareBundle, BundleReplacementKey, Order, OrderId, OrderReplacementKey,
    ShareBundleReplacementKey,
};
use ahash::HashMap;
use futures::Future;
use lru::LruCache;
use reth::{primitives::constants::SLOT_DURATION, providers::StateProviderBox};
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    time::{Duration, Instant}, sync::Arc,
};
use tokio::sync::mpsc::{self};
use tracing::{error, trace};

use super::{
    order_sink::{OrderPoolCommand, OrderSender2OrderSink},
    replaceable_order_sink::ReplaceableOrderSink,
    ReplaceableOrderPoolCommand,
};
use ethers::{
    prelude::*,
    types::{Bytes, H256, U256, Address as EthersAddress},
    providers::{Http as EthersHttp, Provider as EthersProvider},
};

use url::Url;
use web3::{
    contract::{Contract, Options},
    ethabi::{self, Uint},
    Web3,
};

const BLOCKS_TO_KEEP_TXS: u32 = 5;
const TIME_TO_KEEP_TXS: Duration = SLOT_DURATION.saturating_mul(BLOCKS_TO_KEEP_TXS);

const TIME_TO_KEEP_BUNDLE_CANCELLATIONS: Duration = Duration::from_secs(60);

// For testing Gwyneth
const MEMPOOL_TX_THRESHOLD: usize = 1;
// Constants for L1 RPC URL and TaikoL1 address
const L1_RPC_URL: &str = "http://localhost:8545";
const TAIKO_L1_ADDRESS: &str = "0x9fCF7D13d10dEdF17d0f24C62f0cf4ED462f65b7";


#[derive(Clone, Debug)]
struct BlockMetadata {
    block_hash: H256,
    parent_block_hash: H256,
    parent_meta_hash: H256,
    l1_hash: H256,
    difficulty: U256,
    blob_hash: H256,
    extra_data: H256,
    coinbase: Address,
    l2_block_number: u64,
    gas_limit: u32,
    l1_state_block_number: u32,
    timestamp: u64,
    tx_list_byte_offset: u32,
    tx_list_byte_size: u32,
    blob_used: bool,
}

/// Push to pull for OrderSink. Just poll de UnboundedReceiver to get the orders.
#[derive(Debug)]
pub struct OrdersForBlock {
    pub new_order_sub: mpsc::UnboundedReceiver<OrderPoolCommand>,
}

impl OrdersForBlock {
    /// Helper to create a OrdersForBlock "wrapped" with a OrderSender2OrderSink.
    /// Give this OrdersForBlock to an order pull stage and push on the returned OrderSender2OrderSink
    pub fn new_with_sink() -> (Self, OrderSender2OrderSink) {
        let (sink, sender) = OrderSender2OrderSink::new();
        (
            OrdersForBlock {
                new_order_sub: sender,
            },
            sink,
        )
    }
}

/// Events (orders/cancellations) for a single block
#[derive(Debug, Default)]
struct BundleBlockStore {
    /// Bundles and SharedBundles
    bundles: Vec<Order>,
    cancelled_sbundles: Vec<ShareBundleReplacementKey>,
}

#[derive(Debug)]
struct SinkSubscription {
    sink: Box<dyn ReplaceableOrderSink>,
    block_number: u64,
}

/// returned by add_sink to be used on remove_sink
#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub struct OrderPoolSubscriptionId(u64);

/// Repository of ALL orders and cancellations that arrives us via process_commands. No processing is done here.
/// The idea is that OrderPool is alive from the start of the universe and we can ask for the
/// events (Orders and cancellations) for a particular block even if the orders arrived in the past.
/// Since by infra restrictions bundle cancellations don't have an associated block so we store them for a while and asume
/// they are valid for all in progress sinks
#[derive(Debug)]
pub struct OrderPool {
    mempool_txs: Vec<(Order, Instant)>,
    /// cancelled bundle, cancellation arrival time
    bundle_cancellations: VecDeque<(BundleReplacementKey, Instant)>,
    bundles_by_target_block: HashMap<u64, BundleBlockStore>,
    known_orders: LruCache<(OrderId, u64), ()>,
    sinks: HashMap<OrderPoolSubscriptionId, SinkSubscription>,
    next_sink_id: u64,
}

impl Default for OrderPool {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderPool {
    pub fn new() -> Self {
        OrderPool {
            mempool_txs: Vec::new(),
            bundles_by_target_block: HashMap::default(),
            known_orders: LruCache::new(NonZeroUsize::new(10_000).unwrap()),
            sinks: Default::default(),
            next_sink_id: 0,
            bundle_cancellations: Default::default(),
        }
    }

    pub fn process_commands(&mut self, commands: Vec<ReplaceableOrderPoolCommand>) {
        println!("Dani debug: OrderPool received {} commands to process", commands.len());
        commands.into_iter().for_each(|oc| self.process_command(oc));
        println!("Dani debug: OrderPool finished processing commands");
    }

    fn process_order(&mut self, order: &Order) {
        let target_block = order.target_block();
        let order_id = order.id();
        if self
            .known_orders
            .contains(&(order_id, target_block.unwrap_or_default()))
        {
            trace!(?order_id, "Order known, dropping");
            return;
        }
        trace!(?order_id, "Adding order");

        let (order, target_block) = match &order {
            Order::Tx(..) => {
                self.mempool_txs.push((order.clone(), Instant::now()));
                (order, None)
            }
            Order::Bundle(bundle) => {
                let target_block = bundle.block;
                let bundles_store = self
                    .bundles_by_target_block
                    .entry(target_block)
                    .or_default();
                bundles_store.bundles.push(order.clone());
                (order, Some(target_block))
            }
            Order::ShareBundle(bundle) => {
                let target_block = bundle.block;
                let bundles_store = self
                    .bundles_by_target_block
                    .entry(target_block)
                    .or_default();
                bundles_store.bundles.push(order.clone());
                (order, Some(target_block))
            }
        };
        self.known_orders
            .put((order.id(), target_block.unwrap_or_default()), ());
    }

    fn process_remove_sbundle(&mut self, cancellation: &CancelShareBundle) {
        let bundles_store = self
            .bundles_by_target_block
            .entry(cancellation.block)
            .or_default();
        bundles_store.cancelled_sbundles.push(cancellation.key);
    }

    fn process_remove_bundle(&mut self, key: &BundleReplacementKey) {
        self.bundle_cancellations.push_back((*key, Instant::now()));
    }

    fn process_command(&mut self, command: ReplaceableOrderPoolCommand) {
        match &command {
            ReplaceableOrderPoolCommand::Order(order) => {
                println!("Dani debug: Processing order: {:?}", order.id());
                self.process_order(order)
            },
            ReplaceableOrderPoolCommand::CancelShareBundle(c) => {
                println!("Dani debug: Processing cancel share bundle: {:?}", c.key);
                self.process_remove_sbundle(c)
            },
            ReplaceableOrderPoolCommand::CancelBundle(key) => {
                println!("Dani debug: Processing cancel bundle: {:?}", key);
                self.process_remove_bundle(key)
            },
        }
        
        let target_block = command.target_block();
        println!("Dani debug: Command target block: {:?}", target_block);
        
        let initial_sink_count = self.sinks.len();
        self.sinks.retain(|_, sub| {
            if !sub.sink.is_alive() {
                println!("Dani debug: Removing dead sink");
                return false;
            }
            if target_block.is_none() || target_block == Some(sub.block_number) {
                let send_ok = match command.clone() {
                    ReplaceableOrderPoolCommand::Order(o) => {
                        println!("Dani debug: Inserting order into sink");
                        sub.sink.insert_order(o)
                    },
                    ReplaceableOrderPoolCommand::CancelShareBundle(cancel) => {
                        println!("Dani debug: Removing share bundle from sink");
                        sub.sink.remove_bundle(OrderReplacementKey::ShareBundle(cancel.key))
                    },
                    ReplaceableOrderPoolCommand::CancelBundle(key) => {
                        println!("Dani debug: Removing bundle from sink");
                        sub.sink.remove_bundle(OrderReplacementKey::Bundle(key))
                    }
                };
                if !send_ok {
                    println!("Dani debug: Failed to send to sink, removing sink");
                    return false;
                }
            }
            true
        });
        let final_sink_count = self.sinks.len();
        println!("Dani debug: Sink count changed from {} to {}", initial_sink_count, final_sink_count);
    }

    // In your OrderPool impl
    pub async fn propose_block() -> Result<(), Box<dyn std::error::Error>> {
        println!("Trying to propose blocks");

        let provider = EthersProvider::<EthersHttp>::try_from(L1_RPC_URL).expect("Failed to create provider");

        let tx_lists = vec![Bytes::from(hex::decode("f90171b87902f87683028c6280843b9aca00847735940083030d4094f93ee4cf8c6c40b329b0c0626f28333c132cf241880de0b6b3a764000080c080a07f983645ddf8365d14e5fb4e3b07c19fe31e23edd9ee4a737388acc2da7e64a3a072a56043512806a6de5f66f28bb659236eea41c9d66db8493f436804c42723d3b87902f87683028c6280843b9aca00847735940083030d4094f93ee4cf8c6c40b329b0c0626f28333c132cf241880de0b6b3a764000080c001a030911ab2ebf76f1e1bfe00d721207d929053efb051d50708a10dd9f66f84bacba07705a7cdb86ff00aa8c131ef3c4cb2ea2f2f4730d93308f1afbb94a04c1c9ae9b87902f87683028c6280843b9aca00847735940083030d4094f93ee4cf8c6c40b329b0c0626f28333c132cf241880de0b6b3a764000080c001a07da8dfb5bc3b7b353f9614bcd83733168500d1e06f2bcdac761cc54c85847e6aa03b041b0605e86aa379ff0f58a60743da411dfd1a9d4f1d18422a862f67a57fee").expect("Invalid hex string"))];

        let tx_list_hash = web3::signing::keccak256(&tx_lists[0]);

        let meta = Self::create_block_metadata(H256::from_slice(&tx_list_hash), tx_lists[0].len() as u32);
        let mut bytes = [0u8; 32];
        meta.difficulty.to_big_endian(&mut bytes);
        let meta_encoded = ethabi::encode(&[ethabi::Token::Tuple(vec![
            ethabi::Token::FixedBytes(meta.block_hash.as_bytes().to_vec()),
            ethabi::Token::FixedBytes(meta.parent_block_hash.as_bytes().to_vec()),
            ethabi::Token::FixedBytes(meta.parent_meta_hash.as_bytes().to_vec()),
            ethabi::Token::FixedBytes(meta.l1_hash.as_bytes().to_vec()),
            ethabi::Token::Uint(web3::types::U256::from_big_endian(&bytes)),
            ethabi::Token::FixedBytes(meta.blob_hash.as_bytes().to_vec()),
            ethabi::Token::FixedBytes(meta.extra_data.as_bytes().to_vec()),
            ethabi::Token::Address(web3::types::H160::from_slice(meta.coinbase.0.as_slice())),
            ethabi::Token::Uint(meta.l2_block_number.into()),
            ethabi::Token::Uint(meta.gas_limit.into()),
            ethabi::Token::Uint(meta.l1_state_block_number.into()),
            ethabi::Token::Uint(meta.timestamp.into()),
            ethabi::Token::Uint(meta.tx_list_byte_offset.into()),
            ethabi::Token::Uint(meta.tx_list_byte_size.into()),
            ethabi::Token::Bool(meta.blob_used),
        ])]);
    
        println!("Putting calldata together");
    
        let function = ethabi::Function {
            name: "proposeBlock".to_string(),
            inputs: vec![
                ethabi::Param {
                    name: "params".to_string(),
                    kind: ethabi::ParamType::Array(Box::new(ethabi::ParamType::Bytes)),
                    internal_type: None,
                },
                ethabi::Param {
                    name: "txList".to_string(),
                    kind: ethabi::ParamType::Array(Box::new(ethabi::ParamType::Bytes)),
                    internal_type: None,
                },
            ],
            outputs: vec![],
            constant: Some(false),
            state_mutability: ethabi::StateMutability::NonPayable,
        };
    
        let data = function.encode_input(&[
            ethabi::Token::Array(vec![ethabi::Token::Bytes(meta_encoded)]),
            ethabi::Token::Array(
                tx_lists
                    .into_iter()
                    .map(|b| ethabi::Token::Bytes(b.to_vec()))
                    .collect(),
            ),
        ])?;
    
        let tx_object = TransactionRequest {
            to: Some(TAIKO_L1_ADDRESS.parse()?),
            data: Some(Bytes::from_iter(data.iter())),
            ..Default::default()
        };
    
        let chain_id = 160010u64;
    
        let wallet: LocalWallet = "39725efee3fb28614de3bacaffe4cc4bd8c436257e2c8bb887c4b5c4be45e76d"
            .parse::<LocalWallet>()?
            .with_chain_id(chain_id);
    
        let client = SignerMiddleware::new(provider, wallet);
    
        println!("Sending transaction");
    
        let pending_tx = client.send_transaction(tx_object, None).await?;
    
        println!("Transaction sent. Hash: {:?}", pending_tx.tx_hash());
    
        Ok(())
    }

    fn create_block_metadata(tx_list_hash: H256, tx_list_byte_size: u32) -> BlockMetadata {
        BlockMetadata {
            block_hash: H256::random(),
            parent_block_hash: H256::zero(),
            parent_meta_hash: H256::zero(),
            l1_hash: H256::zero(),
            difficulty: U256::zero(),
            blob_hash: tx_list_hash,
            extra_data: H256::zero(),
            coinbase: Address::random(),
            l2_block_number: 0,
            gas_limit: 15_000_000,
            l1_state_block_number: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u64,
            tx_list_byte_offset: 0,
            tx_list_byte_size,
            blob_used: false,
        }
    }

    /// Adds a sink and pushes the current state for the block
    pub fn add_sink(
        &mut self,
        block_number: u64,
        mut sink: Box<dyn ReplaceableOrderSink>,
    ) -> OrderPoolSubscriptionId {
        for order in self.mempool_txs.iter().map(|(order, _)| order.clone()) {
            sink.insert_order(order);
        }
        for cancellation_key in self.bundle_cancellations.iter().map(|(key, _)| key) {
            sink.remove_bundle(OrderReplacementKey::Bundle(*cancellation_key));
        }

        if let Some(bundle_store) = self.bundles_by_target_block.get(&block_number) {
            for order in bundle_store.bundles.iter().cloned() {
                sink.insert_order(order);
            }
            for order_id in bundle_store.cancelled_sbundles.iter().cloned() {
                sink.remove_bundle(OrderReplacementKey::ShareBundle(order_id));
            }
        }
        let res = OrderPoolSubscriptionId(self.next_sink_id);
        self.next_sink_id += 1;
        self.sinks
            .insert(res.clone(), SinkSubscription { sink, block_number });
        res
    }

    /// Removes the sink. If present returns it
    pub fn remove_sink(
        &mut self,
        id: &OrderPoolSubscriptionId,
    ) -> Option<Box<dyn ReplaceableOrderSink>> {
        self.sinks.remove(id).map(|s| s.sink)
    }

    /// Should be called when last block is updated.
    /// It's slow but since it only happens at the start of the block it does now matter.
    /// It clears old txs from the mempool and old bundle_cancellations.
    pub fn head_updated(&mut self, new_block_number: u64, new_state: &StateProviderBox) {
        // remove from bundles by target block
        self.bundles_by_target_block
            .retain(|block_number, _| *block_number > new_block_number);

        // remove mempool txs by nonce, time
        self.mempool_txs.retain(|(order, time)| {
            if time.elapsed() > TIME_TO_KEEP_TXS {
                return false;
            }
            for nonce in order.nonces() {
                if nonce.optional {
                    continue;
                }
                let onchain_nonce = new_state
                    .account_nonce(nonce.address)
                    .map_err(|e| error!("Failed to get a nonce: {}", e))
                    .unwrap_or_default()
                    .unwrap_or_default();
                if onchain_nonce > nonce.nonce {
                    return false;
                }
            }
            true
        });
        //remove old bundle cancellations
        while let Some((_, oldest_time)) = self.bundle_cancellations.front() {
            if oldest_time.elapsed() < TIME_TO_KEEP_BUNDLE_CANCELLATIONS {
                break; // reached the new ones
            }
            self.bundle_cancellations.pop_front();
        }
    }

    /// Does NOT take in account cancellations
    pub fn content_count(&self) -> (usize, usize) {
        let tx_count = self.mempool_txs.len();
        let bundle_count = self
            .bundles_by_target_block
            .values()
            .map(|v| v.bundles.len())
            .sum();
        (tx_count, bundle_count)
    }
}
