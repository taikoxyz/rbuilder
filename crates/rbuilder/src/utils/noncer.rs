use ahash::HashMap;
use alloy_primitives::{Address, B256};
use reth::providers::{ProviderFactory, StateProviderBox};
use reth_db::database::Database;
use reth_errors::ProviderResult;
use revm_primitives::ChainAddress;
use std::sync::{Arc, Mutex};

/// Struct to get nonces for Addresses, caching the results.
/// NonceCache contains the data (but doesn't allow you to query it) and NonceCacheRef is a reference that allows you to query it.
/// Usage:
/// - Create a NonceCache
/// - For every context where the nonce is needed call NonceCache::get_ref and call NonceCacheRef::nonce all the times you need.
///   Neither NonceCache or NonceCacheRef are clonable, the clone of shared info happens on get_ref where we clone the internal cache.
#[derive(Debug)]
pub struct NonceCache<DB> {
    provider_factory: HashMap<u64, ProviderFactory<DB>>,
    // We have to use Arc<Mutex here because Rc are not Send (so can't be used in futures)
    // and borrows don't work when nonce cache is a field in a struct.
    cache: Arc<Mutex<HashMap<ChainAddress, u64>>>,
    block: HashMap<u64, B256>,
}

impl<DB: Database> NonceCache<DB> {
    pub fn new(provider_factory: HashMap<u64, ProviderFactory<DB>>, block: HashMap<u64, B256>) -> Self {
        Self {
            provider_factory,
            cache: Arc::new(Mutex::new(HashMap::default())),
            block,
        }
    }

    pub fn get_ref(&self) -> ProviderResult<NonceCacheRef> {
        let mut states = HashMap::default();
        for (chain_id, provider_factory) in self.provider_factory.iter() {
            states.insert(*chain_id, provider_factory.history_by_block_hash(self.block[chain_id])?);
        }
        Ok(NonceCacheRef {
            states,
            cache: Arc::clone(&self.cache),
        })
    }
}

pub struct NonceCacheRef {
    states: HashMap<u64, StateProviderBox>,
    cache: Arc<Mutex<HashMap<ChainAddress, u64>>>,
}

impl NonceCacheRef {
    pub fn nonce(&self, address: ChainAddress) -> ProviderResult<u64> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(nonce) = cache.get(&address) {
            return Ok(*nonce);
        }
        // TODO: Brecht
        let mut default_chain_id = 1;
        for (chain_id, _state) in self.states.iter() {
            if default_chain_id == 1 {
                default_chain_id = *chain_id;
            }
        }
        let nonce = self.states[&address.0].account_nonce(address.1)?.unwrap_or_default();
        cache.insert(address, nonce);
        Ok(nonce)
    }
}
