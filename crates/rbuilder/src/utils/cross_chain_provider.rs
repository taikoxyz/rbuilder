use std::{collections::HashMap, ops::RangeBounds, sync::Arc};

use ahash::HashMap;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::U256;
use reth_chainspec::ChainInfo;
use reth_db::{mdbx::tx::Tx, transaction::DbTxMut, Database};
use reth_errors::ProviderResult;
use reth_libmdbx::RW;
use reth_primitives::{BlockHash, BlockNumber, Header, SealedHeader};
use reth_provider::{BlockHashReader, BlockIdReader, BlockNumReader, DatabaseProviderFactory, DatabaseProviderRO, HeaderProvider, StateProviderBox, StateProviderFactory};
use revm_primitives::B256;


pub fn testtt(p: CrossChainProvider, q: CrossChainProvider) {
    let _ = <CrossChainProvider as DatabaseProviderFactory<L1Database>>::database_provider_ro(&p);

    let mut m = HashMap::new();
    m.insert(0, p);
    m.insert(1, q);
}

fn call(
    p1: reth_provider::providers::BlockchainProvider2<std::sync::Arc<reth_db::DatabaseEnv>>,
    p2: reth_provider::providers::BlockchainProvider<std::sync::Arc<reth_db::test_utils::TempDatabase<reth_db::DatabaseEnv>>>,
) {
    let p1 = CrossChainProvider::L1(p1);
    let p2 = CrossChainProvider::L2(p2);
    testtt(p1, p2);

    
}

type L1Database = std::sync::Arc<reth_db::DatabaseEnv>;
type L2Database = std::sync::Arc<reth_db::test_utils::TempDatabase<reth_db::DatabaseEnv>>;

#[derive(Clone)]
pub enum CrossChainProvider {
    L1(reth_provider::providers::BlockchainProvider2<L1Database>),
    L2(reth_provider::providers::BlockchainProvider<L2Database>),
    Reopener(ProviderFactoryReopener<Arc<DatabaseEnv>>),
}

impl<DB: Database<TX = reth_db::mdbx::tx::Tx<reth_db::mdbx::RO>>> DatabaseProviderFactory<DB> for CrossChainProvider {
    fn database_provider_ro(&self) -> ProviderResult<DatabaseProviderRO<DB>> {
        match self {
            CrossChainProvider::L1(provider) => provider.database_provider_ro(),
            CrossChainProvider::L2(provider) => provider.database_provider_ro(),
        }
    }
}

impl reth_provider::HeaderProvider for CrossChainProvider {
    fn header(&self,block_hash: &BlockHash) -> ProviderResult<Option<Header>>  {
       match self {
           CrossChainProvider::L1(provider) => provider.header(block_hash),
           CrossChainProvider::L2(provider) => provider.header(block_hash),
       }
    }
    fn header_by_number(&self,num:u64) -> ProviderResult<Option<Header>>  {
         match self {
              CrossChainProvider::L1(provider) => provider.header_by_number(num),
              CrossChainProvider::L2(provider) => provider.header_by_number(num),
         }
    }

    fn header_td(&self,hash: &BlockHash) -> ProviderResult<Option<U256>>  {
        match self {
            CrossChainProvider::L1(provider) => provider.header_td(hash),
            CrossChainProvider::L2(provider) => provider.header_td(hash),
        }
    }

    fn header_td_by_number(&self,number:BlockNumber) -> ProviderResult<Option<U256>>  {
        match self {
            CrossChainProvider::L1(provider) => provider.header_td_by_number(number),
            CrossChainProvider::L2(provider) => provider.header_td_by_number(number),
        }
    }

    fn headers_range(&self,range:impl RangeBounds<BlockNumber>) -> ProviderResult<Vec<Header>>  {
        match self {
            CrossChainProvider::L1(provider) => provider.headers_range(range),
            CrossChainProvider::L2(provider) => provider.headers_range(range),
        }
    }

    fn sealed_header(&self,number:BlockNumber) -> ProviderResult<Option<SealedHeader>>  {
        match self {
            CrossChainProvider::L1(provider) => provider.sealed_header(number),
            CrossChainProvider::L2(provider) => provider.sealed_header(number),
        }
    }

    fn sealed_headers_while(&self,range:impl RangeBounds<BlockNumber> ,predicate:impl FnMut(&SealedHeader) -> bool,) -> ProviderResult<Vec<SealedHeader>>  {
        match self {
            CrossChainProvider::L1(provider) => provider.sealed_headers_while(range,predicate),
            CrossChainProvider::L2(provider) => provider.sealed_headers_while(range,predicate),
        }
    }
}

impl BlockHashReader for CrossChainProvider {
    fn block_hash(&self,number:BlockNumber) -> ProviderResult<Option<B256>>  {
        match self {
            CrossChainProvider::L1(provider) => provider.block_hash(number),
            CrossChainProvider::L2(provider) => provider.block_hash(number),
        }
    }

    fn canonical_hashes_range(&self,start:BlockNumber,end:BlockNumber) -> ProviderResult<Vec<B256>>  {
        match self {
            CrossChainProvider::L1(provider) => provider.canonical_hashes_range(start,end),
            CrossChainProvider::L2(provider) => provider.canonical_hashes_range(start,end),
        }
    }
}
impl BlockNumReader for CrossChainProvider {
    fn chain_info(&self) -> ProviderResult<ChainInfo>  {
        match self {
            CrossChainProvider::L1(provider) => provider.chain_info(),
            CrossChainProvider::L2(provider) => provider.chain_info(),
        }
    }

    fn best_block_number(&self) -> ProviderResult<BlockNumber>  {
        match self {
            CrossChainProvider::L1(provider) => provider.best_block_number(),
            CrossChainProvider::L2(provider) => provider.best_block_number(),
        }
    }

    fn last_block_number(&self) -> ProviderResult<BlockNumber>  {
        match self {
            CrossChainProvider::L1(provider) => provider.last_block_number(),
            CrossChainProvider::L2(provider) => provider.last_block_number(),
        }
    }

    fn block_number(&self,hash:B256) -> ProviderResult<Option<BlockNumber> >  {
        match self {
            CrossChainProvider::L1(provider) => provider.block_number(hash),
            CrossChainProvider::L2(provider) => provider.block_number(hash),
        }
    }
}

impl BlockIdReader for CrossChainProvider {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash> >  {
        match self {
            CrossChainProvider::L1(provider) => provider.pending_block_num_hash(),
            CrossChainProvider::L2(provider) => provider.pending_block_num_hash(),
            
        }
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash> >  {
        match self {
            CrossChainProvider::L1(provider) => provider.safe_block_num_hash(),
            CrossChainProvider::L2(provider) => provider.safe_block_num_hash(),
        }
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash> >  {
        match self {
            CrossChainProvider::L1(provider) => provider.finalized_block_num_hash(),
            CrossChainProvider::L2(provider) => provider.finalized_block_num_hash(),
        }
    }
}

impl StateProviderFactory for CrossChainProvider {
    fn latest(&self) -> ProviderResult<StateProviderBox>  {
        match self {
            CrossChainProvider::L1(provider) => provider.latest(),
            CrossChainProvider::L2(provider) => provider.latest(),
        }
    }

    fn state_by_block_number_or_tag(&self,number_or_tag:BlockNumberOrTag,) -> ProviderResult<StateProviderBox>  {
        match self {
            CrossChainProvider::L1(provider) => provider.state_by_block_number_or_tag(number_or_tag),
            CrossChainProvider::L2(provider) => provider.state_by_block_number_or_tag(number_or_tag),
        }
    }

    fn history_by_block_number(&self,block:BlockNumber) -> ProviderResult<StateProviderBox>  {
        match self {
            CrossChainProvider::L1(provider) => provider.history_by_block_number(block),
            CrossChainProvider::L2(provider) => provider.history_by_block_number(block),
        }
    }

    fn history_by_block_hash(&self,block:BlockHash) -> ProviderResult<StateProviderBox>  {
        match self {
            CrossChainProvider::L1(provider) => provider.history_by_block_hash(block),
            CrossChainProvider::L2(provider) => provider.history_by_block_hash(block),
        }
    }

    fn state_by_block_hash(&self,block:BlockHash) -> ProviderResult<StateProviderBox>  {
        match self {
            CrossChainProvider::L1(provider) => provider.state_by_block_hash(block),
            CrossChainProvider::L2(provider) => provider.state_by_block_hash(block),
        }
    }

    fn pending(&self) -> ProviderResult<StateProviderBox>  {
        match self {
            CrossChainProvider::L1(provider) => provider.pending(),
            CrossChainProvider::L2(provider) => provider.pending(),
        }
    }

    fn pending_state_by_hash(&self,block_hash: B256) -> ProviderResult<Option<StateProviderBox> >  {
        match self {
            CrossChainProvider::L1(provider) => provider.pending_state_by_hash(block_hash),
            CrossChainProvider::L2(provider) => provider.pending_state_by_hash(block_hash),
        }
    }
}