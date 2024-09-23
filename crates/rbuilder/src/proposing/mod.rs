use std::sync::Arc;

use alloy_signer_local::LocalSigner;
use ethers::prelude::k256;
use reth_primitives::{SealedBlockWithSenders, SealedHeader, BlockBody};
use eyre::Result;
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{B256, U256, Address, fixed_bytes, FixedBytes};
use alloy_signer_local::{PrivateKeySigner};
use alloy_transport_http::Http;
use alloy_transport_http::Client;
use std::str::FromStr;
use url::Url;  // Add this import

#[derive(Clone, Debug)]
struct BlockMetadata {
    block_hash: B256,
    parent_block_hash: B256,
    parent_meta_hash: B256,
    l1_hash: B256,
    difficulty: U256,
    blob_hash: B256,
    extra_data: B256,
    coinbase: Address,
    l2_block_number: u64,
    gas_limit: u32,
    l1_state_block_number: u32,
    timestamp: u64,
    tx_list_byte_offset: u32,
    tx_list_byte_size: u32,
    blob_used: bool,
}

#[derive(Debug, Clone)]
pub struct BlockProposer {
    // Add necessary fields for L1 interaction
    rpc_url: String,
    contract_address: Address,
    provider: RootProvider<Http<Client>>,
    signer: LocalSigner<k256::ecdsa::SigningKey>,
}

impl BlockProposer {
    pub fn new(rpc_url: String, contract_address_str: String, private_key_str: String) -> Result<Self> {
        let contract_address = Address::parse_checksummed(&contract_address_str, None)?;
        assert_eq!(contract_address.to_checksum(None), contract_address_str);

        // Create the signer directly from the private key string
        let signer = PrivateKeySigner::from_str(&private_key_str)?;
        // signer.address();
        // let signer_wallet = EthereumWallet::from(signer.clone());

        let url = Url::parse(&rpc_url)?;
        let provider = ProviderBuilder::new().on_http(url);

        Ok(BlockProposer {
            rpc_url,
            contract_address,
            provider,
            signer,
        })
    }

    pub async fn propose_block(&self, block: &SealedBlockWithSenders) -> Result<()> {
        // Extract necessary data from the block
        //let block_number = block.block.header.header.number();
        let sealed_header;
        let block_body;
        (sealed_header, block_body) = block.clone().block.split_header_body();

        let (sealed_header, block_body) = block.clone().block.split_header_body();

        // Create the transaction data
        let tx_data = self.create_propose_block_tx_data(&sealed_header, &block_body)?;

        // Get the current nonce for the wallet
        let nonce = self.provider.get_transaction_count(self.signer.address()).await?;
        
        // Dani todo: Implement the logic to propose the block to the L1 smart contract
        // This might involve creating and sending a transaction to the L1 contract

        Ok(())
    }

    fn create_propose_block_tx_data(&self, sealed_header: &SealedHeader, block_body: &BlockBody) -> Result<Vec<u8>> {
        // Implement the logic to create the transaction data for proposing the block
        // This will depend on your specific smart contract's function signature and requirements
        // For now, we'll just return an empty vector
        Ok(vec![])
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProposeBlockError {
    #[error("Failed to propose block: {0}")]
    ProposalFailed(String),
    // Add other error variants as needed
}