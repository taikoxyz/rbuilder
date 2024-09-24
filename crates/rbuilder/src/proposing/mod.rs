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
use url::Url;
use crate::mev_boost::{SubmitBlockRequest};
use alloy_rpc_types_engine::{ExecutionPayload, ExecutionPayloadV2, ExecutionPayloadV3};

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

        let url = Url::parse(&rpc_url)?;
        let provider = ProviderBuilder::new().on_http(url);

        Ok(BlockProposer {
            rpc_url,
            contract_address,
            provider,
            signer,
        })
    }

    pub async fn propose_block(&self, request: &SubmitBlockRequest) -> Result<()> {
        let execution_payload = request.execution_payload();

        // Create the transaction data
        let tx_data = self.create_propose_block_tx_data(&execution_payload)?;

        // Get the current nonce for the wallet
        let nonce = self.provider.get_transaction_count(self.signer.address()).await?;

        // TODO: Implement the logic to propose the block to the L1 smart contract

        Ok(())
    }

    // Implement the logic to create the transaction data for proposing the block
    fn create_propose_block_tx_data(&self, execution_payload: &ExecutionPayload) -> Result<Vec<u8>> {
        // Later on the payload
        let mut serialized_payload = Vec::new();

        //Extract necessary data from payload
        if let ExecutionPayload::V2(payload) = execution_payload {
            let block_number = payload.payload_inner.block_number;
        } else if let ExecutionPayload::V3(payload) = execution_payload {
            let block_number = payload.payload_inner.payload_inner.block_number;

        } else {
            // Handle unsupported versions
            return Err(eyre::eyre!("Unsupported ExecutionPayload version"));
        }
        
        Ok(serialized_payload)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProposeBlockError {
    #[error("Failed to propose block: {0}")]
    ProposalFailed(String),
    // Add other error variants as needed
}