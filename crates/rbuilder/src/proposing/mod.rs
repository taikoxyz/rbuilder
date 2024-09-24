use std::sync::Arc;

use alloy_signer_local::LocalSigner;
use ethers::prelude::k256;
use reth_primitives::{SealedBlockWithSenders, SealedHeader, BlockBody};
use eyre::Result;
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{U64, B256, U256, Address, fixed_bytes, FixedBytes, Bytes};
use alloy_signer_local::{PrivateKeySigner};
use alloy_transport_http::Http;
use alloy_transport_http::Client;
use std::str::FromStr;
use url::Url;
use crate::mev_boost::{SubmitBlockRequest};
use alloy_rpc_types_engine::{ExecutionPayload, ExecutionPayloadV2, ExecutionPayloadV3};
use alloy_sol_types::{sol, SolType};

use std::convert::TryFrom;
// Using sol macro to use solidity code here.
sol! {
    struct BlockMetadata {
        bytes32 blockHash;
        bytes32 parentBlockHash;
        bytes32 parentMetaHash;
        bytes32 l1Hash;
        uint256 difficulty;
        bytes32 blobHash;
        bytes32 extraData;
        address coinbase;
        uint64 l2BlockNumber;
        uint32 gasLimit;
        uint32 l1StateBlockNumber;
        uint64 timestamp;
        uint24 txListByteOffset;
        uint24 txListByteSize;
        bool blobUsed;
    }

    function proposeBlock(BlockMetadata[] calldata params, bytes[] calldata txList) external payable;
}

// #[derive(Clone, Debug)]
// struct BlockMetadata {
//     block_hash: B256,
//     parent_block_hash: B256,
//     parent_meta_hash: B256,
//     l1_hash: B256,
//     difficulty: U256,
//     blob_hash: B256,
//     extra_data: B256,
//     coinbase: Address,
//     l2_block_number: u64,
//     gas_limit: u32,
//     l1_state_block_number: u32,
//     timestamp: u64,
//     tx_list_byte_offset: u32,
//     tx_list_byte_size: u32,
//     blob_used: bool,
// }

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
        let (meta, tx_list) = self.create_propose_block_tx_data(&execution_payload)?;
        
        // // Encode the metadata
        // let meta_encoded = BlockMetadata::encode(&meta);

        // // Prepare the function call data
        // let function = proposeBlockFunction::abi();
        // let data = function.encode(&[
        //     sol!(bytes[])::encode(&[meta_encoded]),
        //     sol!(bytes[])::encode(&[tx_list_encoded]),
        // ])?;

        // // Create the transaction request
        // let tx_request = TransactionRequest::new()
        //     .to(self.contract_address)
        //     .data(data);

        // // Get the current nonce for the wallet
        // let nonce = self.provider.get_transaction_count(self.signer.address()).await?;
        
        // println!("Sending transaction");
        
        // let pending_tx = self.signer.send_transaction(tx_request.nonce(nonce), &self.provider).await?;

        // println!("Transaction sent. Hash: {:?}", pending_tx.tx_hash());

        Ok(())
    }

    // Implement the logic to create the transaction data for proposing the block
    fn create_propose_block_tx_data(&self, execution_payload: &ExecutionPayload) -> Result<(BlockMetadata, Vec<u8>)> {
        let (block_number, parent_hash, state_root, receipts_root, gas_limit, gas_used, timestamp, extra_data, base_fee_per_gas, transactions) = match execution_payload {
            ExecutionPayload::V2(payload) => {
                let inner = &payload.payload_inner;
                (
                    inner.block_number,
                    inner.parent_hash,
                    inner.state_root,
                    inner.receipts_root,
                    inner.gas_limit,
                    inner.gas_used,
                    inner.timestamp,
                    inner.extra_data.clone(),
                    inner.base_fee_per_gas,
                    inner.transactions.clone(),
                )
            },
            ExecutionPayload::V3(payload) => {
                let inner = &payload.payload_inner.payload_inner;
                (
                    inner.block_number,
                    inner.parent_hash,
                    inner.state_root,
                    inner.receipts_root,
                    inner.gas_limit,
                    inner.gas_used,
                    inner.timestamp,
                    inner.extra_data.clone(),
                    inner.base_fee_per_gas,
                    inner.transactions.clone(),
                )
            },
            _ => return Err(eyre::eyre!("Unsupported ExecutionPayload version")),
        };

        // Create tx_list from transactions
        let tx_list = transactions.iter().flat_map(|tx| tx.0.clone()).collect::<Vec<u8>>();
        let tx_list_hash = B256::from(alloy_primitives::keccak256(&tx_list));

        let meta = BlockMetadata {
            blockHash: B256::random(), // You might want to calculate this based on the payload
            parentBlockHash: parent_hash,
            parentMetaHash: B256::ZERO, // You might need to get this from somewhere else
            l1Hash: B256::ZERO, // You might need to get this from L1
            difficulty: U256::ZERO, // This might need to be set differently for PoS
            blobHash: tx_list_hash,
            extraData: B256::from_slice(&extra_data),
            coinbase: self.signer.address(),
            l2BlockNumber: block_number,
            gasLimit: gas_limit.try_into().map_err(|_| eyre::eyre!("Gas limit overflow"))?,
            l1StateBlockNumber: 0, // You might need to get this from L1
            timestamp: timestamp,
            txListByteOffset: 0u32.try_into().map_err(|_| eyre::eyre!("txListByteOffset conversion error"))?,
            txListByteSize: (tx_list.len() as u32).try_into().map_err(|_| eyre::eyre!("txListByteSize conversion error"))?,
            blobUsed: false,
        };

        Ok((meta, tx_list))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProposeBlockError {
    #[error("Failed to propose block: {0}")]
    ProposalFailed(String),
    // Add other error variants as needed
}