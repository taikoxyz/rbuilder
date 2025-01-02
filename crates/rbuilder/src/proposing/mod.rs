use alloy_network::{Ethereum, EthereumWallet, NetworkWallet, TransactionBuilder};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rlp::{Decodable, Encodable};
use alloy_signer_local::PrivateKeySigner;
//use alloy_sol_types::{sol, SolCall};
use eyre::Result;
//use revm_primitives::{Address, B256, U256};
use alloy_primitives::{Address, B256, U256};
use jsonrpsee::{core::traits::ToRpcParams, http_client::HttpClient, types::Request};
use reth::rpc::server_types::eth::receipt;
use reth_primitives::{TransactionSigned, U64};
//use revm_primitives::address;
use url::Url;
//use crate::mev_boost::{SubmitBlockRequest};
//use alloy_rpc_types_engine::{ExecutionPayload};
use alloy_network::eip2718::Encodable2718;
use alloy_rpc_types_engine::ExecutionPayload;
use alloy_sol_types::{sol, SolCall, SolType};
use std::{str::FromStr, sync::Arc};

use alloy_rpc_types::{TransactionInput, TransactionReceipt, TransactionRequest};
use serde_json::value::RawValue;
use crate::{live_builder::gwyneth::{EthApiStream, EthTxSender}, mev_boost::{RelayError, SubmitBlockRequest}};
use jsonrpsee::{
    core::{
        client::{ClientT, SubscriptionClientT},
        params::ArrayParams,
    },
    rpc_params,
    types::error::ErrorCode,
};
// Using sol macro to use solidity code here.
sol! {
    #[derive(Debug)]
    /// @dev Struct containing data only required for proving a block
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
        bytes txList;
    }

    //#[sol(rpc)]
    #[allow(dead_code)]
    contract Rollup {
        function proposeBlock(BlockMetadata[] calldata data) external payable;
    }
}

#[derive(Debug, Clone)]
pub struct BlockProposer {
    l1_client: Option<HttpClient>,
    l1_rpc: Option<String>,
    contract_address: String,
    private_key: String,
}

impl BlockProposer {
    pub fn new(l1_client: Option<HttpClient>, l1_rpc: Option<String>, contract_address: String, private_key: String) -> Result<Self> {
        Ok(BlockProposer {
            l1_client,
            l1_rpc,
            contract_address,
            private_key,
        })
    }

    pub async fn propose_block(&self, request: &SubmitBlockRequest) -> Result<(), RelayError> {
        println!("[rb] propose_block");

        let execution_payload = request.execution_payload();
        let (meta, num_txs) = self.create_propose_block_tx_data(&execution_payload)
            .expect("Failed to create BlockMetadata in propose block");

        let propose_data = Rollup::proposeBlockCall {
            data: vec![meta.clone()],
        }.abi_encode();

        let decoded_transactions: Vec<TransactionSigned> = decode_transactions(&meta.txList);
        println!("[rb] decoded_transactions: {:?}", decoded_transactions);


        // Create a signer from a random private key.
        let signer = PrivateKeySigner::from_str(&self.private_key).unwrap();
        let wallet = EthereumWallet::from(signer.clone());

        // Build a transaction to send 100 wei from Alice to Bob.
        // The `from` field is automatically filled to the first signer's address (Alice).
        let mut tx = TransactionRequest::default()
            .with_to(Address::from_str(&self.contract_address).unwrap())
            .input(TransactionInput {
                input: Some(propose_data.into()),
                data: None,
            })
            .with_value(U256::from(0))
            .with_gas_limit(5_000_000)
            .with_max_priority_fee_per_gas(1_000_000)
            .with_max_fee_per_gas(10_000_000);

        let receipt = match (&self.l1_client, &self.l1_rpc) {
            (_, Some(url)) => {
                println!("[rb] BlockProposer using L1 RPC URL: {}", url);
                let provider = ProviderBuilder::new().on_http(Url::parse(&url).unwrap());
                let nonce = provider.get_transaction_count(signer.address()).await
                    .map_err(|e| RelayError::ProposalError(e.to_string()))?;
                let chain_id = provider.get_chain_id().await
                    .map_err(|e| RelayError::ProposalError(e.to_string()))?;
                tx.nonce = Some(nonce);
                tx.chain_id = Some(chain_id);
                println!("[rb] BlockProposer tx_envelope done - nonce {:?} on {:?}", nonce, chain_id);

                let tx_encoded = <TransactionRequest as TransactionBuilder<Ethereum>>::build(tx, &wallet)
                    .await
                    .map_err(|e| RelayError::ProposalError(e.to_string()))?
                    .encoded_2718();

                let pending_tx = provider
                    .send_raw_transaction(&tx_encoded)
                    .await
                    .map_err(|e| RelayError::ProposalError(e.to_string()))?;
                println!("[rb] Pending transaction... {}", pending_tx.tx_hash());
                pending_tx.get_receipt().await.map_err(|e| RelayError::ProposalError(e.to_string()))?
            },
            (Some(client), _) => {
                println!("[rb] BlockProposer using L1 client {:?}", client);
                let nonce = client.request::<U256, _>(
                        "eth_getTransactionCount", 
                        rpc_params![signer.address().to_string()]
                    ).await
                    .map_err(|e| RelayError::ProposalError(e.to_string()))?;
                let chain_id = client.request::<Option<U64>, _>("eth_chainId", rpc_params![])
                    .await
                    .map_err(|e| RelayError::ProposalError(e.to_string()))?;
                println!("[rb] BlockProposer tx_envelope done - nonce {:?} on {:?}", nonce, chain_id);
                
                tx.nonce = Some(nonce.try_into().unwrap());
                tx.chain_id = chain_id.map(|c| c.try_into().unwrap());
                // Build the transaction with the provided wallet. Flashbots Protect requires the transaction to
                // be signed locally and send using `eth_sendRawTransaction`.
                let tx_encoded = <TransactionRequest as TransactionBuilder<Ethereum>>::build(tx, &wallet)
                    .await
                    .map_err(|e| RelayError::ProposalError(e.to_string()))?
                    .encoded_2718();

                let params = format!("0x{}", reth_primitives::hex::encode(tx_encoded));
                let tx_hash = client.request::<B256, _>("eth_sendRawTransaction", rpc_params!(params))
                    .await
                    .map_err(|e| RelayError::ProposalError(e.to_string()))?
                    .to_string();
                println!("[rb] BlockProposer eth_sendRawTransaction");
                let mut receipt = None;
                loop {
                    receipt = client.request::<Option<TransactionReceipt>, _>("eth_getTransactionReceipt", rpc_params!(tx_hash.clone()))
                        .await
                        .map_err(|e| RelayError::ProposalError(e.to_string()))?;
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    if receipt.is_some() {
                        break;
                    }
                }
                receipt.unwrap()
            },
            _ => {
                return Err(RelayError::ProposalError("No L1 client or L1 RPC URL provided".to_string()));
            }
        };
        println!(
            "Transaction included in block {}",
            receipt.block_number.expect("Failed to get block number")
        );
        Ok(())
    }

    // The logic to create the transaction (call)data for proposing the block
    fn create_propose_block_tx_data(
        &self,
        execution_payload: &ExecutionPayload,
    ) -> Result<(BlockMetadata, usize)> {
        let execution_payload = match execution_payload {
            ExecutionPayload::V2(payload) => &payload.payload_inner,
            ExecutionPayload::V3(payload) => &payload.payload_inner.payload_inner,
            _ => {
                println!("[rb] Unsupported ExecutionPayload version");
                return Err(eyre::eyre!("Unsupported ExecutionPayload version"));
            }
        };

        let mut transactions = Vec::new();
        for tx_data in execution_payload.transactions.iter() {
            transactions.push(TransactionSigned::decode(&mut tx_data.to_vec().as_slice()).unwrap());
        }

        let mut tx_list = Vec::new();
        transactions.encode(&mut tx_list);
        let tx_list_hash = B256::from(alloy_primitives::keccak256(&tx_list));

        println!("[rb] proposing for block: {}", execution_payload.block_number);
        println!(
            "number of transactions: {}",
            execution_payload.transactions.len()
        );

        let meta = BlockMetadata {
            blockHash: execution_payload.block_hash,
            parentBlockHash: execution_payload.parent_hash,
            parentMetaHash: B256::ZERO, // Either we get rid of this or have a getter ?
            l1Hash: B256::ZERO, // Preconfer/builder has to set this. It needs to represent the l1StateBlockNumber's hash
            difficulty: U256::ZERO, // ??
            blobHash: tx_list_hash,
            extraData: /*execution_payload.extra_data.try_into().unwrap()*/ B256::default(),
            coinbase: execution_payload.fee_recipient,
            l2BlockNumber: execution_payload.block_number,
            gasLimit: execution_payload.gas_limit.try_into().map_err(|_| eyre::eyre!("Gas limit overflow"))?,
            l1StateBlockNumber: 0, // Preconfer/builder has to set this.
            timestamp: execution_payload.timestamp,
            txListByteOffset: 0u32.try_into().map_err(|_| eyre::eyre!("txListByteOffset conversion error"))?,
            txListByteSize: (tx_list.len() as u32).try_into().map_err(|_| eyre::eyre!("txListByteSize conversion error"))?,
            blobUsed: false,
            txList: tx_list.into(),
        };

        // println!("[rb] meta: {:?}", meta);

        Ok((meta, execution_payload.transactions.len()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProposeBlockError {
    #[error("Failed to propose block: {0}")]
    ProposalFailed(String),
    // Add other error variants as needed
}

fn decode_transactions(tx_list: &[u8]) -> Vec<TransactionSigned> {
    #[allow(clippy::useless_asref)]
    Vec::<TransactionSigned>::decode(&mut tx_list.as_ref()).unwrap_or_else(|e| {
        // If decoding fails we need to make an empty block
        println!("[rb] decode_transactions not successful: {e:?}, use empty tx_list");
        vec![]
    })
}

#[test]
fn test_decode_transactions() {
    let b = B256::default();
    println!("[rb] b: {:?}", b);
}