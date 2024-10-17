
use alloy_network::{EthereumWallet, NetworkWallet, TransactionBuilder};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rlp::{Decodable, Encodable};
use alloy_signer_local::PrivateKeySigner;
//use alloy_sol_types::{sol, SolCall};
use eyre::Result;
//use revm_primitives::{Address, B256, U256};
use alloy_primitives::{B256, U256, Address};
use reth_primitives::TransactionSigned;
//use revm_primitives::address;
use url::Url;
//use crate::mev_boost::{SubmitBlockRequest};
//use alloy_rpc_types_engine::{ExecutionPayload};
use alloy_rpc_types_engine::ExecutionPayload;
use alloy_sol_types::{sol, SolCall, SolType};
use alloy_network::eip2718::Encodable2718;
use std::str::FromStr;

use alloy_rpc_types::{TransactionInput, TransactionRequest};

use crate::mev_boost::SubmitBlockRequest;

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
    rpc_url: String,
    contract_address: String,
    private_key: String,
}

impl BlockProposer {
    pub fn new(rpc_url: String, contract_address: String, private_key: String) -> Result<Self> {
        Ok(BlockProposer {
            rpc_url,
            contract_address,
            private_key,
        })
    }

    pub async fn propose_block(&self, request: &SubmitBlockRequest) -> Result<()> {
        println!("propose_block");

        let execution_payload = request.execution_payload();

        // Create the transaction data
        let (meta, num_txs) = self.create_propose_block_tx_data(&execution_payload)?;

        // if num_txs == 1 {
        //     println!("skip propose");
        //     // If there's only the payout tx, don't propose
        //     return Ok(());
        // }

        let decoded_transactions: Vec<TransactionSigned> = decode_transactions(&meta.txList);
        println!("decoded_transactions: {:?}", decoded_transactions);

        let provider = ProviderBuilder::new().on_http(Url::parse(&self.rpc_url.clone()).unwrap());

        // Create a signer from a random private key.
        let signer = PrivateKeySigner::from_str(&self.private_key).unwrap();
        let wallet = EthereumWallet::from(signer.clone());

        // Sign the transaction
        let chain_id = provider.get_chain_id().await?;
        let nonce = provider.get_transaction_count(signer.address()).await.unwrap();

        //let rollup = Rollup::(Address::from_str(&self.contract_address).unwrap(), provider);
        let propose_data = Rollup::proposeBlockCall { data: vec![meta] };
        let propose_data = propose_data.abi_encode();

        // Build a transaction to send 100 wei from Alice to Bob.
        // The `from` field is automatically filled to the first signer's address (Alice).
        let tx = TransactionRequest::default()
            .with_to(Address::from_str(&self.contract_address).unwrap())
            .input(TransactionInput {input: Some(propose_data.into()), data: None })
            .with_nonce(nonce)
            .with_chain_id(chain_id)
            .with_value(U256::from(0))
            .with_gas_limit(5_000_000)
            .with_max_priority_fee_per_gas(1_000_000_000)
            .with_max_fee_per_gas(20_000_000_000);

        // Build the transaction with the provided wallet. Flashbots Protect requires the transaction to
        // be signed locally and send using `eth_sendRawTransaction`.
        let tx_envelope = tx.build(&wallet).await?;

        // Encode the transaction using EIP-2718 encoding.
        let tx_encoded = tx_envelope.encoded_2718();

        // Send the transaction and wait for the broadcast.
        let pending_tx = provider.send_raw_transaction(&tx_encoded).await?;

        println!("Pending transaction... {}", pending_tx.tx_hash());

        // Wait for the transaction to be included and get the receipt.
        let receipt = pending_tx.get_receipt().await?;

        println!(
            "Transaction included in block {}",
            receipt.block_number.expect("Failed to get block number")
        );

        Ok(())
    }

    // The logic to create the transaction (call)data for proposing the block
    fn create_propose_block_tx_data(&self, execution_payload: &ExecutionPayload) -> Result<(BlockMetadata, usize)> {
        let execution_payload = match execution_payload {
            ExecutionPayload::V2(payload) => {
                &payload.payload_inner
            },
            ExecutionPayload::V3(payload) => {
                &payload.payload_inner.payload_inner
            },
            _ => {
                println!("Unsupported ExecutionPayload version");
                return Err(eyre::eyre!("Unsupported ExecutionPayload version"))
            }
        };

        let mut transactions = Vec::new();
        for tx_data in execution_payload.transactions.iter() {
            transactions.push(TransactionSigned::decode(&mut tx_data.to_vec().as_slice()).unwrap());
        }

        let mut tx_list = Vec::new();
        transactions.encode(&mut tx_list);
        let tx_list_hash = B256::from(alloy_primitives::keccak256(&tx_list));

        println!("proposing for block: {}", execution_payload.block_number);
        println!("number of transactions: {}", execution_payload.transactions.len());
        println!("transactions: {:?}", execution_payload.transactions);
        println!("tx list: {:?}", tx_list);

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

        println!("meta: {:?}", meta);

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
        println!("decode_transactions not successful: {e:?}, use empty tx_list");
        vec![]
    })
}
