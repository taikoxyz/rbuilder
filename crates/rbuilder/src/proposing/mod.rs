
use alloy_network::{EthereumWallet, NetworkWallet, TransactionBuilder};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use eyre::Result;
use alloy_primitives::{B256, U256, Address};
use revm_primitives::address;
use url::Url;
use crate::mev_boost::{SubmitBlockRequest};
use alloy_rpc_types_engine::{ExecutionPayload};
use alloy_sol_types::{sol, SolCall, SolType};
use alloy_network::eip2718::Encodable2718;
use ethers::{
    prelude::*,
    types::{Address as EthersAddress}
};  
use ethers::signers::LocalWallet;
use ethers::providers::{Http as EthersHttp, Provider as EthersProvider};
use web3::ethabi;

use ethers::prelude::*;
use std::{convert::TryFrom, str::FromStr};

use alloy_rpc_types::{TransactionInput, TransactionRequest};

// Using sol macro to use solidity code here.
sol! {
    #[derive(Debug)]
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

    //#[sol(rpc)]
    #[allow(dead_code)]
    contract Rollup {
        function proposeBlock(BlockMetadata[] calldata data, bytes[] calldata txLists) external payable;
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
        println!("Dani debug: Trying to propose blocks");

        let execution_payload = request.execution_payload();
        
        // Create the transaction data
        let (meta, tx_list) = self.create_propose_block_tx_data(&execution_payload)?;
        
        println!("meta: {:?}", meta);
        println!("tx_list: {:?}", tx_list);

        // Encode the metadata - so that we be decoding on contract
        let meta_encoded = <BlockMetadata as SolType>::abi_encode(&meta);

        // Put togehter the "abi" for proposeBlock
        let function = ethabi::Function {
            name: "proposeBlock".to_string(),
            inputs: vec![
                ethabi::Param {
                    name: "data".to_string(),
                    kind: ethabi::ParamType::Array(Box::new(ethabi::ParamType::Bytes)),
                    internal_type: None,
                },
                ethabi::Param {
                    name: "txLists".to_string(),
                    kind: ethabi::ParamType::Array(Box::new(ethabi::ParamType::Bytes)),
                    internal_type: None,
                },
            ],
            outputs: vec![],
            constant: Some(false),
            state_mutability: ethabi::StateMutability::Payable,
        };

        // Encode input into the data
        // let data = function.encode_input(&[
        //     ethers::abi::Token::Array(vec![ethers::abi::Token::Bytes(meta_encoded)]),
        //     ethers::abi::Token::Array(vec![ethers::abi::Token::Bytes(tx_list)]),
        // ])?;

        // let tx_object = TransactionRequest {
        //     to: Some(self.contract_address.parse()?),
        //     data: Some(Bytes::from_iter(data.iter())),
        //     ..Default::default()
        // };

        println!("start provider from: {:?}", self.rpc_url);
        //let provider = EthersProvider::<EthersHttp>::try_from(self.rpc_url.clone())?;
        //println!("provider created");
        //let chain_id = provider.get_chainid().await?.as_u64();
        //println!("chain id from provider: {:?}", chain_id);
        //let wallet: LocalWallet = self.private_key.parse::<LocalWallet>()?
        //    .with_chain_id(chain_id);

        //println!("setting up client for tx");
        //let client = SignerMiddleware::new(provider, wallet);

        println!("Dani debug - Sending transaction");

        //let pending_tx = client.send_transaction(tx_object, None).await?;

         // Your private key (ensure this is kept secure and never hard-coded in production)
        //let private_key = "your-private-key-here";
        //let wallet = private_key.parse::<LocalWallet>()?;

        // Connect the wallet to the provider
        //let wallet = wallet.with_provider(provider.clone());

        // The recipient's address
        //let to = "0xRecipientAddress".parse::<Address>()?;

        // The amount to send (in wei)
        //let value = ethers::utils::parse_ether(1.0)?; // Sending 1 Ether

        // Prepare the transaction request
        //let tx = TransactionRequest::new().to(self.contract_address.parse()?);

        let provider = ProviderBuilder::new().on_http(Url::parse(&self.rpc_url.clone()).unwrap());
        println!("provider created");

        // Create a signer from a random private key.
        let signer = PrivateKeySigner::from_str(&self.private_key).unwrap();
        let wallet = EthereumWallet::from(signer.clone());

        // Sign the transaction
        let chain_id = provider.get_chain_id().await?;
        let nonce = provider.get_transaction_count(signer.address()).await.unwrap();
        println!("chain id from provider: {:?}", chain_id);
        println!("nonce from provider: {:?}", nonce);
        
        //let rollup = Rollup::(Address::from_str(&self.contract_address).unwrap(), provider);
        let propose_data = Rollup::proposeBlockCall { data: vec![meta], txLists: vec![tx_list.into()] };
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
        

        //let data = propose_data.abi_encode();


        //let res = provider.send_raw_transaction(&data).await;

        // if res.is_ok() {
        //     println!("SP1 proof verified successfully using!");
        // } else {
        //     println!("SP1 proof verification failed!");
        // }

        //let signed_tx = wallet.sign_transaction(&tx).await?;

        // Serialize the signed transaction into raw bytes
        //let raw_tx_bytes = signed_tx.encode();

        //let pending_tx = provider.send_raw_transaction(raw_tx_bytes).await?;

        //println!("Dani debug - Transaction sent. Hash: {:?}", pending_tx.tx_hash());
        Ok(())
    }

    // The logic to create the transaction (call)data for proposing the block
    fn create_propose_block_tx_data(&self, execution_payload: &ExecutionPayload) -> Result<(BlockMetadata, Vec<u8>)> {
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

        println!("proposing: {}", execution_payload.block_number);

        // Create tx_list from transactions -> Are they RLP encoded alredy ? I guess not so doing now.
        let tx_list = self.rlp_encode_transactions(&execution_payload.transactions);
        let tx_list_hash = B256::from(alloy_primitives::keccak256(&tx_list));

        println!("tx list created: {:?}", tx_list);

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
        };

        Ok((meta, tx_list))
    }

    // This one handles '&[ethers::types::Bytes]' and '&Vec<alloy_primitives::Bytes>' types
    fn rlp_encode_transactions<B>(&self, transactions: &[B]) -> Vec<u8>
    where
        B: AsRef<[u8]>,
    {
        let mut rlp_stream = rlp::RlpStream::new_list(transactions.len());

        for tx in transactions {
            rlp_stream.append(&tx.as_ref());
        }

        rlp_stream.out().to_vec()
    }
    
}

#[derive(Debug, thiserror::Error)]
pub enum ProposeBlockError {
    #[error("Failed to propose block: {0}")]
    ProposalFailed(String),
    // Add other error variants as needed
}