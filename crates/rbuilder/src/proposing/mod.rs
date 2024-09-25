
use eyre::Result;
use alloy_primitives::{B256, U256, Address};
use crate::mev_boost::{SubmitBlockRequest};
use alloy_rpc_types_engine::{ExecutionPayload};
use alloy_sol_types::{sol, SolType};
use ethers::{
    prelude::*,
    types::{Address as EthersAddress}
};
use ethers::signers::LocalWallet;
use ethers::providers::{Http as EthersHttp, Provider as EthersProvider};
use web3::ethabi;

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

    function proposeBlock(BlockMetadata[] calldata data, bytes[] calldata txLists) external payable;
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

        let provider = EthersProvider::<EthersHttp>::try_from(self.rpc_url.clone())?;
        let chain_id = provider.get_chainid().await?.as_u64();
        let wallet: LocalWallet = self.private_key.parse::<LocalWallet>()?
            .with_chain_id(chain_id);

        let execution_payload = request.execution_payload();
        
        // Create the transaction data
        let (meta, tx_list) = self.create_propose_block_tx_data(&execution_payload, wallet.address())?;
        
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
        let data = function.encode_input(&[
            ethers::abi::Token::Array(vec![ethers::abi::Token::Bytes(meta_encoded)]),
            ethers::abi::Token::Array(vec![ethers::abi::Token::Bytes(tx_list)]),
        ])?;

        let tx_object = TransactionRequest {
            to: Some(self.contract_address.parse()?),
            data: Some(Bytes::from_iter(data.iter())),
            ..Default::default()
        };


        let client = SignerMiddleware::new(provider, wallet);

        println!("Dani debug - Sending transaction");

        let pending_tx = client.send_transaction(tx_object, None).await?;

        println!("Dani debug - Transaction sent. Hash: {:?}", pending_tx.tx_hash());
        Ok(())
    }

    // The logic to create the transaction (call)data for proposing the block
    fn create_propose_block_tx_data(&self, execution_payload: &ExecutionPayload, wallet_address: EthersAddress) -> Result<(BlockMetadata, Vec<u8>)> {
        let (block_number, parent_hash, _, _, gas_limit, _, timestamp, extra_data, base_fee_per_gas, transactions, block_hash) = match execution_payload {
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
                    inner.block_hash,
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
                    inner.block_hash,
                )
            },
            _ => return Err(eyre::eyre!("Unsupported ExecutionPayload version")),
        };

        // Create tx_list from transactions -> Are they RLP encoded alredy ? I guess not so doing now.
        let tx_list = self.rlp_encode_transactions(&transactions);
        let tx_list_hash = B256::from(alloy_primitives::keccak256(&tx_list));

        let meta = BlockMetadata {
            blockHash: block_hash,
            parentBlockHash: parent_hash,
            parentMetaHash: B256::ZERO, // Either we get rid of this or have a getter ?
            l1Hash: B256::ZERO, // Preconfer/builder has to set this. It needs to represent the l1StateBlockNumber's hash
            difficulty: U256::ZERO, // ??
            blobHash: tx_list_hash,
            extraData: B256::from_slice(&extra_data),
            coinbase: Address::from_slice(wallet_address.as_bytes()),  // Convert EthersAddress to alloy Address,
            l2BlockNumber: block_number,
            gasLimit: gas_limit.try_into().map_err(|_| eyre::eyre!("Gas limit overflow"))?,
            l1StateBlockNumber: 0, // Preconfer/builder has to set this.
            timestamp: timestamp,
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