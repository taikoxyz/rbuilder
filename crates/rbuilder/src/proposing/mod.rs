use alloy_eips::BlockId;
use alloy_network::{EthereumWallet, NetworkWallet, TransactionBuilder};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rlp::{Decodable, Encodable};
use alloy_signer_local::PrivateKeySigner;
//use alloy_sol_types::{sol, SolCall};
use eyre::Result;
//use revm_primitives::{Address, B256, U256};
use alloy_primitives::{B256, U256, I256, Address};
use reth_primitives::{SealedBlock, TransactionSigned};
use reth_provider::{execution_outcome_to_state_diff, ExecutionOutcome};
use revm::precompile::xcalloptions;
use revm_primitives::{address, AccessList, Bytes, StateDiff};
use sha2::digest::typenum::UInt;
//use revm_primitives::address;
use url::Url;
//use crate::mev_boost::{SubmitBlockRequest};
//use alloy_rpc_types_engine::{ExecutionPayload};
use alloy_rpc_types_engine::ExecutionPayload;
use alloy_sol_types::{sol, SolCall, SolType};
use alloy_network::eip2718::Encodable2718;
use std::{collections::HashMap, hash::{DefaultHasher, Hash, Hasher}, str::FromStr};
use reth_primitives::{GwynethDA, ChainDA};
use alloy_sol_types::SolValue;
use alloy_primitives::keccak256;
use alloy_signer::{Signature, Signer, SignerSync};
use alloy_rpc_types::{TransactionInput, TransactionRequest};

use crate::{building::SealedBlockWrapper, mev_boost::SubmitBlockRequest};

// Using sol macro to use solidity code here.
sol! {
    #[derive(Debug)]
    struct UltraBlock {
        bytes32 ultraHash;
        bytes32 parentUltraHash;
        bytes32 parentL1BlockHash;

        bytes32[] blobHashes;
        bytes da;

        Block[] blocks;
    }

    #[derive(Debug)]
    struct Block {
        L1Block l1Block;

        bytes32 extraData;
        address coinbase;

        uint24 daByteOffset;
        uint24 daByteSize;
    }

    #[derive(Debug)]
    struct L1Block {
        Transaction[] transactions;
    }

    #[derive(Debug)]
    struct Transaction {
        address addr;
        bytes data;
        uint256 value;
        uint64 gas;
        bool reverts;
    }

    #[derive(Debug)]
    struct StateDiffAccount {
        StateDiffStorageSlot[] storageSlots;
        uint balanceChange;
    }

    #[derive(Debug)]
    struct StateDiffStorageSlot {
        bytes32 key;
        bytes32 value;
    }

    #[derive(Debug)]
    struct Proof {
        bytes proof;
    }

    #[derive(Debug)]
    struct ReturnData {
        bytes data;
        bool isRevert;
    }

    //#[sol(rpc)]
    #[allow(dead_code)]
    contract Rollup {
        function propose(UltraBlock calldata _block, Proof calldata proof) external payable;
    }

    contract DelegateContract {
        event Executed(address indexed to, uint256 value, bytes data);

        struct SubCall {
            bytes data;
            address to;
            uint256 value;
        }

        function execute(SubCall[] memory calls) external payable;

        receive() external payable {}
    }

    contract GwynethContract {
        function applyStateDelta(StateDiffAccount calldata accountChanges) external payable;
    }
}


use once_cell::sync::Lazy;
use std::sync::Mutex;

static HISTORY: Lazy<Mutex<HashMap<u64, (u64, u64, u64)>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

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
        let execution_payload = request.execution_payload();
        let block_idx = execution_payload.block_number();
        println!("propose_block in L1 block {} (block gas used: {})", block_idx, request.bid_trace().gas_used);

        // Create the transaction data
        let (ultra_block, sidecar, num_txs, EOAs) = self.create_propose_block_tx_data(&execution_payload)?;

        // Create a signer from a random private key.
        let signer = PrivateKeySigner::from_str(&self.private_key).unwrap();
        let wallet = EthereumWallet::from(signer.clone());

        let input_hash = keccak256(ultra_block.abi_encode());
        let signature: Signature = signer.sign_hash_sync(&input_hash).expect("failed to sign input");

        let proof = Proof {
            proof: signature.as_bytes().into(),
        };

        let propose_data = Rollup::proposeCall { _block: ultra_block, proof };
        let propose_data = propose_data.abi_encode();

        //let decoded_transactions: Vec<TransactionSigned> = decode_transactions(&ultra_block.da);
        //println!("decoded_transactions: {:?}", decoded_transactions);

        let provider = ProviderBuilder::new().on_http(Url::parse(&self.rpc_url.clone()).unwrap());

        // Sign the transaction
        let chain_id = provider.get_chain_id().await?;
        let nonce = provider.get_transaction_count(signer.address()).await.unwrap();

        println!("proposing with nonce: {}", nonce);

        //let block = provider.get_block(BlockId::latest(), BlockTransactionsKind::);

        let num_txs_sent = {
            let mut history = HISTORY.lock().unwrap();
            if !history.contains_key(&nonce) {
                history.insert(nonce, (0, 0, 0));
            }
            let slot_history = history.get_mut(&nonce).unwrap();
            if block_idx < slot_history.1 || (block_idx == slot_history.1 && request.bid_trace().gas_used < slot_history.2) {
                println!("skipping request: ({} {}) (<= ({} {}))", block_idx, request.bid_trace().gas_used, slot_history.1, slot_history.2);
                return Ok(());
            }
            *slot_history = (slot_history.0 + 1, block_idx, request.bid_trace().gas_used);
            println!("New slot history: {:?}", slot_history);
            slot_history.0
        };
        println!("num_txs_sent: {}", num_txs_sent);

        let multiplier = (num_txs_sent * num_txs_sent) as u128;

        println!("multiplier: {}", multiplier);

        // All the EOA addresses we're gonna create account abstraction accounts for
        let mut access_list = AccessList::default();
        for address in EOAs.into_iter() {
            access_list.add_address(address);
        }

        // Build a transaction to send 100 wei from Alice to Bob.
        // The `from` field is automatically filled to the first signer's address (Alice).
        let tx = TransactionRequest::default()
            .with_to(Address::from_str(&self.contract_address).unwrap())
            .input(TransactionInput {input: Some(propose_data.into()), data: None })
            .with_nonce(nonce)
            .with_chain_id(chain_id)
            .with_value(U256::from(0))
            .with_gas_limit(15_000_000)
            .with_max_priority_fee_per_gas(1_000_000_000 * multiplier)
            .with_max_fee_per_gas(200_000_000_000 * multiplier)
            //.with_blob_sidecar(sidecar)
            //.with_max_fee_per_blob_gas(1_000_000_000 * multiplier)
            .with_access_list(access_list);

        // Build the transaction with the provided wallet. Flashbots Protect requires the transaction to
        // be signed locally and send using `eth_sendRawTransaction`.
        let tx_envelope = tx.build(&wallet).await?;

        // Encode the transaction using EIP-2718 encoding.
        let tx_encoded = tx_envelope.encoded_2718();

        println!("tx size: {}", tx_encoded.len());

        // Send the transaction and wait for the broadcast.
        match provider.send_raw_transaction(&tx_encoded).await {
            Ok(pending_tx) => {
                println!("Pending transaction... {}", pending_tx.tx_hash());
            },
            Err(e) => {
                println!("Error while proposing tx: {}", e)
            },
        };

        // Wait for the transaction to be included and get the receipt.
        // let receipt = pending_tx.get_receipt().await?;
        // println!(
        //     "Transaction included in block {}",
        //     receipt.block_number.expect("Failed to get block number")
        // );

        Ok(())
    }

    // The logic to create the transaction (call)data for proposing the block
    fn create_propose_block_tx_data(&self, execution_payload: &ExecutionPayload) -> Result<(UltraBlock, BlobTransactionSidecar, usize, Vec<Address>)> {
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

        println!("Proposed payload: {:?}", execution_payload.block_hash);
        let l1_chain_id = 160010;
        let extension_oracle = address!("1ADB9959EB142bE128E6dfEcc8D571f07cd66DeE");
        let l1_tx_overhead_gas = 25_000u64;
        //let all_gas = 30_000_000u64;
        let max_gas_delta = 2_000_000u64;
        let max_gas_send_eth = 100_000u64;
        let max_gas_extension_oracle = 1_000_000u64;

        let mut transactions = Vec::new();
        for tx_data in execution_payload.transactions.iter() {
            transactions.push(TransactionSigned::decode(&mut tx_data.to_vec().as_slice()).unwrap());
        }

        println!("num transactions: {}", transactions.len());
        for tx in transactions.iter() {
            println!("Included tx: {:?}", tx.hash());
        }

        let mut tx_list = Vec::new();
        transactions.encode(&mut tx_list);
        let tx_list_hash = B256::from(alloy_primitives::keccak256(&tx_list));

        let mut EOAs = Vec::new();

        //println!("proposing for block: {}", execution_payload.block_number);
        //println!("number of transactions: {}", execution_payload.transactions.len());
        //println!("transactions: {:?}", execution_payload.transactions);
        //println!("tx list: {:?}", tx_list);

        //println!("Block extra data: {:?}", execution_payload.extra_data);
        let (da, l1_block, ultra_hash) = if execution_payload.extra_data.len() > 32 {
            //println!("Decoding extra data...");
            let (_, l1_state_diff, blocks, block_hashes): (ExecutionOutcome, StateDiff, HashMap<u64, SealedBlock>, HashMap::<u64, (B256, B256)>) = bincode::deserialize(&execution_payload.extra_data.to_vec()).unwrap();

            println!("l1 state diff: {:?}", l1_state_diff);

            let mut chain_das = HashMap::default();
            for (&chain_id, block) in blocks.iter() {
                if chain_id == l1_chain_id {
                    continue;
                }
                //let execution_outcome = execution_outcome.filter_chain(chain_id);

                //let json_str = String::from_utf8(block.extra_data.to_vec()).unwrap();
                //let state_diff = serde_json::from_str(&json_str).unwrap_or(None);

                // L2 State Diff
                let state_diff = bincode::deserialize(&block.extra_data.to_vec()).unwrap();

                // Filter out accounts
                // let mut state_diff = execution_outcome_to_state_diff(&execution_outcome, block.state_root);
                // state_diff.accounts = state_diff.clone().accounts.into_iter().filter(|account| account.address != alloy_eips::eip4788::BEACON_ROOTS_ADDRESS && account.address != alloy_eips::eip2935::HISTORY_STORAGE_ADDRESS).collect::<Vec<_>>();
                // if chain_id == l1_chain_id {
                //     state_diff.accounts = state_diff.clone().accounts.into_iter().filter(|account| account.address != execution_payload.fee_recipient).collect::<Vec<_>>();
                // }
                // state_diff.state_root = block.state_root;

                chain_das.insert(chain_id, ChainDA {
                    block_hash: block.hash(),
                    state_diff: Some(state_diff),
                    extra_data: block.extra_data.clone(),
                    transactions: None,
                });
            }

            let mut l1_block = L1Block { transactions: Vec::new() };
            let mut l1_call_idx = 0usize;
            for entry in l1_state_diff.entries.iter() {
                match entry {
                    revm_primitives::StateDiffEntry::Diff { accounts } => {
                        for (address, account) in accounts.iter() {
                            let mut onchain_slots = Vec::new();
                            for slot in account.storage.iter() {
                                onchain_slots.push(StateDiffStorageSlot {
                                    key: slot.0.clone().into(),
                                    value: slot.1.clone().into(),
                                });
                            }

                            // let (value_to_send, value_to_receive)  = if account.balance_delta > I256::ZERO {
                            //     (account.balance_delta.unsigned_abs(), U256::ZERO)
                            // } else {
                            //     (U256::ZERO, account.balance_delta.unsigned_abs())
                            // };
                            // let value_to_send = U256::ZERO;
                            // let value_to_receive = U256::ZERO;
                            let (value_to_send, value_to_receive)  = if account.balance_negative {
                                (U256::ZERO, account.balance_delta)
                            } else {
                                (account.balance_delta, U256::ZERO)
                            };

                            // If we just have to send ETH, then don't even call the applyStateDelta function
                            if onchain_slots.len() == 0 && value_to_receive == U256::ZERO && value_to_send > U256::ZERO {
                                l1_block.transactions.push(Transaction {
                                    addr: address.1,
                                    data: Bytes::new(),
                                    value: value_to_send,
                                    gas: max_gas_send_eth,
                                    reverts: true,
                                });
                            } else if onchain_slots.len() > 0 || value_to_receive != U256::ZERO || value_to_send != U256::ZERO {
                                let apply_state_delta_call = GwynethContract::applyStateDeltaCall {
                                    accountChanges: StateDiffAccount {
                                        storageSlots: onchain_slots,
                                        balanceChange: value_to_receive,
                                    },
                                };

                                l1_block.transactions.push(Transaction {
                                    addr: address.1,
                                    data: Bytes::from(apply_state_delta_call.abi_encode()),
                                    value: value_to_send,
                                    gas: max_gas_delta,
                                    reverts: true,
                                });
                            }
                        }
                    }
                    revm_primitives::StateDiffEntry::XCall { call } => {
                        let mut onchain_outputs = Vec::new();
                        for (call_idx, call) in l1_state_diff.outputs.iter() {
                            if *call_idx == l1_call_idx {
                                onchain_outputs.push(ReturnData {
                                    data: call.output.output.clone().into(),
                                    isRevert: call.output.revert,
                                })
                            }
                        }
                        if onchain_outputs.len() > 0 {
                            l1_block.transactions.push(Transaction {
                                addr: extension_oracle,
                                data: Bytes::from(onchain_outputs.abi_encode()),
                                value: U256::ZERO,
                                gas: max_gas_extension_oracle,
                                reverts: true,
                            });
                        }


                        let delegate_call = DelegateContract::SubCall {
                            data: call.input.input.clone(),
                            to: call.input.target_address.1,
                            value: call.input.value,
                        };

                        let execute_call = DelegateContract::executeCall {
                            calls: vec![delegate_call],
                        };

                        l1_block.transactions.push(Transaction {
                            addr: call.input.caller.1,
                            data: Bytes::from(execute_call.abi_encode()),
                            value: U256::ZERO,
                            gas: l1_tx_overhead_gas + call.input.gas_limit,
                            reverts: true,
                        });

                        l1_call_idx += 1;

                        EOAs.push(call.input.caller.1);
                    }
                }
            }

            // Calculate ULTRA hashes

            let mut block_hashes = block_hashes.iter().map(|(key, value)| (key, value)).collect::<Vec<_>>();
            block_hashes.sort_by_key(|(chain_id, _)| **chain_id);

            let mut previous_ultra_hashes = Vec::<u8>::new();
            let mut current_ultra_hashes = Vec::<u8>::new();

            for (_, (previous_hash, current_hash)) in block_hashes.iter() {
                previous_ultra_hashes.append(&mut previous_hash.0.to_vec());
                current_ultra_hashes.append(&mut current_hash.0.to_vec());
            }

            let parent_ultra_hash = alloy_primitives::keccak256(&previous_ultra_hashes);
            let current_ultra_hash = alloy_primitives::keccak256(&current_ultra_hashes);

            (
                GwynethDA {
                    chain_das,
                    transactions: None,
                    extra_data: Bytes::new(),
                },
                l1_block,
                (parent_ultra_hash, current_ultra_hash)
            )
        } else {
            (GwynethDA::default(), L1Block { transactions: Vec::new() }, (B256::default(), B256::default()))
        };

        println!("L1 block: {:?}", l1_block);
        println!("ultra_hash: {:?}", ultra_hash);

        //println!("da: {:?}", da);

        //let state_diffs = Bytes::from(bincode::serialize(&da).unwrap());

        let txs_and_diffs = Bytes::from(bincode::serialize(&(da, tx_list)).unwrap());

        println!("txs_and_diffs size: {}", txs_and_diffs.len());

        //println!("l1 state diff: {:?}", l1_state_diff);

        // Create a sidecar with some data.
        let sidecar: SidecarBuilder<SimpleCoder> = SidecarBuilder::from_slice(&txs_and_diffs);
        let sidecar = sidecar.build()?;

        //println!("sidecar: {:?}", sidecar);

        //let sidecar = sidecar.unwrap();

        let blob_hashes = sidecar.versioned_hashes().collect::<Vec<_>>();
        //let blob_hashes = vec![tx_list_hash];

        //println!("blob_hashes: {:?}", blob_hashes);

        //let blobs: Vec<_> = sidecar.blobs.clone().into_iter().zip(sidecar.commitments.clone()).collect();
        //let blobs = sidecar.blobs.into_iter().map(|(blob, _)| Blob::from(*blob)).collect::<Vec<_>>();

        // let blobs = blobs
        //     .into_iter()
        //     // Convert blob KZG commitments to versioned hashes
        //     .map(|(blob, commitment)| (blob, kzg_to_versioned_hash(commitment.as_slice())))
        //     // Filter only blobs that are present in the block data
        //     .filter(|(_, hash)| blob_hashes.contains(hash))
        //     .map(|(blob, _)| Blob::from(*blob))
        //     .collect::<Vec<_>>();
        // if blobs.len() != blob_hashes.len() {
        //     eyre::bail!("some blobs not found")
        // }

        let data = SimpleCoder::default()
            .decode_all(&sidecar.blobs)
            .ok_or(eyre::eyre!("failed to decode blobs"))?
            .concat();

        assert_eq!(data, txs_and_diffs.to_vec(), "blob data does not match calldata");

        let block = Block {
            extraData: /*execution_payload.extra_data.try_into().unwrap()*/ B256::default(),
            coinbase: execution_payload.fee_recipient,
            daByteOffset: 0u32.try_into().map_err(|_| eyre::eyre!("txListByteOffset conversion error"))?,
            daByteSize: (txs_and_diffs.len() as u32).try_into().map_err(|_| eyre::eyre!("txListByteSize conversion error"))?,
            l1Block: l1_block,
        };

        let ultra_block = UltraBlock {
            ultraHash: ultra_hash.1,
            parentUltraHash: ultra_hash.0,
            parentL1BlockHash: execution_payload.parent_hash,
            blobHashes: blob_hashes,
            da: txs_and_diffs,
            blocks: vec![block],
        };

        Ok((ultra_block, sidecar, execution_payload.transactions.len(), EOAs))
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


#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use reth_primitives::{BlockBody, Receipt};
    // use ahash::HashMap;

    use super::*;

    #[test]
    fn test_create_propose_block_tx_data() { 
        let execution_outcome: ExecutionOutcome<Receipt> = ExecutionOutcome::default();
        // let mut blocks: HashMap<u64, SealedBlock<_, _>> = HashMap::default();
        let block: SealedBlock<Header, BlockBody> = SealedBlock::default();

        let _execution_outcome = Bytes::from(bincode::serialize(&execution_outcome).unwrap());
        bincode::deserialize::<ExecutionOutcome<Receipt>>(&_execution_outcome.to_vec()).unwrap();
        

        // blocks.insert(160010u64, block);
        // let _blocks = Bytes::from(bincode::serialize(&blocks).unwrap());
        // bincode::deserialize::<HashMap<u64, SealedBlock<Header, BlockBody>>>(&_blocks.to_vec()).unwrap();

        let mut simple_hashmap: HashMap<u64, &str> = HashMap::default();
        simple_hashmap.insert(160010u64, "Fuck");
        let _simple_hashmap = Bytes::from(bincode::serialize(&simple_hashmap).unwrap());
        bincode::deserialize::<HashMap<u64, String>>(&_simple_hashmap.to_vec()).unwrap();

        // let _block = Bytes::from(bincode::serialize(&block).unwrap());
        // bincode::deserialize::<SealedBlock<Header, BlockBody>>(&_block.to_vec()).unwrap();

        let header: Header = Header::default();
        let header_bytes = bincode::serialize(&header).unwrap();
        let _header = Bytes::from(header_bytes.clone());
        bincode::deserialize::<Header>(&header_bytes).unwrap();

        // let block_body: BlockBody = BlockBody::default();
        // let _block_body = Bytes::from(bincode::serialize(&block_body).unwrap());
        // bincode::deserialize::<BlockBody>(&_block_body.to_vec()).unwrap();

        // let extra_data = Bytes::from(bincode::serialize(&(execution_outcome, blocks)).unwrap());
        // let (execution_outcome_, blocks_): (ExecutionOutcome<Receipt>, HashMap<u64, SealedBlock<Header, BlockBody>>) = bincode::deserialize(&extra_data.to_vec()).unwrap();
        // println!("extra_data: {}", extra_data);
        // println!("execution_outcome: {:?}", execution_outcome_);
        // println!("blocks: {:?}", blocks_);
    }
}