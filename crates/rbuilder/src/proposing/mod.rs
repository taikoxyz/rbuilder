
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

use alloy_rpc_types::{TransactionInput, TransactionRequest};

use crate::mev_boost::SubmitBlockRequest;

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
        bytes txList;
        bytes stateDiffs;
        L1Block l1Block;
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
    struct ReturnData {
        bytes data;
        bool isRevert;
    }

    //#[sol(rpc)]
    #[allow(dead_code)]
    contract Rollup {
        function proposeBlock(BlockMetadata[] calldata data) external payable;
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
        let (meta, num_txs, EOAs) = self.create_propose_block_tx_data(&execution_payload)?;

        let propose_data = Rollup::proposeBlockCall { data: vec![meta.clone()] };
        let propose_data = propose_data.abi_encode();

        let decoded_transactions: Vec<TransactionSigned> = decode_transactions(&meta.txList);
        //println!("decoded_transactions: {:?}", decoded_transactions);

        let provider = ProviderBuilder::new().on_http(Url::parse(&self.rpc_url.clone()).unwrap());

        // Create a signer from a random private key.
        let signer = PrivateKeySigner::from_str(&self.private_key).unwrap();
        let wallet = EthereumWallet::from(signer.clone());

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
    fn create_propose_block_tx_data(&self, execution_payload: &ExecutionPayload) -> Result<(BlockMetadata, usize, Vec<Address>)> {
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

        //println!("Proposed payload: {:?}", execution_payload);
        let l1_chain_id = 160010;
        let extension_oracle = address!("1ADB9959EB142bE128E6dfEcc8D571f07cd66DeE");

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
        let (da, l1_block) = if execution_payload.extra_data.len() > 32 {
            //println!("Decoding extra data...");
            let (_, l1_state_diff, blocks): (ExecutionOutcome, StateDiff, HashMap<u64, SealedBlock>) = bincode::deserialize(&execution_payload.extra_data.to_vec()).unwrap();

            println!("l1 state diff: {:?}", l1_state_diff);

            let mut chain_das = HashMap::default();
            for (&chain_id, block) in blocks.iter() {
                if chain_id == l1_chain_id {
                    continue;
                }
                //let execution_outcome = execution_outcome.filter_chain(chain_id);

                //let json_str = String::from_utf8(block.extra_data.to_vec()).unwrap();
                //let state_diff = serde_json::from_str(&json_str).unwrap_or(None);

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
            let mut onchain_outputs = Vec::new();
            for call in l1_state_diff.outputs.iter() {
                onchain_outputs.push(ReturnData {
                    data: call.output.output.clone().into(),
                    isRevert: call.output.revert,
                })
            }
            if onchain_outputs.len() > 0 {
                l1_block.transactions.push(Transaction {
                    addr: extension_oracle,
                    data: Bytes::from(onchain_outputs.abi_encode()),
                    value: U256::ZERO,

                });
            }
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
                                });
                            }
                        }
                    }
                    revm_primitives::StateDiffEntry::XCall { call } => {
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
                        });

                        EOAs.push(call.input.caller.1);
                    }
                }
            }

            (
                GwynethDA {
                    chain_das,
                    transactions: None,
                    extra_data: Bytes::new(),
                },
                l1_block,
            )
        } else {
            (GwynethDA::default(), L1Block { transactions: Vec::new() })
        };

        println!("L1 block: {:?}", l1_block);

        //println!("da: {:?}", da);

        let serialized_bytes = bincode::serialize(&da).unwrap();
        //println!("state_diffs: {:?}", serialized_bytes);
        let state_diffs = Bytes::from(serialized_bytes);

        //println!("l1 state diff: {:?}", l1_state_diff);

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
            stateDiffs: state_diffs,
            l1Block: l1_block,
        };

        //println!("meta: {:?}", meta);

        Ok((meta, execution_payload.transactions.len(), EOAs))
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
