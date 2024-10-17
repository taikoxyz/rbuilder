use std::{
    cmp::max, sync::Arc, time::{Duration, Instant}
};

use ahash::HashMap;
use alloy_primitives::U256;
use reth::tasks::pool::BlockingTaskPool;
use reth_db::database::Database;
use reth_payload_builder::database::SyncCachedReads as CachedReads;
use reth_primitives::format_ether;
use reth_provider::{BlockNumReader, ProviderFactory, StateProvider};
use revm_primitives::ChainAddress;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace};
use reth::primitives::{Header, Block as RethBlock};

use crate::{
    building::{
        estimate_payout_gas_limit, tracers::GasUsedSimulationTracer, BlockBuildingContext,
        BlockState, BuiltBlockTrace, BuiltBlockTraceError, CriticalCommitOrderError,
        EstimatePayoutGasErr, ExecutionError, ExecutionResult, FinalizeError, FinalizeResult,
        PartialBlock, Sorting,
    },
    primitives::SimulatedOrder,
    roothash::RootHashConfig,
    telemetry,
};

use super::Block;

/// Trait to help building blocks. It still needs to be finished (finalize_block) to set the payout tx and computing some extra stuff (eg: root hash).
/// Txs can be added before finishing it.
/// Typical usage:
/// 1 - Create it some how.
/// 2 - Call lots of commit_order.
/// 3 - Call set_trace_fill_time when you are done calling commit_order (we still have to review this step).
/// 4 - Call finalize_block.
pub trait BlockBuildingHelper: Send + Sync {
    fn box_clone(&self) -> Box<dyn BlockBuildingHelper>;

    /// Tries to add an order to the end of the block.
    /// Block state changes only on Ok(Ok)
    fn commit_order(
        &mut self,
        order: &SimulatedOrder,
    ) -> Result<Result<&ExecutionResult, ExecutionError>, CriticalCommitOrderError>;

    /// Call set the trace fill_time (we still have to review this)
    fn set_trace_fill_time(&mut self, time: Duration);
    /// If not set the trace will default to creation time.
    fn set_trace_orders_closed_at(&mut self, orders_closed_at: OffsetDateTime);

    /// Only if can_add_payout_tx you can pass Some(payout_tx_value) to finalize_block (a little ugly could be improved...)
    fn can_add_payout_tx(&self) -> bool;

    /// Accumulated coinbase delta - gas cost of final payout tx (if can_add_payout_tx).
    /// This is the maximum profit that can reach the final fee recipient (max bid!).
    /// Maximum payout_tx_value value to pass to finalize_block.
    /// The main reason to get an error is if profit is so low that we can't pay the payout tx (that would mean negative block value!).
    fn true_block_value(&self) -> Result<U256, BlockBuildingHelperError>;

    /// Eats the BlockBuildingHelper since once it's finished you should not use it anymore.
    /// payout_tx_value: If Some, added at the end of the block from coinbase to the final fee recipient.
    ///     This only works if can_add_payout_tx.
    fn finalize_block(
        self: Box<Self>,
        payout_tx_value: Option<U256>,
    ) -> Result<FinalizeBlockResult, BlockBuildingHelperError>;

    /// Useful if we want to give away this object but keep on building some other way.
    fn clone_cached_reads(&self) -> CachedReads;

    /// BuiltBlockTrace for current state.
    fn built_block_trace(&self) -> &BuiltBlockTrace;

    /// BlockBuildingContext used for building.
    fn building_context(&self) -> &BlockBuildingContext;

    /// Updates the cached reads for the block state.
    fn update_cached_reads(&mut self, cached_reads: CachedReads);
}

/// Implementation of BlockBuildingHelper based on a ProviderFactory<DB>
#[derive(Clone)]
pub struct BlockBuildingHelperFromDB<DB> {
    /// Balance of fee recipient before we stared building.
    _fee_recipient_balance_start: U256,
    /// Accumulated changes for the block (due to commit_order calls).
    block_state: BlockState,
    partial_block: PartialBlock<GasUsedSimulationTracer>,
    /// Gas reserved for the final payout txs from coinbase to fee recipient.
    /// None means we don't need this final tx since coinbase == fee recipient.
    payout_tx_gas: Option<u64>,
    /// Name of the builder that pregenerated this block.
    /// Might be ambiguous if several building parts were involved...
    builder_name: String,
    building_ctx: HashMap<u64, BlockBuildingContext>,
    built_block_trace: BuiltBlockTrace,
    /// Needed to get the initial state and the final root hash calculation.
    provider_factory: HashMap<u64, ProviderFactory<DB>>,
    root_hash_task_pool: BlockingTaskPool,
    root_hash_config: RootHashConfig,
    /// Token to cancel in case of fatal error (if we believe that it's impossible to build for this block).
    cancel_on_fatal_error: CancellationToken,
    origin_chain_id: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockBuildingHelperError {
    #[error("Error accessing block data: {0}")]
    ProviderError(#[from] reth_errors::ProviderError),
    #[error("Unable estimate payout gas: {0}")]
    UnableToEstimatePayoutGas(#[from] EstimatePayoutGasErr),
    #[error("pre_block_call failed")]
    PreBlockCallFailed,
    #[error("InsertPayoutTxErr while finishing block: {0}")]
    InsertPayoutTxErr(#[from] crate::building::InsertPayoutTxErr),
    #[error("Bundle consistency check failed: {0}")]
    BundleConsistencyCheckFailed(#[from] BuiltBlockTraceError),
    #[error("Error finalizing block: {0}")]
    FinalizeError(#[from] FinalizeError),
    #[error("Payout tx not allowed for block")]
    PayoutTxNotAllowed,
}

impl BlockBuildingHelperError {
    /// Non critial error can happen during normal operations of the builder
    pub fn is_critical(&self) -> bool {
        match self {
            BlockBuildingHelperError::FinalizeError(finalize) => {
                !finalize.is_consistent_db_view_err()
            }
            BlockBuildingHelperError::InsertPayoutTxErr(
                crate::building::InsertPayoutTxErr::ProfitTooLow,
            ) => false,
            _ => true,
        }
    }
}

pub struct FinalizeBlockResult {
    pub block: Block,
    /// Since finalize_block eats the object we need the cached_reads in case we create a new
    pub cached_reads: CachedReads,
}

impl<DB: Database + Clone + 'static> BlockBuildingHelperFromDB<DB> {
    /// allow_tx_skip: see [`PartialBlockFork`]
    /// Performs initialization:
    /// - Query fee_recipient_balance_start.
    /// - pre_block_call.
    /// - Estimate payout tx cost.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_factory: HashMap<u64, ProviderFactory<DB>>,
        root_hash_task_pool: BlockingTaskPool,
        root_hash_config: RootHashConfig,
        building_ctx: HashMap<u64, BlockBuildingContext>,
        cached_reads: Option<CachedReads>,
        builder_name: String,
        discard_txs: bool,
        enforce_sorting: Option<Sorting>,
        cancel_on_fatal_error: CancellationToken,
    ) -> Result<Self, BlockBuildingHelperError> {
        let mut origin_chain_id = 0;

        // @Maybe an issue - we have 2 db txs here (one for hash and one for finalize)
        let mut state_providers: HashMap<u64, Arc<dyn StateProvider>> = HashMap::default();
        for (chain_id, provider_factory) in provider_factory.iter() {
            state_providers.insert(
                *chain_id,
                provider_factory.history_by_block_hash(building_ctx[chain_id].attributes.parent)?.into(),
            );
            if *chain_id > origin_chain_id {
                origin_chain_id = *chain_id;
            }
        }
        //println!("origin_chain_id: {}", origin_chain_id);

        let fee_recipient_balance_start = state_providers[&building_ctx[&origin_chain_id].chain_spec.chain.id()]
            .account_balance(building_ctx[&origin_chain_id].attributes.suggested_fee_recipient)?
            .unwrap_or_default();
        let mut partial_block = PartialBlock::new(discard_txs, enforce_sorting)
            .with_tracer(GasUsedSimulationTracer::default());
        // Brecht: create local state for block building on top of latest blockchain state
        let mut block_state =
            BlockState::new_arc(state_providers).with_cached_reads(cached_reads.unwrap_or_default());
        partial_block
            .pre_block_call(&building_ctx[&origin_chain_id], &mut block_state)
            .map_err(|_| BlockBuildingHelperError::PreBlockCallFailed)?;
        // let payout_tx_gas = if building_ctx[&origin_chain_id].coinbase_is_suggested_fee_recipient() {
        //     None
        // } else {
        //     let payout_tx_gas = estimate_payout_gas_limit(
        //         building_ctx[&origin_chain_id].attributes.suggested_fee_recipient,
        //         &building_ctx[&origin_chain_id],
        //         &mut block_state,
        //         0,
        //     )?;
        //     partial_block.reserve_gas(payout_tx_gas);
        //     Some(payout_tx_gas)
        // };
        let payout_tx_gas = None;
        Ok(Self {
            _fee_recipient_balance_start: fee_recipient_balance_start,
            block_state,
            partial_block,
            payout_tx_gas,
            builder_name,
            building_ctx,
            built_block_trace: BuiltBlockTrace::new(),
            provider_factory,
            root_hash_task_pool,
            root_hash_config,
            cancel_on_fatal_error,
            origin_chain_id,
        })
    }

    /// Trace and telemetry
    fn trace_finalized_block(
        finalized_block: &FinalizeResult,
        builder_name: &String,
        building_ctx: &BlockBuildingContext,
        built_block_trace: &BuiltBlockTrace,
        sim_gas_used: u64,
    ) {
        let txs = finalized_block.sealed_block.body.len();
        let gas_used = finalized_block.sealed_block.gas_used;
        let blobs = finalized_block.txs_blob_sidecars.len();

        telemetry::add_built_block_metrics(
            built_block_trace.fill_time,
            built_block_trace.finalize_time,
            txs,
            blobs,
            gas_used,
            sim_gas_used,
            builder_name,
            building_ctx.timestamp(),
        );

        trace!(
            block = building_ctx.block_env.number.to::<u64>(),
            build_time_mus = built_block_trace.fill_time.as_micros(),
            finalize_time_mus = built_block_trace.finalize_time.as_micros(),
            profit = format_ether(built_block_trace.bid_value),
            builder_name = builder_name,
            txs,
            blobs,
            gas_used,
            sim_gas_used,
            use_suggested_fee_recipient_as_coinbase =
                building_ctx.coinbase_is_suggested_fee_recipient(),
            "Built block",
        );
    }

    /// Inserts payout tx if necessary and updates built_block_trace.
    fn finalize_block_execution(
        &mut self,
        payout_tx_value: Option<U256>,
    ) -> Result<(), BlockBuildingHelperError> {
        // let (bid_value, true_value) = if let (Some(payout_tx_gas), Some(payout_tx_value)) =
        //     (self.payout_tx_gas, payout_tx_value)
        // {
        //     //println!("insert_proposer_payout_tx");
        //     match self.partial_block.insert_proposer_payout_tx(
        //         payout_tx_gas,
        //         payout_tx_value,
        //         &self.building_ctx[&self.origin_chain_id],
        //         &mut self.block_state,
        //     ) {
        //         Ok(()) => (payout_tx_value, self.true_block_value()?),
        //         Err(err) => return Err(err.into()),
        //     }
        // } else {
        //     (
        //         self.partial_block.coinbase_profit,
        //         self.partial_block.coinbase_profit,
        //     )
        // };
        let bid_value = U256::from(self.partial_block.gas_used);
        let true_value = U256::from(self.partial_block.gas_used);

        println!("gas used: {:?}", self.partial_block.gas_used);
        // Since some extra money might arrived directly the suggested_fee_recipient (when suggested_fee_recipient != coinbase)
        // we check the fee_recipient delta and make our bid include that! This is supposed to be what the relay will check.
        let fee_recipient_balance_after = self
            .block_state
            .balance(ChainAddress(self.origin_chain_id, self.building_ctx[&self.origin_chain_id].attributes.suggested_fee_recipient))?;
        let fee_recipient_balance_diff = fee_recipient_balance_after
            .checked_sub(self._fee_recipient_balance_start)
            .unwrap_or_default();
        self.built_block_trace.bid_value = max(bid_value, fee_recipient_balance_diff);
        self.built_block_trace.true_bid_value = true_value;

        self.built_block_trace.bid_value = U256::from(self.partial_block.gas_used);
        self.built_block_trace.true_bid_value = self.built_block_trace.bid_value;

        Ok(())
    }
}

impl<DB: Database + Clone + 'static> BlockBuildingHelper for BlockBuildingHelperFromDB<DB> {
    /// Forwards to partial_block and updates trace.
    fn commit_order(
        &mut self,
        order: &SimulatedOrder,
    ) -> Result<Result<&ExecutionResult, ExecutionError>, CriticalCommitOrderError> {
        let result =
            self.partial_block
                .commit_order(order, &self.building_ctx[&self.origin_chain_id], &mut self.block_state);
        println!("commit order: {:?}", order);
        match result {
            Ok(ok_result) => match ok_result {
                Ok(res) => {
                    self.built_block_trace.add_included_order(res);
                    Ok(Ok(self.built_block_trace.included_orders.last().unwrap()))
                }
                Err(err) => {
                    self.built_block_trace
                        .modify_payment_when_no_signer_error(&err);
                    Ok(Err(err))
                }
            },
            Err(e) => Err(e),
        }
    }

    fn set_trace_fill_time(&mut self, time: Duration) {
        self.built_block_trace.fill_time = time;
    }

    fn set_trace_orders_closed_at(&mut self, orders_closed_at: OffsetDateTime) {
        self.built_block_trace.orders_closed_at = orders_closed_at;
    }

    fn can_add_payout_tx(&self) -> bool {
        !self.building_ctx[&self.origin_chain_id].coinbase_is_suggested_fee_recipient()
    }

    fn true_block_value(&self) -> Result<U256, BlockBuildingHelperError> {
        if let Some(payout_tx_gas) = self.payout_tx_gas {
            Ok(self
                .partial_block
                .get_proposer_payout_tx_value(payout_tx_gas, &self.building_ctx[&self.origin_chain_id])?)
        } else {
            Ok(self.partial_block.coinbase_profit)
        }
    }

    // Brecht: finalize
    fn finalize_block(
        mut self: Box<Self>,
        payout_tx_value: Option<U256>,
    ) -> Result<FinalizeBlockResult, BlockBuildingHelperError> {
        //println!("finalize_block");
        if payout_tx_value.is_some() && self.building_ctx[&self.origin_chain_id].coinbase_is_suggested_fee_recipient() {
            return Err(BlockBuildingHelperError::PayoutTxNotAllowed);
        }
        let start_time = Instant::now();

        //println!("finalize_block_execution");
        self.finalize_block_execution(payout_tx_value)?;
        //println!("finalize_block_execution done");
        // This could be moved outside of this func (pre finalize) since I don´t think the payout tx can change much.
        self.built_block_trace
            .verify_bundle_consistency(&self.building_ctx[&self.origin_chain_id].blocklist)?;

        let sim_gas_used = self.partial_block.tracer.used_gas;
        let mut blocks = HashMap::default();
        let mut cached_reads = CachedReads::default();
        for (chain_id, provider_factory) in self.provider_factory.iter() {
            // TODO Brecht: fix
            if *chain_id == 160010 {
                continue;
            }

            //println!("Creating block for chain {}", chain_id);

            let block_number = self.building_context().block();
            let finalized_block = match self.partial_block.clone().finalize(
                &mut self.block_state,
                &self.building_ctx[&self.origin_chain_id],
                provider_factory.clone(),
                self.root_hash_config.clone(),
                self.root_hash_task_pool.clone(),
            ) {
                Ok(finalized_block) => finalized_block,
                Err(err) => {
                    if err.is_consistent_db_view_err() {
                        let last_block_number = provider_factory
                            .last_block_number()
                            .unwrap_or_default();
                        debug!(
                            block_number,
                            last_block_number, "Can't build on this head, cancelling slot"
                        );
                        self.cancel_on_fatal_error.cancel();
                    }
                    return Err(BlockBuildingHelperError::FinalizeError(err));
                }
            };
            self.built_block_trace.update_orders_sealed_at();

            self.built_block_trace.finalize_time = start_time.elapsed();

            Self::trace_finalized_block(
                &finalized_block,
                &self.builder_name,
                &self.building_ctx[&self.origin_chain_id],
                &self.built_block_trace,
                sim_gas_used,
            );

            let block = Block {
                trace: self.built_block_trace.clone(),
                sealed_block: finalized_block.sealed_block,
                txs_blobs_sidecars: finalized_block.txs_blob_sidecars,
                builder_name: self.builder_name.clone(),
            };

            blocks.insert(*chain_id, block);
            cached_reads = finalized_block.cached_reads;
        }

        let header = Header::default();
        let block = RethBlock {
            header,
            //body: self.executed_tx.into_iter().map(|t| t.tx.into()).collect(),
            // TODO Brecht: fix
            body: blocks[&167010].sealed_block.body.clone(),
            ommers: Vec::new(),
            withdrawals: None,
            requests: None,
        };

        let block = Block {
            trace: self.built_block_trace.clone(),
            sealed_block: block.seal_slow(),
            txs_blobs_sidecars: Vec::new(),
            builder_name: self.builder_name.clone(),
        };

        Ok(FinalizeBlockResult {
            block,
            cached_reads,
        })
    }

    fn clone_cached_reads(&self) -> CachedReads {
        self.block_state.clone_cached_reads()
    }

    fn built_block_trace(&self) -> &BuiltBlockTrace {
        &self.built_block_trace
    }

    fn building_context(&self) -> &BlockBuildingContext {
        &self.building_ctx[&self.origin_chain_id]
    }

    fn box_clone(&self) -> Box<dyn BlockBuildingHelper> {
        Box::new(self.clone())
    }

    fn update_cached_reads(&mut self, cached_reads: CachedReads) {
        self.block_state = self.block_state.clone().with_cached_reads(cached_reads);
    }
}
