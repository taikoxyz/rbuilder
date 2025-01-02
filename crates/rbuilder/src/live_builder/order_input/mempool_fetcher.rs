use super::{OrderInputConfig, ReplaceableOrderPoolCommand};
use crate::{
    live_builder::gwyneth::{EthApiStream}, primitives::{MempoolTx, Metadata, Order, TransactionSignedEcRecoveredWithBlobs}, telemetry::add_txfetcher_time_to_query
};
use alloy_primitives::{hex, Bytes, FixedBytes};
use alloy_provider::{IpcConnect, Provider, ProviderBuilder, RootProvider};
use alloy_pubsub::PubSubFrontend;
use futures::{FutureExt, StreamExt};
use reth::transaction_pool::{EthPoolTransaction, EthPooledTransaction};
use std::{pin::pin, sync::Arc, time::Instant};
use tokio::{
    sync::{mpsc, mpsc::error::SendTimeoutError},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};

/// Subscribes to EL mempool and pushes new txs as orders in results.
/// This version allows 4844 by subscribing to subscribe_pending_txs to get the hashes and then calling eth_getRawTransactionByHash
/// to get the raw tx that, in case of 4844 tx, may include blobs.
/// In the future we may consider updating reth so we can process blob txs in a different task to avoid slowing down non blob txs.
pub async fn subscribe_to_mempool_with_blobs(
    config: OrderInputConfig,
    ethapi: Arc<dyn EthApiStream>,
    results: mpsc::Sender<ReplaceableOrderPoolCommand>,
    global_cancel: CancellationToken,
) -> eyre::Result<JoinHandle<()>> {
    println!("[rb] Cecilia ==>  mempool_fetcher::subscribe_to_mempool_with_blobs");
    let handle = tokio::spawn(async move {
        info!("Subscribe to txpool with blobs: started");

        while let Some(tx) = ethapi.full_pending_transaction_stream().next().await {
            if config.skip {
                continue;
            }
            println!("[rb] Cecilia debug: Some txn arrived on {:?}", tx);

            let start = Instant::now();
            let tx = convert_pooled_transactions(tx.transaction.transaction.clone());

            let order = Order::Tx(tx);
            let order_id = order.id();

            let parse_duration = start.elapsed();
            trace!(order = ?order.id(), parse_duration_mus = parse_duration.as_micros(), "Mempool transaction received with blobs");

            add_txfetcher_time_to_query(parse_duration);
            println!(
                "Dani debug: About to send order to results channel. Order ID: {:?}",
                order_id
            );
            match results
                .send_timeout(
                    ReplaceableOrderPoolCommand::Order(order),
                    config.results_channel_timeout,
                )
                .await
            {
                Ok(()) => {}
                Err(SendTimeoutError::Timeout(_)) => {
                    error!("Failed to send txpool tx to results channel, timeout");
                }
                Err(SendTimeoutError::Closed(_)) => {
                    break;
                }
            }
            println!(
                "Dani debug: Successfully sent order to results channel. Order ID: {:?}",
                order_id
            );
        }

        // stream is closed, cancelling token because builder can't work without this stream
        global_cancel.cancel();
        info!("Subscribe to txpool: finished");
    });

    Ok(handle)
}

fn convert_pooled_transactions(mut pooled_tx: EthPooledTransaction) -> MempoolTx {
    let tx = pooled_tx.transaction().clone();

    let tx_with_blobs = if let Some(blob) = pooled_tx.take_blob().maybe_sidecar() {
        TransactionSignedEcRecoveredWithBlobs {
            tx,
            blobs_sidecar: Arc::new(blob.clone()),
            metadata: Default::default(),
        }
    } else {
        TransactionSignedEcRecoveredWithBlobs::new_no_blobs(tx).unwrap()
    };

    MempoolTx {
        tx_with_blobs,
    }
}


// #[cfg(test)]
// mod test {
//     use super::*;
//     use alloy_consensus::{SidecarBuilder, SimpleCoder};
//     use alloy_network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844};
//     use alloy_node_bindings::Anvil;
//     use alloy_primitives::U256;
//     use alloy_provider::{Provider, ProviderBuilder};
//     use alloy_rpc_types::TransactionRequest;
//     use alloy_signer_local::PrivateKeySigner;

//     #[tokio::test]
//     /// Test that the fetcher can retrieve transactions (both normal and blob) from the txpool
//     async fn test_fetcher_retrieves_transactions() {
//         let anvil = Anvil::new()
//             .args(["--ipc", "/tmp/anvil.ipc"])
//             .try_spawn()
//             .unwrap();

//         let (sender, mut receiver) = mpsc::channel(10);
//         subscribe_to_mempool_with_blobs(
//             OrderInputConfig::default_e2e(),
//             sender,
//             CancellationToken::new(),
//         )
//         .await
//         .unwrap();

//         let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
//         let wallet = EthereumWallet::from(signer);

//         let provider = ProviderBuilder::new()
//             .with_recommended_fillers()
//             .wallet(wallet)
//             .on_http(anvil.endpoint().parse().unwrap());

//         let alice = anvil.addresses()[0];

//         let sidecar: SidecarBuilder<SimpleCoder> =
//             SidecarBuilder::from_slice("Blobs are fun!".as_bytes());
//         let sidecar = sidecar.build().unwrap();

//         let gas_price = provider.get_gas_price().await.unwrap();
//         let eip1559_est = provider.estimate_eip1559_fees(None).await.unwrap();

//         let tx = TransactionRequest::default()
//             .with_to(alice)
//             .with_nonce(0)
//             .with_max_fee_per_blob_gas(gas_price)
//             .with_max_fee_per_gas(eip1559_est.max_fee_per_gas)
//             .with_max_priority_fee_per_gas(eip1559_est.max_priority_fee_per_gas)
//             .with_blob_sidecar(sidecar);

//         let pending_tx = provider.send_transaction(tx).await.unwrap();
//         let recv_tx = receiver.recv().await.unwrap();

//         let tx_with_blobs = match recv_tx {
//             ReplaceableOrderPoolCommand::Order(Order::Tx(MempoolTx { tx_with_blobs })) => {
//                 Some(tx_with_blobs)
//             }
//             _ => None,
//         }
//         .unwrap();

//         assert_eq!(tx_with_blobs.hash(), *pending_tx.tx_hash());
//         assert_eq!(tx_with_blobs.blobs_sidecar.blobs.len(), 1);

//         // send another tx without blobs
//         let tx = TransactionRequest::default()
//             .with_to(alice)
//             .with_nonce(1)
//             .with_value(U256::from(1))
//             .with_max_fee_per_gas(eip1559_est.max_fee_per_gas)
//             .with_max_priority_fee_per_gas(eip1559_est.max_priority_fee_per_gas);

//         let pending_tx = provider.send_transaction(tx).await.unwrap();
//         let recv_tx = receiver.recv().await.unwrap();

//         let tx_without_blobs = match recv_tx {
//             ReplaceableOrderPoolCommand::Order(Order::Tx(MempoolTx { tx_with_blobs })) => {
//                 Some(tx_with_blobs)
//             }
//             _ => None,
//         }
//         .unwrap();

//         assert_eq!(tx_without_blobs.hash(), *pending_tx.tx_hash());
//         assert_eq!(tx_without_blobs.blobs_sidecar.blobs.len(), 0);
//     }
// }
