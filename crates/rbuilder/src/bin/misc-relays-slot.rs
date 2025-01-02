//! Helper app to get information from a landed block from the relays.
//! Takes no configuration since it uses a hardcoded list of relays ([`rbuilder::mev_boost::RELAYS`]).
use alloy_primitives::utils::format_ether;
use clap::Parser;
use rbuilder::backtest::fetch::mev_boost::PayloadDeliveredFetcher;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(help = "block number")]
    block: u64,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    let env = tracing_subscriber::EnvFilter::from_default_env();
    let writer = tracing_subscriber::fmt()
        .with_env_filter(env)
        .with_test_writer();
    writer.init();

    let fetcher = PayloadDeliveredFetcher::default();
    let result = fetcher.get_payload_delivered(cli.block).await;
    let payload = result.best_bid().ok_or_else(|| {
        eyre::eyre!(
            "No payload delivered, relay_errors: {:?}",
            result.relay_errors
        )
    })?;

    let ts_diff = (payload.timestamp * 1000) as i64 - payload.timestamp_ms as i64;
    let value = format_ether(payload.value);

    println!("[rb] Payload delivered");
    println!("[rb] relay          {}", result.best_relay().unwrap());
    println!("[rb] block          {}", payload.block_number);
    println!("[rb] block_hash     {:?}", payload.block_hash);
    println!("[rb] timestamp_ms   {}", payload.timestamp_ms);
    println!("[rb] timestamp      {}", payload.timestamp);
    println!("[rb] timestamp_diff {}", ts_diff);
    println!("[rb] num_tx         {}", payload.num_tx);
    println!("[rb] gas_used       {}", payload.gas_used);
    println!("[rb] builder        {:?}", payload.builder_pubkey);
    println!("[rb] value          {}", value);
    println!("[rb] optimistic     {}", payload.optimistic_submission);

    Ok(())
}
