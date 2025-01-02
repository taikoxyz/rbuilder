FROM lukemathwalker/cargo-chef:latest-rust-1 AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev

COPY ./rbuilder/Cargo.lock /rbuilder/Cargo.lock
COPY ./rbuilder/Cargo.toml /rbuilder/Cargo.toml
COPY ./rbuilder/crates /rbuilder/crates
COPY ./reth/Cargo.lock ./reth/Cargo.lock
COPY ./reth/Cargo.toml ./reth/Cargo.toml
COPY ./reth/crates ./reth/crates
COPY ./reth/bin ./reth/bin
COPY ./reth/examples ./reth/examples
COPY ./reth/testing ./reth/testing
COPY ./revm ./revm
COPY ./revm-inspectors ./revm-inspectors
RUN pwd && ls

WORKDIR /rbuilder
RUN cargo build --bin gwyneth-rbuilder --release

FROM ubuntu:22.04 AS runtime
COPY --from=builder /rbuilder/target/release/gwyneth-rbuilder /usr/local/bin
COPY ./reth/crates/ethereum/node/tests/assets /network-configs
RUN cat /network-configs/genesis.json
WORKDIR /app
# RUN rbuilder

ENTRYPOINT ["/usr/local/bin/gwyneth-rbuilder"]
