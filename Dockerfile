# Dockerfile for building rbuilder executable
FROM lukemathwalker/cargo-chef:latest-rust-1 AS builder
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config git

# Copy the entire rbuilder repository
COPY . .

# Build the executable
RUN cargo build --release

# Stage for the executable
FROM scratch
COPY --from=builder /app/target/release/rbuilder /usr/local/bin/rbuilder

# Mark the executable as the entrypoint
ENTRYPOINT ["/usr/local/bin/rbuilder"]
