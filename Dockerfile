FROM rust:1-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY src ./src
COPY xtask ./xtask

RUN cargo build --locked --release --bin tunnelworm --bin tunnelwormd

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY --from=builder /app/target/release/tunnelworm /usr/local/bin/tunnelworm
COPY --from=builder /app/target/release/tunnelwormd /usr/local/bin/tunnelwormd

ENTRYPOINT ["/usr/local/bin/tunnelworm"]
