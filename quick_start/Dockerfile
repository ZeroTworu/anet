# ANet VPN Server — multi-stage build from anet source
# Use rust:bookworm (Rust 1.85+ required for anet edition 2024)
FROM rust:bookworm AS builder
RUN apt-get update \
  && apt-get install -y --no-install-recommends protobuf-compiler \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy full anet workspace (needed for cargo workspace resolution)
COPY anet /build/anet
WORKDIR /build/anet

# Build anet-server and anet-keygen (keygen used by generate-config.sh)
RUN cargo build --release -p anet-server -p anet-keygen

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       ca-certificates openssl iptables iproute2 procps \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /config
WORKDIR /config

COPY --from=builder /build/anet/target/release/anet-server /usr/local/bin/anet-server
COPY --from=builder /build/anet/target/release/anet-keygen /usr/local/bin/anet-keygen
COPY openssl-server.cnf /usr/share/anet/openssl-server.cnf

# Server needs NET_ADMIN for TUN and iptables NAT; run with host network on Linux
ENTRYPOINT ["/usr/local/bin/anet-server"]
CMD ["-c", "/config/server.toml"]
