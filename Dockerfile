# ANet VPN Server — Download prebuilt binaries from GitHub releases
# This is the default mode for quick setup
FROM debian:bookworm-slim

ARG ANET_VERSION=latest
ARG GITHUB_REPO=ZeroTworu/anet

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       ca-certificates openssl iptables iproute2 procps curl unzip \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Download and extract prebuilt binaries from GitHub releases
RUN set -e && \
    if [ "$ANET_VERSION" = "latest" ]; then \
      # Get latest release tag from GitHub API
      RELEASE_TAG=$(curl -sL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'); \
      VERSION_NUM=$(echo "$RELEASE_TAG" | sed 's/^v//'); \
      DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${RELEASE_TAG}/server_${VERSION_NUM}.zip"; \
    else \
      DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${ANET_VERSION}/server_${ANET_VERSION}.zip"; \
    fi && \
    echo "Downloading from: $DOWNLOAD_URL" && \
    curl -sfL "$DOWNLOAD_URL" -o server.zip || { \
      echo "Failed to download from $DOWNLOAD_URL"; \
      echo "Trying fallback: latest redirect..."; \
      curl -sL "https://github.com/${GITHUB_REPO}/releases/latest" | grep -o 'href="[^"]*server_[^"]*\.zip"' | head -1 | sed 's/href="//;s/"$//' | xargs -I {} curl -sL "https://github.com{}" -o server.zip; \
    } && \
    unzip -q server.zip && \
    mv server/anet-server /usr/local/bin/anet-server && \
    chmod +x /usr/local/bin/anet-server && \
    rm -rf server.zip server

# Download anet-keygen (from anet repo releases if available, otherwise build minimal version)
RUN KEYGEN_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/anet-keygen" && \
    if curl -sfL "$KEYGEN_URL" -o /usr/local/bin/anet-keygen 2>/dev/null; then \
      chmod +x /usr/local/bin/anet-keygen; \
      echo "Downloaded anet-keygen from releases"; \
    else \
      echo "#!/bin/sh" > /usr/local/bin/anet-keygen && \
      echo "echo 'anet-keygen not available in releases. Use generate-config.sh on host.'" >> /usr/local/bin/anet-keygen && \
      chmod +x /usr/local/bin/anet-keygen; \
    fi

RUN mkdir -p /config
WORKDIR /config

COPY openssl-server.cnf /usr/share/anet/openssl-server.cnf

# Server needs NET_ADMIN for TUN and iptables NAT; run with host network on Linux
ENTRYPOINT ["/usr/local/bin/anet-server"]
CMD ["-c", "/config/server.toml"]
