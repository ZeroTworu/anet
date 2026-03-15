#!/usr/bin/env bash
# ============================================================================
# ANet VPN Server — Docker Installer
# Default: Uses prebuilt binaries from GitHub releases (fast, no compilation)
# To build from source: ./install.sh --build-from-source
# Usage: ./install.sh [--build-from-source] [--clients N] [--external-if IFACE] [--bind PORT]
# Config flags (--clients, --external-if, etc.) are passed to generate-config.sh
# ============================================================================
set -euo pipefail

# ── colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
header(){ echo -e "\n${CYAN}══════ $* ══════${NC}"; }
ok()    { echo -e "  ${GREEN}✔${NC} $*"; }
fail()  { echo -e "  ${RED}✘${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── 1. Check prerequisites ─────────────────────────────────────────────────
header "Checking prerequisites"

MISSING=0

# Docker
if command -v docker &>/dev/null; then
  ok "docker $(docker --version | awk '{print $3}' | tr -d ',')"
else
  fail "docker not found — install: https://docs.docker.com/engine/install/"
  MISSING=1
fi

# Docker Compose (plugin or standalone)
if docker compose version &>/dev/null; then
  ok "docker compose $(docker compose version --short 2>/dev/null || echo '(ok)')"
elif command -v docker-compose &>/dev/null; then
  ok "docker-compose (standalone)"
else
  fail "docker compose not found — install: https://docs.docker.com/compose/install/"
  MISSING=1
fi

# openssl (used inside container, but useful on host too)
if command -v openssl &>/dev/null; then
  ok "openssl $(openssl version 2>/dev/null | awk '{print $2}')"
else
  warn "openssl not found on host (ok — container has it)"
fi

# Check OS
if [[ "$(uname -s)" != "Linux" ]]; then
  warn "ANet Docker server requires Linux for host networking + TUN"
  warn "Current OS: $(uname -s). Container may not work correctly."
fi

# Check root / docker permissions
if ! docker info &>/dev/null; then
  fail "Cannot connect to Docker daemon. Run as root or add user to docker group."
  MISSING=1
fi

if [[ $MISSING -eq 1 ]]; then
  err "Missing prerequisites. Fix the issues above and re-run."
  exit 1
fi

# ── 2. Choose build mode ──────────────────────────────────────────────────
header "Checking build mode"

# Check if --build-from-source flag is passed
BUILD_FROM_SOURCE=0
CONFIG_ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "--build-from-source" ]]; then
    BUILD_FROM_SOURCE=1
  else
    # Collect other args for generate-config.sh
    CONFIG_ARGS+=("$arg")
  fi
done

if [[ $BUILD_FROM_SOURCE -eq 1 ]]; then
  info "Build mode: FROM SOURCE (--build-from-source flag detected)"
  info "This will compile anet from Rust source code (slower, ~5-10 min)"
  ANET_REPO="https://github.com/ZeroTworu/anet.git"

  if [[ -d ./anet && -f ./anet/Cargo.toml ]]; then
    ok "anet/ directory exists"
  else
    warn "anet/ directory not found — cloning from $ANET_REPO"
    if command -v git &>/dev/null; then
      git clone "$ANET_REPO" ./anet
      ok "Cloned anet repository"
    else
      fail "git not found — install git or manually clone:"
      echo "      git clone $ANET_REPO ./anet"
      exit 1
    fi
  fi
  COMPOSE_FILE="docker-compose.build.yml"
else
  info "Build mode: PREBUILT BINARIES (default)"
  info "Docker will download latest release from GitHub (fast, ~1-2 min)"
  info "To build from source: ./install.sh --build-from-source"
  COMPOSE_FILE="docker-compose.yml"
fi

header "Checking TUN device"
if [[ -e /dev/net/tun ]]; then
  ok "/dev/net/tun exists"
else
  warn "/dev/net/tun not found — server needs TUN support in kernel"
  warn "Try: mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun"
fi

header "Enabling IPv4 forwarding"
if sysctl -w net.ipv4.ip_forward=1 &>/dev/null; then
  ok "net.ipv4.ip_forward=1"
else
  warn "Could not set ip_forward (run as root)"
fi

# ── 3. Build Docker image ─────────────────────────────────────────────────
header "Building Docker image"
docker compose -f "$COMPOSE_FILE" build
info "Image built successfully"

# ── 4. Generate config if not present ─────────────────────────────────────
header "Checking configuration"
if [[ -f ./server/server.toml ]]; then
  # Check if it has real keys or placeholders
  if grep -q 'Содержимое cert.pem' ./server/server.toml 2>/dev/null || \
     grep -q 'server_signing_key = ""' ./server/server.toml 2>/dev/null; then
    warn "server.toml has placeholder values — regenerating"
    bash ./generate-config.sh "${CONFIG_ARGS[@]}"
  else
    ok "server.toml exists with configured keys"
    info "To regenerate: ./generate-config.sh ${CONFIG_ARGS[*]}"
  fi
else
  info "No server.toml found — generating new config"
  bash ./generate-config.sh "${CONFIG_ARGS[@]}"
fi

# ── 5. Start container ────────────────────────────────────────────────────
header "Starting ANet server"
docker compose -f "$COMPOSE_FILE" up -d
sleep 2

# Quick health check
if docker compose -f "$COMPOSE_FILE" ps --format '{{.State}}' 2>/dev/null | grep -q running; then
  ok "Container is running"
else
  # Fallback check for older docker compose
  if docker ps --filter "name=anet-server" --format '{{.Status}}' | grep -q Up; then
    ok "Container is running"
  else
    fail "Container failed to start"
    echo ""
    warn "Last 20 log lines:"
    docker compose -f "$COMPOSE_FILE" logs --tail 20 anet-server
    exit 1
  fi
fi

# ── 6. Quick port check ───────────────────────────────────────────────────
sleep 1
BIND_PORT=$(grep 'bind_to' ./server/server.toml 2>/dev/null | grep -oP ':\K[0-9]+' || echo "8443")
if ss -ulnp 2>/dev/null | grep -q ":${BIND_PORT}"; then
  ok "Port ${BIND_PORT}/UDP is listening"
else
  warn "Port ${BIND_PORT}/UDP not detected yet — server may still be starting"
fi

# ── Done ────────────────────────────────────────────────────────────────────
header "Installation complete"
info "Server is running on port ${BIND_PORT}/UDP"
info "Config:      ./server/server.toml"
info "Client keys: ./server/client-keys.txt"
echo ""
info "Useful commands:"
if [[ "$COMPOSE_FILE" == "docker-compose.build.yml" ]]; then
  COMPOSE_CMD="docker compose -f docker-compose.build.yml"
else
  COMPOSE_CMD="docker compose"
fi
echo "  $COMPOSE_CMD logs -f anet-server    # live logs"
echo "  $COMPOSE_CMD restart anet-server    # restart"
echo "  $COMPOSE_CMD down                   # stop"
echo "  ./diagnose.sh                         # diagnostics"
echo "  ./generate-config.sh --clients 2      # regenerate with 2 clients"
