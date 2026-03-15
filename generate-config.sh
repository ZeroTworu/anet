#!/usr/bin/env bash
# ============================================================================
# ANet VPN Server — Config Generator
# Generates all crypto material and assembles server.toml + client info
# Usage: ./generate-config.sh [--clients N] [--external-if IFACE] [--bind PORT]
# ============================================================================
set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
NUM_CLIENTS=1
EXTERNAL_IF=""
BIND_PORT="8443"
CONFIG_DIR="./server"
IMAGE_NAME="anet-server:latest"

# ── colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
header(){ echo -e "\n${CYAN}══════ $* ══════${NC}"; }

# ── parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --clients)      NUM_CLIENTS="$2"; shift 2 ;;
    --external-if)  EXTERNAL_IF="$2"; shift 2 ;;
    --bind)         BIND_PORT="$2";   shift 2 ;;
    --config-dir)   CONFIG_DIR="$2";  shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--clients N] [--external-if IFACE] [--bind PORT] [--config-dir DIR]"
      echo ""
      echo "  --clients N         Number of client key pairs to generate (default: 1)"
      echo "  --external-if IFACE Network interface for NAT (auto-detected if omitted)"
      echo "  --bind PORT         UDP port to bind (default: 8443)"
      echo "  --config-dir DIR    Output directory for server.toml (default: ./server)"
      exit 0 ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
done

# ── detect external interface ───────────────────────────────────────────────
if [[ -z "$EXTERNAL_IF" ]]; then
  EXTERNAL_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}') || true
  if [[ -z "$EXTERNAL_IF" ]]; then
    EXTERNAL_IF="eth0"
    warn "Could not auto-detect external interface, using eth0"
  else
    info "Auto-detected external interface: $EXTERNAL_IF"
  fi
fi

# ── check docker image (build if missing) ──────────────────────────────────
header "Checking Docker image"
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
  warn "Image $IMAGE_NAME not found, building..."
  docker compose build
fi

# ── helper: run anet-keygen inside container ────────────────────────────────
keygen() {
  docker run --rm --entrypoint anet-keygen "$IMAGE_NAME" "$@"
}

# ── generate server key ────────────────────────────────────────────────────
header "Generating server signing key"
SERVER_KEYGEN_OUT=$(keygen server)
echo "$SERVER_KEYGEN_OUT"

SERVER_SIGNING_KEY=$(echo "$SERVER_KEYGEN_OUT" | grep 'server_signing_key' | sed 's/.*= *"\(.*\)"/\1/')
SERVER_PUB_KEY=$(echo "$SERVER_KEYGEN_OUT" | grep -A1 'Public Key' | tail -1 | tr -d '[:space:]')

info "server_signing_key = ${SERVER_SIGNING_KEY:0:12}..."
info "server public_key  = ${SERVER_PUB_KEY:0:12}..."

# ── generate client keys ──────────────────────────────────────────────────
header "Generating $NUM_CLIENTS client key pair(s)"
ALLOWED_CLIENTS=""
CLIENT_CONFIGS=""

for i in $(seq 1 "$NUM_CLIENTS"); do
  CLIENT_KEYGEN_OUT=$(keygen client)

  CLIENT_PRIVATE_KEY=$(echo "$CLIENT_KEYGEN_OUT" | grep 'private_key' | sed 's/.*= *"\(.*\)"/\1/')
  CLIENT_FINGERPRINT=$(echo "$CLIENT_KEYGEN_OUT" | grep -A1 'Fingerprint' | tail -1 | tr -d '[:space:]')
  CLIENT_PUB_KEY=$(echo "$CLIENT_KEYGEN_OUT" | grep -A1 'Public Key' | tail -1 | tr -d '[:space:]')

  info "Client #${i}: fingerprint = ${CLIENT_FINGERPRINT}"

  # Build allowed_clients TOML array entries
  if [[ -n "$ALLOWED_CLIENTS" ]]; then
    ALLOWED_CLIENTS="${ALLOWED_CLIENTS}
    \"${CLIENT_FINGERPRINT}\","
  else
    ALLOWED_CLIENTS="    \"${CLIENT_FINGERPRINT}\","
  fi

  # Accumulate client info for output file
  CLIENT_CONFIGS="${CLIENT_CONFIGS}
# ═══════════════════════════════════════
# Client #${i}
# ═══════════════════════════════════════
# Put this in client.toml → [keys]:
#   private_key    = \"${CLIENT_PRIVATE_KEY}\"
#   server_pub_key = \"${SERVER_PUB_KEY}\"
#
# Fingerprint (already added to server.toml):
#   ${CLIENT_FINGERPRINT}
# Public Key:
#   ${CLIENT_PUB_KEY}
"
done

# ── generate QUIC certificate ──────────────────────────────────────────────
header "Generating QUIC TLS certificate"
CERT_DIR=$(mktemp -d)

# Use openssl + openssl-server.cnf from the image
docker run --rm -v "$CERT_DIR:/certs" --entrypoint sh "$IMAGE_NAME" -c "
  openssl genrsa -out /certs/key.pem 2048 2>/dev/null
  openssl req -new -x509 -key /certs/key.pem -out /certs/cert.pem -days 3650 \
    -config /usr/share/anet/openssl-server.cnf -extensions v3_req 2>/dev/null
"

QUIC_CERT=$(cat "$CERT_DIR/cert.pem")
QUIC_KEY=$(cat "$CERT_DIR/key.pem")
rm -rf "$CERT_DIR"

info "QUIC certificate generated (3650 days, SAN: alco)"

# ── assemble server.toml ──────────────────────────────────────────────────
header "Writing config files"
mkdir -p "$CONFIG_DIR"

cat > "$CONFIG_DIR/server.toml" << TOMLEOF
# =========================================================================
# ANet Server Configuration — auto-generated $(date -u '+%Y-%m-%d %H:%M UTC')
# =========================================================================

[network]
net = "10.0.0.0"
mask = "255.255.255.0"
gateway = "10.0.0.1"
self_ip = "10.0.0.2"
if_name = "anet-server"
mtu = 1300

[server]
bind_to = "0.0.0.0:${BIND_PORT}"
external_if = "${EXTERNAL_IF}"

[authentication]
allowed_clients = [
${ALLOWED_CLIENTS}
]
auth_servers = []
auth_server_token = ""

[crypto]
quic_cert = """
${QUIC_CERT}
"""

quic_key = """
${QUIC_KEY}
"""

server_signing_key = "${SERVER_SIGNING_KEY}"

[stats]
enabled = true
interval_minutes = 1

[stealth]
padding_step = 64
min_jitter_ns = 1000000
max_jitter_ns = 5000000

[quic_transport]
algorithm = "bbr"
expected_rtt_ms = 60
bandwidth_down_mbps = 1000
bandwidth_up_mbps = 1000
enable_gso = true
idle_timeout_seconds = 21600
max_mtu = 1500
TOMLEOF

info "Written: $CONFIG_DIR/server.toml"

# ── write client info ─────────────────────────────────────────────────────
cat > "$CONFIG_DIR/client-keys.txt" << CLIENTEOF
# =========================================================================
# ANet Client Keys — auto-generated $(date -u '+%Y-%m-%d %H:%M UTC')
# =========================================================================
# Server address for client.toml: YOUR_SERVER_IP:${BIND_PORT}
# Server public key (server_pub_key): ${SERVER_PUB_KEY}
${CLIENT_CONFIGS}
CLIENTEOF

info "Written: $CONFIG_DIR/client-keys.txt"

# ── summary ────────────────────────────────────────────────────────────────
header "Done"
info "Config:      $CONFIG_DIR/server.toml"
info "Client keys: $CONFIG_DIR/client-keys.txt"
echo ""
info "Next steps:"
echo "  1. Generate client.toml: ./generate-client-config.sh --server-address YOUR_IP:${BIND_PORT}"
echo "  2. Copy client.toml to your Windows/Linux client"
echo "  3. Start the server:  docker compose up -d"
echo "  4. Check diagnostics: ./diagnose.sh"
