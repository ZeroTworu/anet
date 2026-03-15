#!/usr/bin/env bash
# ============================================================================
# ANet — Generate client.toml from server/client-keys.txt
# Run on the server; copy the generated client.toml to your Windows/Linux client.
# Usage: ./generate-client-config.sh --server-address IP:PORT [--client N] [--output FILE]
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_FILE="${SCRIPT_DIR}/server/client-keys.txt"
TEMPLATE="${SCRIPT_DIR}/client-windows/client.toml"
CONFIG_DIR="${SCRIPT_DIR}/server"
CLIENT_NUM=1
OUTPUT_FILE=""
SERVER_ADDRESS=""

# ── colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
header(){ echo -e "\n${CYAN}══════ $* ══════${NC}"; }
ok()    { echo -e "  ${GREEN}✔${NC} $*"; }

# ── parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-address) SERVER_ADDRESS="$2"; shift 2 ;;
    --client)         CLIENT_NUM="$2";     shift 2 ;;
    --output)         OUTPUT_FILE="$2";   shift 2 ;;
    -h|--help)
      echo "Usage: $0 --server-address IP:PORT [--client N] [--output FILE]"
      echo ""
      echo "  --server-address IP:PORT  Server address (e.g. 194.41.113.15:8443)"
      echo "  --client N                Client number from client-keys.txt (default: 1)"
      echo "  --output FILE             Output path (default: client-windows/client.toml)"
      echo ""
      echo "Requires: server/client-keys.txt (from ./generate-config.sh)"
      exit 0 ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$SERVER_ADDRESS" ]]; then
  err "Missing --server-address IP:PORT"
  exit 1
fi

if [[ -z "$OUTPUT_FILE" ]]; then
  OUTPUT_FILE="${SCRIPT_DIR}/client-windows/client.toml"
fi

# ── check inputs ───────────────────────────────────────────────────────────
header "Checking inputs"

if [[ ! -f "$KEYS_FILE" ]]; then
  err "Keys file not found: $KEYS_FILE"
  err "Run ./generate-config.sh first."
  exit 1
fi
ok "Keys file: $KEYS_FILE"

if [[ ! -f "$TEMPLATE" ]]; then
  err "Template not found: $TEMPLATE"
  exit 1
fi
ok "Template: $TEMPLATE"

# ── trim: strip leading/trailing whitespace and CR only (keep key intact) ────
trim_key() {
  local v
  if [[ $# -ge 1 ]]; then
    v="$1"
  else
    IFS= read -r v || true
  fi
  echo "$v" | sed 's/^[[:space:]\r]*//;s/[[:space:]\r]*$//' | tr -d '\r\n'
}

# ── validate Base64 key decodes to 32 bytes (Ed25519) ────────────────────────
validate_ed25519_b64() {
  local key="$1"
  local name="$2"
  local len
  len=$(echo "$key" | base64 -d 2>/dev/null | wc -c)
  if [[ "$len" -ne 32 ]]; then
    err "$name: decoded length is $len (expected 32). Key length ${#key} chars."
    return 1
  fi
  return 0
}

# ── parse server public key (from header) ───────────────────────────────────
SERVER_PUB_KEY=$(grep "Server public key (server_pub_key):" "$KEYS_FILE" | sed 's/.*: *//' | trim_key)
if [[ -z "$SERVER_PUB_KEY" ]]; then
  err "Could not parse server_pub_key from $KEYS_FILE"
  exit 1
fi
if ! validate_ed25519_b64 "$SERVER_PUB_KEY" "server_pub_key"; then exit 1; fi
info "Server public key: ${#SERVER_PUB_KEY} chars, decodes to 32 bytes"

# ── parse client block (Client #N) ──────────────────────────────────────────
BLOCK=$(awk -v n="$CLIENT_NUM" '
  /# Client #/ {
    if (found) exit
    if ($0 ~ "# Client #" n " " || $0 ~ "# Client #" n "$") found = 1
    next
  }
  found { print }
' "$KEYS_FILE")

PRIVATE_KEY=$(echo "$BLOCK" | grep "private_key" | sed -n 's/.*= *"\([^"]*\)".*/\1/p' | trim_key)
CLIENT_SERVER_PUB=$(echo "$BLOCK" | grep "server_pub_key" | sed -n 's/.*= *"\([^"]*\)".*/\1/p' | trim_key)
[[ -n "$CLIENT_SERVER_PUB" ]] && SERVER_PUB_KEY=$(trim_key "$CLIENT_SERVER_PUB")

if [[ -z "$PRIVATE_KEY" ]]; then
  err "Could not parse private_key for Client #$CLIENT_NUM in $KEYS_FILE"
  err "Check that Client #$CLIENT_NUM exists (e.g. generate-config.sh --clients $CLIENT_NUM)"
  exit 1
fi
if ! validate_ed25519_b64 "$PRIVATE_KEY" "private_key"; then exit 1; fi
info "Client #$CLIENT_NUM private_key: ${#PRIVATE_KEY} chars, decodes to 32 bytes"

# ── generate client.toml ───────────────────────────────────────────────────
header "Writing client config"

mkdir -p "$(dirname "$OUTPUT_FILE")"

# Write keys to temp files (one line each, so awk getline reads reliably)
TMP_PRIV=$(mktemp) TMP_PUB=$(mktemp) TMP_ADDR=$(mktemp)
trap 'rm -f "$TMP_PRIV" "$TMP_PUB" "$TMP_ADDR"' EXIT
echo "$PRIVATE_KEY" > "$TMP_PRIV"
echo "$SERVER_PUB_KEY" > "$TMP_PUB"
echo "$SERVER_ADDRESS" > "$TMP_ADDR"

# Write to temp file first: template and output are often the same path (would truncate before read)
TMP_OUTPUT=$(mktemp)
trap 'rm -f "$TMP_PRIV" "$TMP_PUB" "$TMP_ADDR" "$TMP_OUTPUT"' EXIT

awk -v addr_file="$TMP_ADDR" -v priv_file="$TMP_PRIV" -v pub_file="$TMP_PUB" '
  BEGIN {
    getline addr < addr_file; close(addr_file)
    getline priv < priv_file; close(priv_file)
    getline pub  < pub_file;  close(pub_file)
    gsub(/\r$/, "", addr); gsub(/\r$/, "", priv); gsub(/\r$/, "", pub)
  }
  /^address = "/      { print "address = \"" addr "\""; next }
  /^private_key = "/  { print "private_key = \"" priv "\""; next }
  /^server_pub_key = "/ { print "server_pub_key = \"" pub "\""; next }
  { print }
' "$TEMPLATE" > "$TMP_OUTPUT"
mv "$TMP_OUTPUT" "$OUTPUT_FILE"

info "Written: $OUTPUT_FILE"
echo ""
info "Copy this file to your Windows/Linux client and run the ANet client."
echo "  scp $OUTPUT_FILE user@pc:./client.toml"
echo "  or copy client-windows/ folder to the client machine."
