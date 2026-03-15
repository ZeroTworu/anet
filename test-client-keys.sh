#!/usr/bin/env bash
# ============================================================================
# ANet — Validate keys in client.toml (Linux)
# Usage: ./test-client-keys.sh [path/to/client.toml]
# Default: client-windows/client.toml
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT_TOML="${1:-${SCRIPT_DIR}/client-windows/client.toml}"
# Resolve relative path to absolute (so we read the same file generate-client-config.sh wrote)
[[ "$CLIENT_TOML" != /* ]] && CLIENT_TOML="${SCRIPT_DIR}/${CLIENT_TOML}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()  { echo -e "${GREEN}PASS${NC} $*"; }
fail() { echo -e "${RED}FAIL${NC} $*"; }
warn() { echo -e "${YELLOW}WARN${NC} $*"; }

echo "Validating: $CLIENT_TOML"
echo "---"

if [[ ! -f "$CLIENT_TOML" ]]; then
  fail "File not found: $CLIENT_TOML"
  exit 1
fi

# Extract value for key (first occurrence); grep || true so set -e doesn't exit on no match
get_toml() {
  (grep -E "^${1}[[:space:]]*=" "$CLIENT_TOML" || true) | head -1 | sed -n 's/^[^=]*=[[:space:]]*"\([^"]*\)".*/\1/p' | tr -d '\r\n'
}

ADDRESS=$(get_toml "address")
PRIVATE_KEY=$(get_toml "private_key")
SERVER_PUB_KEY=$(get_toml "server_pub_key")

FAILED=0

# Check present
if [[ -z "$ADDRESS" ]]; then
  fail "address is empty"
  FAILED=1
else
  ok "address = \"$ADDRESS\""
fi

if [[ -z "$PRIVATE_KEY" ]]; then
  fail "private_key is empty"
  FAILED=1
else
  BYTES=$(echo "$PRIVATE_KEY" | base64 -d 2>/dev/null | wc -c)
  if [[ "$BYTES" -eq 32 ]]; then
    ok "private_key: ${#PRIVATE_KEY} chars, decodes to 32 bytes (Ed25519)"
  else
    fail "private_key: decodes to $BYTES bytes (expected 32). Length ${#PRIVATE_KEY} chars."
    FAILED=1
  fi
fi

if [[ -z "$SERVER_PUB_KEY" ]]; then
  fail "server_pub_key is empty"
  FAILED=1
else
  BYTES=$(echo "$SERVER_PUB_KEY" | base64 -d 2>/dev/null | wc -c)
  if [[ "$BYTES" -eq 32 ]]; then
    ok "server_pub_key: ${#SERVER_PUB_KEY} chars, decodes to 32 bytes (Ed25519)"
  else
    fail "server_pub_key: decodes to $BYTES bytes (expected 32). Length ${#SERVER_PUB_KEY} chars."
    FAILED=1
  fi
fi

# Address format
if [[ -n "$ADDRESS" && "$ADDRESS" == *"YOUR_SERVER_IP"* ]]; then
  warn "address contains placeholder YOUR_SERVER_IP — replace with real server IP"
fi

echo "---"
if [[ $FAILED -eq 0 ]]; then
  echo -e "${GREEN}All key checks passed.${NC}"
  exit 0
else
  echo -e "${RED}Some checks failed. Fix client.toml or regenerate with ./generate-client-config.sh${NC}"
  exit 1
fi
