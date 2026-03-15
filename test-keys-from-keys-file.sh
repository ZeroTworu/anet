#!/usr/bin/env bash
# ============================================================================
# ANet — Validate keys in server/client-keys.txt (Linux)
# Same parsing as generate-client-config.sh; checks that keys decode to 32 bytes.
# Usage: ./test-keys-from-keys-file.sh [--client N]
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_FILE="${SCRIPT_DIR}/server/client-keys.txt"
CLIENT_NUM=1
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()  { echo -e "${GREEN}PASS${NC} $*"; }
fail() { echo -e "${RED}FAIL${NC} $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client) CLIENT_NUM="$2"; shift 2 ;;
    *) KEYS_FILE="$1"; shift ;;
  esac
done

echo "Validating: $KEYS_FILE (Client #$CLIENT_NUM)"
echo "---"

if [[ ! -f "$KEYS_FILE" ]]; then
  fail "File not found: $KEYS_FILE (run ./generate-config.sh first)"
  exit 1
fi

trim_key() {
  local v
  if [[ $# -ge 1 ]]; then
    v="$1"
  else
    IFS= read -r v || true
  fi
  echo "$v" | sed 's/^[[:space:]\r]*//;s/[[:space:]\r]*$//' | tr -d '\r\n'
}

# Server public key from header
SERVER_PUB_KEY=$(grep "Server public key (server_pub_key):" "$KEYS_FILE" | sed 's/.*: *//' | trim_key)
if [[ -z "$SERVER_PUB_KEY" ]]; then
  fail "Could not parse server_pub_key from header"
  exit 1
fi
BYTES=$(echo "$SERVER_PUB_KEY" | base64 -d 2>/dev/null | wc -c)
if [[ "$BYTES" -eq 32 ]]; then
  ok "server_pub_key (header): ${#SERVER_PUB_KEY} chars, 32 bytes"
else
  fail "server_pub_key decodes to $BYTES bytes (expected 32)"
  exit 1
fi

# Client block
BLOCK=$(awk -v n="$CLIENT_NUM" '
  /# Client #/ {
    if (found) exit
    if ($0 ~ "# Client #" n " " || $0 ~ "# Client #" n "$") found = 1
    next
  }
  found { print }
' "$KEYS_FILE")

PRIVATE_KEY=$(echo "$BLOCK" | grep "private_key" | sed -n 's/.*= *"\([^"]*\)".*/\1/p' | trim_key)
CLIENT_PUB=$(echo "$BLOCK" | grep "server_pub_key" | sed -n 's/.*= *"\([^"]*\)".*/\1/p' | trim_key)
[[ -z "$CLIENT_PUB" ]] && CLIENT_PUB="$SERVER_PUB_KEY"

if [[ -z "$PRIVATE_KEY" ]]; then
  fail "Could not parse private_key for Client #$CLIENT_NUM"
  exit 1
fi
BYTES=$(echo "$PRIVATE_KEY" | base64 -d 2>/dev/null | wc -c)
if [[ "$BYTES" -eq 32 ]]; then
  ok "private_key (Client #$CLIENT_NUM): ${#PRIVATE_KEY} chars, 32 bytes"
else
  fail "private_key decodes to $BYTES bytes (expected 32)"
  exit 1
fi

BYTES=$(echo "$CLIENT_PUB" | base64 -d 2>/dev/null | wc -c)
if [[ "$BYTES" -eq 32 ]]; then
  ok "server_pub_key (block): ${#CLIENT_PUB} chars, 32 bytes"
else
  fail "server_pub_key (block) decodes to $BYTES bytes (expected 32)"
  exit 1
fi

echo "---"
echo -e "${GREEN}client-keys.txt is valid. You can run ./generate-client-config.sh${NC}"
exit 0
