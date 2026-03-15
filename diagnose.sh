#!/usr/bin/env bash
# ============================================================================
# ANet VPN Server — Diagnostics
# Checks container, network, TUN, iptables, config, and logs
# Usage: ./diagnose.sh
# ============================================================================
set -uo pipefail

# ── colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()     { echo -e "  ${GREEN}✔${NC} $*"; PASS=$((PASS+1)); }
fail()   { echo -e "  ${RED}✘${NC} $*"; FAIL=$((FAIL+1)); }
warn()   { echo -e "  ${YELLOW}!${NC} $*"; WARN_N=$((WARN_N+1)); }
header() { echo -e "\n${CYAN}── $* ──${NC}"; }

PASS=0; FAIL=0; WARN_N=0
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/server/server.toml"

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   ANet VPN Server — Diagnostics          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo "  Host:   $(hostname 2>/dev/null || echo unknown)"
echo "  Kernel: $(uname -r 2>/dev/null || echo unknown)"
echo "  Date:   $(date -u '+%Y-%m-%d %H:%M UTC')"

# ════════════════════════════════════════════════════════════════════════════
header "1. Docker"
# ════════════════════════════════════════════════════════════════════════════

if command -v docker &>/dev/null; then
  ok "Docker installed: $(docker --version | awk '{print $3}' | tr -d ',')"
else
  fail "Docker not found"
fi

if docker info &>/dev/null; then
  ok "Docker daemon is reachable"
else
  fail "Cannot connect to Docker daemon"
fi

# Container status
CONTAINER_STATUS=$(docker ps -a --filter "name=anet-server" --format '{{.Status}}' 2>/dev/null || echo "")
if [[ -z "$CONTAINER_STATUS" ]]; then
  fail "Container 'anet-server' does not exist (run: docker compose up -d)"
elif echo "$CONTAINER_STATUS" | grep -qi "up"; then
  UPTIME=$(echo "$CONTAINER_STATUS" | head -1)
  ok "Container running: $UPTIME"
else
  fail "Container exists but not running: $CONTAINER_STATUS"
  echo "      Try: docker compose up -d"
fi

# Image
if docker image inspect anet-server:latest &>/dev/null; then
  IMAGE_SIZE=$(docker image inspect anet-server:latest --format '{{.Size}}' 2>/dev/null || echo "?")
  IMAGE_MB=$((IMAGE_SIZE / 1048576))
  ok "Image anet-server:latest (${IMAGE_MB} MB)"
else
  warn "Image anet-server:latest not found (run: docker compose build)"
fi

# ════════════════════════════════════════════════════════════════════════════
header "2. Configuration"
# ════════════════════════════════════════════════════════════════════════════

if [[ -f "$CONFIG" ]]; then
  ok "server.toml exists: $CONFIG"
else
  fail "server.toml not found at $CONFIG"
fi

if [[ -f "$CONFIG" ]]; then
  # Check crypto keys
  SIGNING_KEY=$(grep 'server_signing_key' "$CONFIG" 2>/dev/null | grep -oP '"[^"]+"' | tr -d '"')
  if [[ -n "$SIGNING_KEY" && "$SIGNING_KEY" != "" ]]; then
    ok "server_signing_key is set (${#SIGNING_KEY} chars)"
  else
    fail "server_signing_key is empty"
  fi

  # Check QUIC cert
  if grep -q 'BEGIN CERTIFICATE' "$CONFIG" 2>/dev/null; then
    ok "quic_cert contains a certificate"
  else
    fail "quic_cert is missing or placeholder"
  fi

  # Check QUIC key
  if grep -q 'BEGIN PRIVATE KEY' "$CONFIG" 2>/dev/null || grep -q 'BEGIN RSA PRIVATE KEY' "$CONFIG" 2>/dev/null; then
    ok "quic_key contains a private key"
  else
    fail "quic_key is missing or placeholder"
  fi

  # Check allowed_clients
  CLIENT_COUNT=$(grep -cP '"[A-Za-z0-9+/=]{10,}"' "$CONFIG" 2>/dev/null || echo 0)
  # Subtract keys that are not fingerprints (signing_key, cert lines)
  FINGERPRINTS=$(awk '/allowed_clients/,/]/' "$CONFIG" 2>/dev/null | grep -cP '"[A-Za-z0-9+/=]{10,}"' || echo 0)
  if [[ "$FINGERPRINTS" -gt 0 ]]; then
    ok "allowed_clients: $FINGERPRINTS client(s) configured"
  else
    warn "allowed_clients is empty — no clients will be able to connect"
  fi

  # Check external_if
  EXT_IF=$(grep 'external_if' "$CONFIG" 2>/dev/null | grep -oP '"[^"]+"' | tr -d '"')
  if [[ -n "$EXT_IF" ]]; then
    if ip link show "$EXT_IF" &>/dev/null; then
      ok "external_if = \"$EXT_IF\" (interface exists)"
    else
      fail "external_if = \"$EXT_IF\" but interface NOT found on host"
      echo "      Available interfaces: $(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')"
    fi
  else
    warn "external_if not set in config"
  fi

  # Check bind port
  BIND_TO=$(grep 'bind_to' "$CONFIG" 2>/dev/null | grep -oP '"[^"]+"' | tr -d '"')
  if [[ -n "$BIND_TO" ]]; then
    ok "bind_to = \"$BIND_TO\""
    BIND_PORT=$(echo "$BIND_TO" | grep -oP ':\K[0-9]+')
  else
    BIND_PORT="8443"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════
header "3. Network"
# ════════════════════════════════════════════════════════════════════════════

# UDP port
if ss -ulnp 2>/dev/null | grep -q ":${BIND_PORT:-8443} "; then
  PROC=$(ss -ulnp 2>/dev/null | grep ":${BIND_PORT:-8443} " | head -1)
  ok "Port ${BIND_PORT:-8443}/UDP is listening"
  echo "      $PROC"
else
  fail "Port ${BIND_PORT:-8443}/UDP is NOT listening"
fi

# TUN interface
TUN_NAME=$(grep 'if_name' "$CONFIG" 2>/dev/null | grep -oP '"[^"]+"' | tr -d '"' || echo "anet-server")
if ip link show "$TUN_NAME" &>/dev/null 2>&1; then
  TUN_IP=$(ip addr show "$TUN_NAME" 2>/dev/null | grep 'inet ' | awk '{print $2}')
  ok "TUN interface '$TUN_NAME' exists (IP: ${TUN_IP:-none})"
else
  warn "TUN interface '$TUN_NAME' not found (normal if no clients connected yet)"
fi

# Default route
DEFAULT_GW=$(ip route show default 2>/dev/null | head -1 || echo "none")
ok "Default route: $DEFAULT_GW"

# ip_forward
IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "?")
if [[ "$IP_FWD" == "1" ]]; then
  ok "IPv4 forwarding enabled"
else
  warn "IPv4 forwarding is OFF (ip_forward=$IP_FWD) — server enables it on client connect"
fi

# ════════════════════════════════════════════════════════════════════════════
header "4. Firewall / NAT"
# ════════════════════════════════════════════════════════════════════════════

# Check iptables MASQUERADE
if command -v iptables &>/dev/null; then
  NAT_RULES=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -i masquerade || echo "")
  if [[ -n "$NAT_RULES" ]]; then
    ok "MASQUERADE rules found in iptables:"
    echo "$NAT_RULES" | while read -r line; do echo "      $line"; done
  else
    warn "No MASQUERADE rules in iptables (server adds them on client connect)"
  fi
else
  warn "iptables not found on host"
fi

# Check if UFW / firewalld might block
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
  UFW_PORT=$(ufw status 2>/dev/null | grep "${BIND_PORT:-8443}" || echo "")
  if [[ -n "$UFW_PORT" ]]; then
    ok "UFW: port ${BIND_PORT:-8443} rule found"
  else
    warn "UFW is active but no rule for port ${BIND_PORT:-8443}/udp"
    echo "      Fix: sudo ufw allow ${BIND_PORT:-8443}/udp"
  fi
fi

if command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then
  FWD_PORT=$(firewall-cmd --list-ports 2>/dev/null | grep "${BIND_PORT:-8443}" || echo "")
  if [[ -n "$FWD_PORT" ]]; then
    ok "firewalld: port ${BIND_PORT:-8443} is open"
  else
    warn "firewalld is running but port ${BIND_PORT:-8443}/udp may not be open"
    echo "      Fix: sudo firewall-cmd --add-port=${BIND_PORT:-8443}/udp --permanent && sudo firewall-cmd --reload"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════
header "5. Container logs (last 30 lines)"
# ════════════════════════════════════════════════════════════════════════════

if docker ps -a --filter "name=anet-server" --format '{{.Names}}' 2>/dev/null | grep -q anet-server; then
  LOGS=$(docker compose logs --tail 30 anet-server 2>/dev/null || docker logs --tail 30 anet-server 2>/dev/null || echo "(could not read logs)")

  # Check for common errors
  ERROR_COUNT=$(echo "$LOGS" | grep -ciE 'error|panic|fatal|invalid' || true)
  ERROR_COUNT=${ERROR_COUNT:-0}

  if [[ "$ERROR_COUNT" -gt 0 ]]; then
    fail "Found $ERROR_COUNT error line(s) in recent logs:"
    echo "$LOGS" | grep -iE 'error|panic|fatal|invalid' | tail -5 | while read -r line; do
      echo -e "      ${RED}$line${NC}"
    done
  else
    ok "No errors in recent logs"
  fi

  echo ""
  echo "$LOGS" | tail -15 | while read -r line; do echo "  $line"; done
else
  warn "Container not found — cannot read logs"
fi

# ════════════════════════════════════════════════════════════════════════════
header "6. Connectivity test"
# ════════════════════════════════════════════════════════════════════════════

# External IP
EXT_IP=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || echo "")
if [[ -n "$EXT_IP" ]]; then
  ok "External IP: $EXT_IP"
else
  warn "Could not determine external IP (no internet or curl not installed)"
fi

# DNS
if nslookup google.com &>/dev/null 2>&1 || host google.com &>/dev/null 2>&1; then
  ok "DNS resolution works"
else
  warn "DNS resolution failed (may not affect server operation)"
fi

# ════════════════════════════════════════════════════════════════════════════
header "Summary"
# ════════════════════════════════════════════════════════════════════════════

echo -e "  ${GREEN}Passed:${NC}  $PASS"
echo -e "  ${YELLOW}Warnings:${NC} $WARN_N"
echo -e "  ${RED}Failed:${NC}  $FAIL"
echo ""

if [[ $FAIL -eq 0 ]]; then
  echo -e "  ${GREEN}All critical checks passed.${NC}"
else
  echo -e "  ${RED}There are $FAIL failed check(s) — review output above.${NC}"
fi
echo ""
