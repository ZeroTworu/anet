#!/usr/bin/env bash
# ==============================================================================
# Скрипт автоматической настройки маршрутизации Cloudflare WARP (wgcf-profile)
# для стабилизации соединения сервера ANet (WRTC) с инфраструктурой ВКС (Ktalk / JVB)
# ==============================================================================
set -euo pipefail

WG_IF="${WG_IF:-wgcf-profile}"
WG_CONF="/etc/wireguard/${WG_IF}.conf"
ANET_SUBNET="${ANET_SUBNET:-172.112.0.0/16}"
EXT_IF="${EXT_IF:-$(ip route show default | awk '/default/ {print $5; exit}')}"

if [ -z "$EXT_IF" ]; then
    EXT_IF="ens3"
fi

if [ ! -f "$WG_CONF" ]; then
    echo "[-] Не найден конфигурационный файл $WG_CONF!"
    echo "    Сгенерируйте профиль wgcf (wgcf register && wgcf generate)"
    echo "    и скопируйте wgcf-profile.conf в $WG_CONF."
    exit 1
fi

echo "[1/6] Обновляем конфигурацию $WG_CONF (Table = off и штатный для WARP MTU = 1280)..."
sed -i '/^[[:space:]]*Table[[:space:]]*=/Id' "$WG_CONF"
sed -i '/^[[:space:]]*MTU[[:space:]]*=/Id' "$WG_CONF"
sed -i '/^\[Interface\]/a Table = off\nMTU = 1280' "$WG_CONF"

echo "[2/6] Перезапускаем интерфейс $WG_IF и очищаем старые правила маршрутизации..."
wg-quick down "$WG_IF" 2>/dev/null || true
wg-quick up "$WG_IF"

while ip -4 rule del not fwmark 51820 table 51820 2>/dev/null; do :; done
while ip -6 rule del not fwmark 51820 table 51820 2>/dev/null; do :; done
while ip -4 rule del table 100 2>/dev/null; do :; done
ip route flush table 100 2>/dev/null || true

echo "[3/6] Настраиваем MTU 1280, txqueuelen и планировщик fq_codel на $WG_IF..."
ip link set dev "$WG_IF" mtu 1280 txqueuelen 1000 up
tc qdisc replace dev "$WG_IF" root fq_codel

echo "[4/6] Включаем IPv4 forwarding и режим loose rp_filter для асимметричных маршрутов..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null
sysctl -w "net.ipv4.conf.${WG_IF}.rp_filter=2" >/dev/null
sysctl -w "net.ipv4.conf.${EXT_IF}.rp_filter=2" >/dev/null

echo "[5/6] Настраиваем таблицу маршрутизации 100 для подсетей ВКС и медиамостов JVB через WARP..."
ip route replace default dev "$WG_IF" table 100

# Целевые подсети инфраструктуры Контур.Толк (AS49675) и облачных медиамостов JVB / STUN / TURN
KTALK_CIDRS=(
    "46.17.200.0/21"
    "89.169.16.0/24"
    "84.201.128.0/18"
    "51.250.0.0/17"
    "158.160.0.0/16"
    "130.193.32.0/19"
    "178.154.128.0/17"
    "91.209.56.0/22"
    "91.197.180.0/23"
    "193.160.208.0/22"
    "193.232.166.0/24"
)

for cidr in "${KTALK_CIDRS[@]}"; do
    ip -4 rule add to "$cidr" table 100 priority 100
done

ip route flush cache

echo "[6/6] Настраиваем iptables (FORWARD для anet+, NAT на ${EXT_IF} + ${WG_IF} и TCP MSS Clamping)..."
# Разрешаем прохождение пакетов между TUN-интерфейсом (anet-test / anet-server) и внешними интерфейсами
iptables -D FORWARD -i anet+ -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o anet+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -I FORWARD 1 -i anet+ -j ACCEPT
iptables -I FORWARD 2 -o anet+ -m state --state RELATED,ESTABLISHED -j ACCEPT

# Маскарадинг клиентского трафика из туннельной подсети ANet на основном интерфейсе
iptables -t nat -D POSTROUTING -s "$ANET_SUBNET" -o "$EXT_IF" -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s "$ANET_SUBNET" -o "$EXT_IF" -j MASQUERADE

# Маскарадинг пакетов, уходящих в интерфейс Cloudflare WARP
iptables -t nat -D POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE

# Зажатие TCP MSS для исключения фрагментации пакетов внутри туннеля с MTU 1280
iptables -t mangle -D OUTPUT -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160 2>/dev/null || true
iptables -t mangle -D OUTPUT -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1080 2>/dev/null || true
iptables -t mangle -I OUTPUT 1 -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1080

iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "[+] Настройка завершена. Проверка маршрута до медиамоста JVB (89.169.16.6):"
ip route get 89.169.16.6 || true
