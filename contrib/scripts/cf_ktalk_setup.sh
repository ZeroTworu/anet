#!/usr/bin/env bash
# ==============================================================================
# Универсальный скрипт установки и настройки Cloudflare WARP (wgcf)
# для селективной маршрутизации инфраструктуры Контур.Толк / JVB на сервере ANet.
#
# Возможности:
#   1. Автоматическая установка зависимостей (wireguard-tools, iproute2,
#      iptables, iptables-persistent, curl, jq) и бинарника wgcf.
#   2. Автоматическая регистрация аккаунта Cloudflare WARP и генерация
#      профиля /etc/wireguard/wgcf-profile.conf (если он ещё не создан).
#   3. Настройка split-tunneling (Table = off, MTU = 1280) без перехвата
#      основного входящего/исходящего трафика сервера.
#   4. Маршрутизация подсетей Контур.Толк (AS49675, TURN/STUN, медиамосты JVB
#      и облачные узлы) через интерфейс wgcf-profile с явным зажатием
#      маршрутного MTU = 1240 и advmss = 1160 (защита от зависаний TLS 1.3
#      BoringSSL с постквантовым гибридным ключом X25519MLKEM768).
#   5. Полная настройка sysctl (ip_forward=1, loose rp_filter=2), дисциплины
#      очереди fq_codel, NAT (MASQUERADE на основной интерфейс и wgcf-profile),
#      двустороннего TCP MSS Clamping и отключения транзитного QUIC (UDP:443).
#   6. Полная персистентность после перезагрузки сервера (PostUp/PostDown хук
#      в WireGuard + systemd wg-quick@wgcf-profile + /etc/sysctl.d +
#      netfilter-persistent).
# ==============================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Ошибка: скрипт необходимо запускать от имени root (sudo)." >&2
    exit 1
fi

WG_IF="${WG_IF:-wgcf-profile}"
WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/${WG_IF}.conf"
HOOK_SCRIPT="${WG_DIR}/anet-warp-ktalk-hook.sh"
SYSCTL_CONF="/etc/sysctl.d/99-anet-warp-ktalk.conf"
ANET_SUBNET="${ANET_SUBNET:-172.112.0.0/16}"

# Автоопределение основного внешнего сетевого интерфейса (например, ens3 / eth0)
WAN_IF="${WAN_IF:-$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')}"
if [ -z "$WAN_IF" ]; then
    WAN_IF="ens3"
fi

echo "======================================================================"
echo "[*] Настройка Cloudflare WARP + селективной маршрутизации для ANet"
echo "    Основной WAN-интерфейс : ${WAN_IF}"
echo "    Интерфейс WireGuard    : ${WG_IF}"
echo "    Подсеть туннеля ANet   : ${ANET_SUBNET}"
echo "======================================================================"

# ------------------------------------------------------------------------------
# Шаг 1. Установка системных пакетов и утилиты wgcf
# ------------------------------------------------------------------------------
echo "[1/7] Проверка и установка системных зависимостей..."
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        wireguard-tools \
        iproute2 \
        iptables \
        iptables-persistent \
        netfilter-persistent \
        curl \
        ca-certificates \
        jq >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q wireguard-tools iproute iptables iptables-services curl ca-certificates jq >/dev/null
elif command -v yum >/dev/null 2>&1; then
    yum install -y -q wireguard-tools iproute iptables iptables-services curl ca-certificates jq >/dev/null
fi

if ! command -v wgcf >/dev/null 2>&1; then
    echo "[*] Утилита wgcf не найдена. Скачиваем последний релиз ViRb3/wgcf..."
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64) WGCF_ARCH="amd64" ;;
        aarch64|arm64) WGCF_ARCH="arm64" ;;
        armv7l) WGCF_ARCH="armv7" ;;
        *)
            echo "[-] Неподдерживаемая архитектура процессора: $ARCH" >&2
            exit 1
            ;;
    esac

    WGCF_URL="$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest 2>/dev/null \
        | jq -r ".assets[] | select(.name | test(\"linux_${WGCF_ARCH}$\"; \"i\")) | .browser_download_url" \
        | head -n 1 || true)"

    if [ -z "$WGCF_URL" ] || [ "$WGCF_URL" = "null" ]; then
        WGCF_URL="https://github.com/ViRb3/wgcf/releases/download/v2.2.29/wgcf_2.2.29_linux_${WGCF_ARCH}"
    fi

    curl -fsSL "$WGCF_URL" -o /usr/local/bin/wgcf
    chmod +x /usr/local/bin/wgcf
    echo "[+] Установлен /usr/local/bin/wgcf ($(wgcf --version 2>/dev/null || echo 'ok'))"
fi

# ------------------------------------------------------------------------------
# Шаг 2. Генерация профиля /etc/wireguard/wgcf-profile.conf (если отсутствует)
# ------------------------------------------------------------------------------
mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

if [ ! -f "$WG_CONF" ]; then
    echo "[2/7] Профиль $WG_CONF не найден. Регистрируем аккаунт Cloudflare WARP..."
    WGCF_WORK_DIR="${WG_DIR}/wgcf-account"
    mkdir -p "$WGCF_WORK_DIR"
    pushd "$WGCF_WORK_DIR" >/dev/null

    if [ ! -f "wgcf-account.toml" ]; then
        wgcf register --accept-tos
    fi
    wgcf generate
    cp -f "wgcf-profile.conf" "$WG_CONF"
    chmod 600 "$WG_CONF"
    popd >/dev/null
    echo "[+] Сгенерирован профиль $WG_CONF"
else
    echo "[2/7] Используем существующий профиль $WG_CONF"
fi

# ------------------------------------------------------------------------------
# Шаг 3. Запись постоянных настроек ядра в /etc/sysctl.d/99-anet-warp-ktalk.conf
# ------------------------------------------------------------------------------
echo "[3/7] Записываем персистентные параметры sysctl в ${SYSCTL_CONF}..."
cat > "$SYSCTL_CONF" <<EOF
# Автоматически сгенерировано скриптом настройки ANet + Cloudflare WARP
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.${WAN_IF}.rp_filter = 2
EOF
sysctl --system >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# Шаг 4. Создание идемпотентного хук-скрипта PostUp/PostDown для WireGuard
# ------------------------------------------------------------------------------
echo "[4/7] Создаём хук маршрутизации и файрвола ${HOOK_SCRIPT}..."
cat > "$HOOK_SCRIPT" <<'EOF_HOOK'
#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-up}"
WG_IF="__WG_IF__"
WAN_IF="__WAN_IF__"
ANET_SUBNET="__ANET_SUBNET__"

# Полный список подсетей Контур.Толк (AS49675, TURN/STUN, балансировщики и облачные пулы JVB)
KTALK_SUBNETS=(
    "46.17.200.0/21"
    "89.169.16.0/20"
    "89.169.16.0/24"
    "45.130.11.0/24"
    "95.215.255.0/24"
    "91.209.56.0/22"
    "91.197.180.0/23"
    "193.160.208.0/22"
    "193.232.166.0/24"
    "195.88.208.0/23"
    "213.189.204.0/24"
    "84.201.128.0/18"
    "51.250.0.0/17"
    "158.160.0.0/16"
    "130.193.32.0/19"
    "178.154.128.0/17"
    "213.59.255.0/24"
)

cleanup_rules() {
    while ip -4 rule del not fwmark 51820 table 51820 2>/dev/null; do :; done
    while ip -6 rule del not fwmark 51820 table 51820 2>/dev/null; do :; done
    while ip -4 rule del table 100 2>/dev/null; do :; done
    ip route flush table 100 2>/dev/null || true
}

if [ "$ACTION" = "down" ]; then
    cleanup_rules
    ip route flush cache 2>/dev/null || true
    exit 0
fi

# 1. Очищаем старые правила таблиц маршрутизации
cleanup_rules

# 2. Настраиваем интерфейс WARP: MTU 1280, очередь txqueuelen 1000 и планировщик fq_codel
ip link set dev "$WG_IF" mtu 1280 txqueuelen 1000 up
tc qdisc replace dev "$WG_IF" root fq_codel 2>/dev/null || true

# 3. Включаем IPv4 forwarding и loose rp_filter=2 для асимметричной/полиси маршрутизации
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null
sysctl -w "net.ipv4.conf.${WG_IF}.rp_filter=2" >/dev/null 2>&1 || true
sysctl -w "net.ipv4.conf.${WAN_IF}.rp_filter=2" >/dev/null 2>&1 || true

# 4. Восстанавливаем link-scope маршрут собственного адреса интерфейса WARP
WG_IPV4="$(ip -4 -o addr show dev "$WG_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1)"
ip route flush dev "$WG_IF" 2>/dev/null || true
if [ -n "$WG_IPV4" ]; then
    ip route replace "${WG_IPV4}/32" dev "$WG_IF" scope link
fi

# 5. Заворачиваем все подсети Контур.Толк и медиамостов JVB в WARP
#    с явным зажатием маршрутного MTU 1240 и advmss 1160 (для безболезненного
#    прохождения постквантового TLS 1.3 ClientHello X25519MLKEM768)
ip route replace default dev "$WG_IF" mtu 1240 advmss 1160 table 100

for cidr in "${KTALK_SUBNETS[@]}"; do
    ip route replace "$cidr" dev "$WG_IF" scope link mtu 1240 advmss 1160
    ip -4 rule add to "$cidr" table 100 priority 100
done

ip route flush cache

# 6. Правила FORWARD для туннельных интерфейсов anet+ и отключение транзитного QUIC (UDP:443)
while iptables -D FORWARD -i anet+ -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do :; done
while iptables -D FORWARD -i anet+ -j ACCEPT 2>/dev/null; do :; done
while iptables -D FORWARD -o anet+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done

iptables -I FORWARD 1 -i anet+ -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD 2 -i anet+ -j ACCEPT
iptables -I FORWARD 3 -o anet+ -m state --state RELATED,ESTABLISHED -j ACCEPT

# 7. NAT (MASQUERADE) на основной интерфейс и на интерфейс WARP
while iptables -t nat -D POSTROUTING -s "$ANET_SUBNET" -o "$WAN_IF" -j MASQUERADE 2>/dev/null; do :; done
iptables -t nat -A POSTROUTING -s "$ANET_SUBNET" -o "$WAN_IF" -j MASQUERADE

while iptables -t nat -D POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null; do :; done
iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE

# 8. Двусторонний TCP MSS Clamping для локальных соединений (OUTPUT) и транзита (FORWARD)
for mss_val in 1160 1080; do
    while iptables -t mangle -D OUTPUT -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val" 2>/dev/null; do :; done
    while iptables -t mangle -D FORWARD -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val" 2>/dev/null; do :; done
    while iptables -t mangle -D FORWARD -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val" 2>/dev/null; do :; done
done
for mss_val in 1040 1000; do
    while iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val" 2>/dev/null; do :; done
    while iptables -t mangle -D FORWARD -i anet+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val" 2>/dev/null; do :; done
    while iptables -t mangle -D FORWARD -o anet+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val" 2>/dev/null; do :; done
done

iptables -t mangle -I OUTPUT 1 -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160
iptables -t mangle -I FORWARD 1 -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160
iptables -t mangle -I FORWARD 2 -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160
iptables -t mangle -I FORWARD 3 -i anet+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1040
iptables -t mangle -I FORWARD 4 -o anet+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1040
EOF_HOOK

sed -i "s|__WG_IF__|${WG_IF}|g" "$HOOK_SCRIPT"
sed -i "s|__WAN_IF__|${WAN_IF}|g" "$HOOK_SCRIPT"
sed -i "s|__ANET_SUBNET__|${ANET_SUBNET}|g" "$HOOK_SCRIPT"
chmod 700 "$HOOK_SCRIPT"

# ------------------------------------------------------------------------------
# Шаг 5. Патчинг /etc/wireguard/wgcf-profile.conf (Table = off, MTU = 1280, PostUp/PostDown)
# ------------------------------------------------------------------------------
echo "[5/7] Обновляем конфигурацию ${WG_CONF} (Table = off, MTU = 1280, PostUp/PostDown)..."
sed -i '/^[[:space:]]*Table[[:space:]]*=/Id' "$WG_CONF"
sed -i '/^[[:space:]]*MTU[[:space:]]*=/Id' "$WG_CONF"
sed -i '/^[[:space:]]*PostUp[[:space:]]*=/Id' "$WG_CONF"
sed -i '/^[[:space:]]*PostDown[[:space:]]*=/Id' "$WG_CONF"
sed -i "/^\[Interface\]/a Table = off\nMTU = 1280\nPostUp = ${HOOK_SCRIPT} up\nPostDown = ${HOOK_SCRIPT} down" "$WG_CONF"
chmod 600 "$WG_CONF"

# ------------------------------------------------------------------------------
# Шаг 6. Перезапуск интерфейса, включение автозапуска systemd и сохранение iptables
# ------------------------------------------------------------------------------
echo "[6/7] Перезапускаем сервис wg-quick@${WG_IF} и сохраняем правила..."
wg-quick down "$WG_IF" 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@${WG_IF}.service"
else
    wg-quick up "$WG_IF"
fi

# Гарантированно вызываем хук ещё раз на случай нестандартного wg-quick
"$HOOK_SCRIPT" up

if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
elif [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# Шаг 7. Финальная диагностика
# ------------------------------------------------------------------------------
echo "[7/7] Проверяем маршрутизацию и соединение с Контур.Толк через WARP..."
echo "----------------------------------------------------------------------"
wg show "$WG_IF"
echo "----------------------------------------------------------------------"
ip route show dev "$WG_IF" | head -n 10
echo "----------------------------------------------------------------------"
if curl -I -s -m 8 https://ktalk.ru/ | head -n 5; then
    echo "[+] Успешно! Трафик к Контур.Толк маршрутизируется через ${WG_IF} и правила сохранены для автозапуска."
else
    echo "[!] Внимание: проверочный запрос curl к https://ktalk.ru/ не вернул заголовки за 8 с."
fi
