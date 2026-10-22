#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{
        bpf_ktime_get_ns, bpf_redirect_neigh, bpf_skb_adjust_room, bpf_skb_pull_data,
        bpf_skb_set_tstamp, bpf_xdp_adjust_head,
    },
    macros::{classifier, map, xdp},
    maps::HashMap,
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use aya_log_ebpf::debug;

use anet_ebpf_common::{
    AstplConfig, EdtState, EgressRoutingData, IngressSessionData, RateRule, TokenBucketState,
    ASTPL_ENCAP_LEN,
};

mod ip;
use ip::{
    ipv4_header_checksum, parse_dst_ipv4, parse_src_ipv4, xoroshiro_crypt_packet, ContextWrapper,
    EthHdr, Ipv4Hdr, UdpHdr, ETH_P_IP_BE, IPPROTO_ICMP, IPPROTO_UDP,
};

/// `BPF_SKB_TSTAMP_DELIVERY_MONO` из `enum bpf_skb_tstamp_type` ядра
/// (include/uapi/linux/bpf.h). В сгенерированных биндингах aya-ebpf 0.1.1
/// (`aya_ebpf::bindings`) этот enum отсутствует, поэтому значение
/// захардкожено — это стабильный UAPI ядра, он не меняется между релизами.
const BPF_SKB_TSTAMP_DELIVERY_MONO: u32 = 1;

/// Стабильные UAPI-константы ядра Linux (`include/uapi/linux/bpf.h`) для `bpf_skb_adjust_room`.
const BPF_ADJ_ROOM_NET: u32 = 0;
const BPF_F_ADJ_ROOM_FIXED_GSO: u64 = 1 << 0;
const BPF_F_ADJ_ROOM_ENCAP_L3_IPV4: u64 = 1 << 1;
const BPF_F_ADJ_ROOM_ENCAP_L4_UDP: u64 = 1 << 3;

/// Идентификатор внутритуннельного ICMP-зонда ANet (`0x414E`, "AN") в сетевом порядке байт.
const ANET_PROBE_IDENT_BE: u16 = 0x414Eu16.to_be();

/// Глобальные константы для `override_global` / `set_global` (резервный источник конфигурации).
#[unsafe(no_mangle)]
static ASTPL_PORT: u16 = 0;
#[unsafe(no_mangle)]
static SERVER_IP: u32 = 0;
#[unsafe(no_mangle)]
static ETH_IFINDEX: u32 = 0;

/// Правила ограничения скорости. Ключ — IPv4 клиента внутри туннельной сети
/// (`assigned_ip`) в сетевом (big-endian) порядке байт. Заполняется/чистится
/// из `anet-server::shaper::Shaper` по мере жизни клиентских сессий.
#[map(name = "RATE_RULES")]
static RATE_RULES: HashMap<u32, RateRule> = HashMap::with_max_entries(4096, 0);

/// EDT-состояние для egress (download клиента: интернет -> клиент).
#[map(name = "EDT_STATE")]
static EDT_STATE: HashMap<u32, EdtState> = HashMap::with_max_entries(4096, 0);

/// Token-Bucket состояние для ingress (upload клиента: клиент -> интернет).
#[map(name = "TB_STATE")]
static TB_STATE: HashMap<u32, TokenBucketState> = HashMap::with_max_entries(4096, 0);

/// Глобальная конфигурация транспорта ASTP-L (ключ `0`).
#[map(name = "ASTPL_CONFIG")]
static ASTPL_CONFIG: HashMap<u32, AstplConfig> = HashMap::with_max_entries(1, 0);

/// Таблица входящих сессий ASTP-L для XDP на физическом интерфейсе (`eth0`).
/// Ключ — `nonce_prefix: u32` (Big-Endian, первые 4 байта UDP payload).
#[map(name = "ASTPL_INGRESS_MAP")]
static ASTPL_INGRESS_MAP: HashMap<u32, IngressSessionData> = HashMap::with_max_entries(4096, 0);

/// Таблица исходящей маршрутизации ASTP-L для TC Egress на `tun0`.
/// Ключ — внутренний VPN IPv4 клиента (`assigned_ip: u32`, Big-Endian).
#[map(name = "ASTPL_EGRESS_MAP")]
static ASTPL_EGRESS_MAP: HashMap<u32, EgressRoutingData> = HashMap::with_max_entries(4096, 0);

#[inline(always)]
fn load_astpl_config() -> AstplConfig {
    let key = 0u32;
    if let Some(cfg) = unsafe { ASTPL_CONFIG.get(&key) } {
        return *cfg;
    }
    unsafe {
        AstplConfig {
            astpl_port_be: core::ptr::read_volatile(&ASTPL_PORT),
            _pad: 0,
            server_ip_be: core::ptr::read_volatile(&SERVER_IP),
            eth_ifindex: core::ptr::read_volatile(&ETH_IFINDEX),
            _pad2: 0,
        }
    }
}

/// Проверка Token Bucket для upload-трафика клиента (`src_ip` в Big-Endian).
/// Возвращает `true`, если пакет разрешён, или `false`, если превышен лимит скорости.
#[inline(always)]
fn check_upload_token_bucket(src_ip: u32, packet_len: i64, now: u64) -> bool {
    let Some(rule) = (unsafe { RATE_RULES.get(&src_ip) }) else {
        return true;
    };

    if rule.rate_bytes_per_sec == 0 {
        return true;
    }

    let mut state = match unsafe { TB_STATE.get(&src_ip) } {
        Some(state) => *state,
        None => TokenBucketState {
            tokens: rule.burst_bytes as i64,
            last_update_ns: now,
        },
    };

    let elapsed_ns = now.saturating_sub(state.last_update_ns).min(1_000_000_000);
    let refill = ((rule.rate_bytes_per_sec * elapsed_ns) / 1_000_000_000) as i64;

    state.tokens = state.tokens.saturating_add(refill).min(rule.burst_bytes as i64);
    state.last_update_ns = now;

    let allowed = if state.tokens >= packet_len {
        state.tokens -= packet_len;
        true
    } else {
        false
    };

    let _ = TB_STATE.insert(&src_ip, &state, 0);
    allowed
}

/// EDT egress classifier. Вешается на `clsact egress` TUN-интерфейса сервера
/// (см. `anet-server::shaper::Shaper::attach`). TUN-egress — это пакеты,
/// которые ядро отдаёт обратно клиенту, т.е. download с его точки зрения.
///
/// Реализация без потерь: считаем момент, когда пакет МОЖЕТ уйти (Earliest
/// Departure Time), пишем его в `skb->tstamp` — фактическую задержку и
/// порядок отправки берёт на себя qdisc `fq`, который ОБЯЗАН стоять как root
/// qdisc интерфейса, иначе `tstamp` тихо игнорируется и пакет уйдёт сразу.
#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(&ctx) {
        Ok(action) => action,
        Err(()) => TC_ACT_OK,
    }
}

fn try_tc_egress(ctx: &TcContext) -> Result<i32, ()> {
    let Some(dst_ip) = parse_dst_ipv4(ctx) else {
        return Ok(TC_ACT_OK);
    };

    // Если для клиента задан лимит скорости — применяем EDT-пейсинг перед отправкой.
    if let Some(rule) = unsafe { RATE_RULES.get(&dst_ip) } {
        if rule.rate_bytes_per_sec > 0 {
            let packet_len = ctx.len() as u64;
            let now = unsafe { bpf_ktime_get_ns() };

            let scheduled_from = match unsafe { EDT_STATE.get(&dst_ip) } {
                Some(state) => state.next_departure_ns.max(now),
                None => now,
            };

            // 10^9 * packet_len (максимум ~65535) = ~6.5 * 10^13, что с запасом
            // укладывается в u64 (предел u64: 1.84 * 10^19). 128-битная арифметика не требуется.
            let cost_ns = (1_000_000_000u64 * packet_len) / rule.rate_bytes_per_sec;
            let next_departure = scheduled_from.saturating_add(cost_ns);

            // Ограничиваем глубину виртуального буфера очереди размером burst_bytes.
            // Если время отправки пакета (next_departure) выходит за пределы горизонта планирования
            // (horizon), это сигнализирует о переполнении буфера шейпера.
            let safe_burst = rule.burst_bytes.max(1).min(1_000_000_000);
            let max_horizon_ns = (1_000_000_000u64 * safe_burst) / rule.rate_bytes_per_sec;
            let horizon = now.saturating_add(max_horizon_ns.max(cost_ns));
            if next_departure > horizon {
                return Ok(TC_ACT_SHOT);
            }

            let _ = EDT_STATE.insert(
                &dst_ip,
                &EdtState {
                    next_departure_ns: next_departure,
                },
                0,
            );

            // ВНИМАНИЕ: bpf_skb_set_tstamp — helper, появившийся в Linux 5.18
            // (BPF_FUNC_skb_set_tstamp).
            unsafe {
                let _ = bpf_skb_set_tstamp(
                    ctx.as_ptr() as *mut _,
                    next_departure,
                    BPF_SKB_TSTAMP_DELIVERY_MONO,
                );
            }

            debug!(
                ctx,
                "tc_egress: dst={:i}, next_departure_ns={}", dst_ip, next_departure
            );
        }
    }

    // Если клиент подключён по протоколу ASTP-L и его маршрут присутствует в ASTPL_EGRESS_MAP,
    // сразу выполняем инкапсуляцию и редирект в физический интерфейс.
    try_astpl_tc_egress(ctx)
}

/// Программа TC Classifier для инкапсуляции исходящих пакетов ASTP-L на `tun0`.
/// Может прикрепляться как самостоятельно (`astpl_tc_egress`), так и вызываться
/// из цепочки `tc_egress` при совместной работе с `Shaper`.
#[classifier]
pub fn astpl_tc_egress(ctx: TcContext) -> i32 {
    match try_astpl_tc_egress(&ctx) {
        Ok(action) => action,
        Err(()) => TC_ACT_OK,
    }
}

fn try_astpl_tc_egress(ctx: &TcContext) -> Result<i32, ()> {
    let w_init = ContextWrapper::Tc(ctx);
    let inner_ip = w_init.read_unaligned::<Ipv4Hdr>(0)?;
    if inner_ip.version() != 4 {
        return Ok(TC_ACT_OK);
    }

    // В `Ipv4Hdr` поле `dst_addr` лежит в сетевом порядке байт (Big-Endian),
    // как и ключ в `ASTPL_EGRESS_MAP`.
    let inner_dst_ip = inner_ip.dst_addr;
    let Some(routing_ptr) = ASTPL_EGRESS_MAP.get_ptr_mut(&inner_dst_ip) else {
        return Ok(TC_ACT_OK);
    };

    let cfg = load_astpl_config();
    if cfg.astpl_port_be == 0 || cfg.server_ip_be == 0 || cfg.eth_ifindex == 0 {
        return Ok(TC_ACT_OK);
    }

    // КРИТИЧНО для TC: линеаризуем буфер sk_buff перед in-place шифрованием,
    // чтобы все фрагменты страницы (paged frags) оказались в линейной области data..data_end.
    let pull_ret = unsafe { bpf_skb_pull_data(ctx.as_ptr() as *mut _, 0) };
    if pull_ret < 0 {
        return Ok(TC_ACT_OK);
    }

    let w_plain = ContextWrapper::Tc(ctx);
    let inner_len = w_plain.data_end().saturating_sub(w_plain.data());
    if inner_len < Ipv4Hdr::LEN {
        return Ok(TC_ACT_OK);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let (crypto_seed, dst_ip, dst_port, nonce_prefix, tx_seq) = unsafe {
        let routing = &mut *routing_ptr;
        if routing.dst_ip == 0 || routing.dst_port == 0 {
            return Ok(TC_ACT_OK);
        }
        let mut next_seq = routing.tx_seq.wrapping_add(1);
        if next_seq == 0 {
            next_seq = 1;
        }
        routing.tx_seq = next_seq;
        routing.tx_bytes = routing.tx_bytes.saturating_add(inner_len as u64);
        routing.last_seen_ns = now;
        (
            routing.crypto_seed,
            routing.dst_ip,
            routing.dst_port,
            routing.nonce_prefix,
            next_seq,
        )
    };

    // Шифруем внутренний IPv4-пакет на месте (0 .. data_end)
    xoroshiro_crypt_packet(&w_plain, 0, crypto_seed, tx_seq)?;

    // Раздвигаем начало пакета на 36 байт под Outer IPv4 (20) + Outer UDP (8) + ASTP-L Header (8)
    let flags =
        BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    let adj_ret = unsafe {
        bpf_skb_adjust_room(
            ctx.as_ptr() as *mut _,
            ASTPL_ENCAP_LEN as i32,
            BPF_ADJ_ROOM_NET,
            flags,
        )
    };
    if adj_ret < 0 {
        return Ok(TC_ACT_SHOT);
    }

    // После bpf_skb_adjust_room старые указатели недействительны — создаём новую обёртку
    let w_encap = ContextWrapper::Tc(ctx);
    let total_ip_len = w_encap.data_end().saturating_sub(w_encap.data());
    if total_ip_len < ASTPL_ENCAP_LEN + Ipv4Hdr::LEN {
        return Ok(TC_ACT_SHOT);
    }
    let udp_total_len = total_ip_len - Ipv4Hdr::LEN;

    let mut outer_ip = Ipv4Hdr {
        version_ihl: 0x45,
        tos: 0,
        tot_len: (total_ip_len as u16).to_be(),
        id: (tx_seq as u16).to_be(),
        frag_off: 0x4000u16.to_be(), // Don't Fragment (DF)
        ttl: 64,
        proto: IPPROTO_UDP,
        check: 0,
        src_addr: cfg.server_ip_be,
        dst_addr: dst_ip,
    };
    outer_ip.check = ipv4_header_checksum(&outer_ip);

    let outer_udp = UdpHdr {
        source: cfg.astpl_port_be,
        dest: dst_port,
        len: (udp_total_len as u16).to_be(),
        check: 0, // UDP checksum 0 валиден для IPv4 (RFC 768)
    };

    w_encap.write_unaligned::<Ipv4Hdr>(0, outer_ip)?;
    w_encap.write_unaligned::<UdpHdr>(Ipv4Hdr::LEN, outer_udp)?;
    w_encap.write_unaligned::<u32>(Ipv4Hdr::LEN + UdpHdr::LEN, nonce_prefix)?;
    w_encap.write_unaligned::<u32>(Ipv4Hdr::LEN + UdpHdr::LEN + 4, tx_seq.to_be())?;

    // Отправляем зашифрованный UDP-пакет напрямую в физический интерфейс через подсистему соседей (ARP/Neighbour)
    let action =
        unsafe { bpf_redirect_neigh(cfg.eth_ifindex, core::ptr::null_mut(), 0, 0) as i32 };
    Ok(action)
}

/// Программа XDP для декапсуляции входящих пакетов ASTP-L на физическом интерфейсе (`eth0`).
/// Выполняет:
/// 1. Демультиплексирование по 4-байтному `nonce_prefix` за O(1) (промах -> `XDP_PASS` в Userspace для Handshake / `DatagramReassembler`).
/// 2. Дешифрование `Xoroshiro128+` на месте и проверку инвариантов внутреннего IPv4-заголовка.
/// 3. Ядерный NAT Rebinding (обновление внешнего IP:Port клиента в `ASTPL_EGRESS_MAP` без участия Userspace).
/// 4. Декапсуляцию со сдвигом L2-заголовка (`bpf_xdp_adjust_head` на 36 байт) и передачу пакета в IP Forwarding ядра.
#[xdp]
pub fn astpl_xdp_ingress(ctx: XdpContext) -> u32 {
    match try_astpl_xdp_ingress(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_astpl_xdp_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let w = ContextWrapper::Xdp(ctx);

    // Минимальный размер кадра ASTP-L Data Plane:
    // Eth (14) + Outer IPv4 (20) + Outer UDP (8) + ASTP-L Header (8) + Inner IPv4 (20) = 70 байт
    const OUTER_HEADERS_LEN: usize = EthHdr::LEN + ASTPL_ENCAP_LEN; // 14 + 36 = 50 байт
    const MIN_ASTPL_FRAME_LEN: usize = OUTER_HEADERS_LEN + Ipv4Hdr::LEN; // 70 байт

    if w.data() + MIN_ASTPL_FRAME_LEN > w.data_end() {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth = w.read_unaligned::<EthHdr>(0)?;
    if eth.ether_type != ETH_P_IP_BE {
        return Ok(xdp_action::XDP_PASS);
    }

    let outer_ip = w.read_unaligned::<Ipv4Hdr>(EthHdr::LEN)?;
    if outer_ip.version() != 4 || outer_ip.ihl() != 5 || outer_ip.proto != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let cfg = load_astpl_config();
    if cfg.astpl_port_be == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let outer_udp = w.read_unaligned::<UdpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)?;
    if outer_udp.dest != cfg.astpl_port_be {
        return Ok(xdp_action::XDP_PASS);
    }

    // Читаем 8-байтный заголовок ASTP-L: [nonce_prefix: u32 (BE)][seq: u32 (BE)]
    let astpl_offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN; // 42
    let nonce_prefix = w.read_unaligned::<u32>(astpl_offset)?;
    let seq_be = w.read_unaligned::<u32>(astpl_offset + 4)?;
    let seq = u32::from_be(seq_be);

    // 1. Демультиплексирование Control Plane vs Data Plane за O(1):
    // Если `nonce_prefix` не найден в карте или `seq == 0` — это пакет Handshake (Phase I / Phase III),
    // UDP-фрагмент для `DatagramReassembler` или управляющий пакет сессии. Пропускаем в Userspace.
    let Some(session_ptr) = ASTPL_INGRESS_MAP.get_ptr_mut(&nonce_prefix) else {
        return Ok(xdp_action::XDP_PASS);
    };
    if seq == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let (crypto_seed, assigned_ip) = unsafe {
        let s = &*session_ptr;
        (s.crypto_seed, s.assigned_ip)
    };

    // 2. Расшифровываем внутренний IPv4-пакет на месте (offset 50 .. data_end)
    let inner_len = xoroshiro_crypt_packet(&w, OUTER_HEADERS_LEN, crypto_seed, seq)?;

    // 3. Проверяем криптографические инварианты расшифрованного внутреннего IPv4-заголовка:
    // - версия IPv4 == 4 и IHL >= 5
    // - полная длина внутреннего IPv4-пакета (tot_len) соответствует реальному размеру payload
    // - внутренний адрес источника строго равен выданному клиенту VPN IP (anti-spoofing)
    let inner_ip = w.read_unaligned::<Ipv4Hdr>(OUTER_HEADERS_LEN)?;
    let inner_tot_len = u16::from_be(inner_ip.tot_len) as usize;
    let valid_inner = inner_ip.version() == 4
        && inner_ip.ihl() >= 5
        && inner_tot_len >= Ipv4Hdr::LEN
        && inner_tot_len <= inner_len
        && inner_ip.src_addr == assigned_ip;

    if !valid_inner {
        // При случайной коллизии префикса (1 на 2^32) или невалидном пакете откатываем XOR обратно
        // и передаём пакет в Userspace без повреждения исходных байт.
        let _ = xoroshiro_crypt_packet(&w, OUTER_HEADERS_LEN, crypto_seed, seq);
        return Ok(xdp_action::XDP_PASS);
    }

    // 4. Бесшовная миграция адреса клиента в ядре (Kernel NAT Rebinding) и обновление счётчиков:
    let now = unsafe { bpf_ktime_get_ns() };
    let outer_src_ip = outer_ip.src_addr;
    let outer_src_port = outer_udp.source;

    unsafe {
        let s = &mut *session_ptr;
        s.rx_bytes = s.rx_bytes.saturating_add(inner_tot_len as u64);
        s.last_seq = seq;
        s.last_seen_ns = now;

        if s.client_ip != outer_src_ip || s.client_port != outer_src_port {
            s.client_ip = outer_src_ip;
            s.client_port = outer_src_port;
            if let Some(egress_ptr) = ASTPL_EGRESS_MAP.get_ptr_mut(&assigned_ip) {
                (*egress_ptr).dst_ip = outer_src_ip;
                (*egress_ptr).dst_port = outer_src_port;
            }
        }
    }

    // 5. Если пакет является внутритуннельным ICMP Echo Request зондом ANet (`ident == 0x414E`),
    // возвращаем исходное шифрование и отдаём `XDP_PASS` в Userspace-сокет `anet-server`,
    // чтобы сервер мгновенно сформировал Echo Reply independientemente от настроек IP/iptables на TUN.
    if inner_ip.proto == IPPROTO_ICMP
        && inner_ip.ihl() == 5
        && w.data() + OUTER_HEADERS_LEN + Ipv4Hdr::LEN + 8 <= w.data_end()
    {
        let icmp_type = w.read_unaligned::<u8>(OUTER_HEADERS_LEN + Ipv4Hdr::LEN)?;
        let icmp_ident = w.read_unaligned::<u16>(OUTER_HEADERS_LEN + Ipv4Hdr::LEN + 4)?;
        if icmp_type == 8 && icmp_ident == ANET_PROBE_IDENT_BE {
            let _ = xoroshiro_crypt_packet(&w, OUTER_HEADERS_LEN, crypto_seed, seq);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // 6. Проверяем Token-Bucket шейпер для upload-трафика клиента (в `RATE_RULES` ключ — `u32::from_be(assigned_ip)`).
    if !check_upload_token_bucket(u32::from_be(assigned_ip), inner_tot_len as i64, now) {
        return Ok(xdp_action::XDP_DROP);
    }

    // 7. Декапсуляция на месте: копируем L2 Ethernet-заголовок на 36 байт вправо
    // и сдвигаем указатель начала пакета через `bpf_xdp_adjust_head(ctx, 36)`.
    w.write_unaligned::<EthHdr>(ASTPL_ENCAP_LEN, eth)?;
    let adj_ret = unsafe { bpf_xdp_adjust_head(ctx.as_ptr() as *mut _, ASTPL_ENCAP_LEN as i32) };
    if adj_ret < 0 {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

/// Token-Bucket ingress. Вешается в SKB(generic)-режиме — TUN не
/// поддерживает native/driver XDP. TUN-ingress — это пакеты, которые сам
/// `anet-server` записывает в устройство после расшифровки клиентского
/// трафика (путь клиент -> сервер -> интернет), т.е. upload с точки зрения
/// клиента. Лишнее дропается: TCP отправителя сам снизит окно перегрузки.
#[xdp]
pub fn xdp_ingress(ctx: XdpContext) -> u32 {
    match try_xdp_ingress(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let Some(src_ip) = parse_src_ipv4(ctx) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let packet_len = (ctx.data_end() - ctx.data()) as i64;
    let now = unsafe { bpf_ktime_get_ns() };

    let action = if check_upload_token_bucket(src_ip, packet_len, now) {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    };

    debug!(ctx, "xdp_ingress: src={:i}, action={}", src_ip, action);

    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
