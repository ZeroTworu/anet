//! Внутритуннельный перехватчик DNS-запросов (In-Tunnel DNS Interceptor).
//!
//! Перехватывает UDP-пакеты на порту 53, выполняет сопоставление доменов по правилам
//! AdBlock / Split-Tunneling, генерирует синтетические ответы с корректными контрольными суммами
//! и выполняет прямой DNS-резолв для `RuleAction::Direct` с наполнением `DirectIpCache`.

use anet_filter_core::{
    compute_ipv4_checksum, compute_udp_v4_checksum, LocalOverrides, RuleAction,
     CAPTIVE_PORTAL_DOMAINS, MOZILLA_CANARY_DOMAIN,
};
use bytes::{Bytes, BytesMut};
use log::{debug, trace};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::direct_ip_cache::DirectIpCache;

/// Результат обработки пакета перехватчиком
pub enum InterceptResult {
    /// DNS-запрос перехвачен и обработан локально (сгенерирован ответный IP/UDP пакет)
    Handled(Bytes),
    /// DNS-запрос к домену с правилом Direct (требуется прямой резолв в обход VPN и запись IP в DirectIpCache)
    DirectQuery,
    /// Пакет не является DNS-запросом или требует проксирования через туннель
    PassThrough,
    /// Пакет отброшен
    Drop,
}

/// Легковесный парсер DNS-запроса
#[derive(Debug)]
pub struct DnsQueryInfo {
    pub transaction_id: u16,
    pub flags: u16,
    pub qname: String,
    pub qtype: u16, // 1 = A, 28 = AAAA
}

/// Извлекает Destination IP из сырого IPv4 или IPv6 пакета
pub fn extract_packet_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Список публичных DoH IP-резолверов, для которых блокируется порт 443/853,
/// чтобы браузеры (Chrome/Edge/Brave/Firefox) гарантированно переключались на стандартный UDP:53
pub const DOH_RESOLVER_IPS: [Ipv4Addr; 8] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(1, 0, 0, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(8, 8, 4, 4),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(149, 112, 112, 112),
    Ipv4Addr::new(208, 67, 222, 222),
    Ipv4Addr::new(208, 67, 220, 220),
];

/// Выделенные DNS-серверы для прямых запросов (Direct), маршрутизируемые в обход VPN-туннеля
pub const DIRECT_UPSTREAM_DNS_IPS: [Ipv4Addr; 2] = [
    Ipv4Addr::new(77, 88, 8, 8),
    Ipv4Addr::new(8, 8, 4, 4),
];

/// Проверяет, является ли пакет попыткой шифрованного DNS (DoT порт 853 или DoH порт 443 к публичным DNS)
pub fn is_encrypted_dns_packet(packet: &[u8]) -> bool {
    if packet.len() < 24 || (packet[0] >> 4) != 4 {
        return false;
    }
    let ihl = ((packet[0] & 0x0F) * 4) as usize;
    if packet.len() < ihl + 4 {
        return false;
    }
    let proto = packet[9];
    if proto != 6 && proto != 17 {
        return false;
    }
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    if dst_port == 853 {
        return true;
    }
    if dst_port == 443 {
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        if DOH_RESOLVER_IPS.contains(&dst_ip)
            || DIRECT_UPSTREAM_DNS_IPS.contains(&dst_ip)
        {
            return true;
        }
    }
    false
}

/// Внутритуннельный DNS-интерцептор
#[derive(Clone)]
pub struct DnsInterceptor {
    local_overrides: Arc<LocalOverrides>,
    direct_cache: DirectIpCache,
}

impl DnsInterceptor {
    pub fn direct_cache(&self) -> &DirectIpCache {
        &self.direct_cache
    }

    pub fn new(local_overrides: Arc<LocalOverrides>, direct_cache: DirectIpCache) -> Self {
        Self {
            local_overrides,
            direct_cache,
        }
    }

    /// Проверяет сырой IP-пакет на принадлежность к DNS-запросам (IPv4, UDP, Dst Port 53)
    pub fn is_dns_query(packet: &[u8]) -> bool {
        if packet.len() < 28 {
            return false;
        }
        // IPv4 (version == 4, IHL >= 5)
        if (packet[0] >> 4) != 4 {
            return false;
        }
        let ihl = ((packet[0] & 0x0F) * 4) as usize;
        if packet.len() < ihl + 8 {
            return false;
        }
        // Protocol == 17 (UDP)
        if packet[9] != 17 {
            return false;
        }
        // UDP Dst Port == 53
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
        dst_port == 53
    }

    /// Проверяет сырой IP-пакет на принадлежность к DNS-ответам (IPv4, UDP, Src Port 53)
    pub fn is_dns_response(packet: &[u8]) -> bool {
        if packet.len() < 28 || (packet[0] >> 4) != 4 {
            return false;
        }
        let ihl = ((packet[0] & 0x0F) * 4) as usize;
        if packet.len() < ihl + 8 || packet[9] != 17 {
            return false;
        }
        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
        src_port == 53
    }

    /// Обрабатывает входящий пакет из TUN
    pub fn handle_packet(
        &self,
        packet: &[u8],
        abc_domain_lookup: impl Fn(&str) -> Option<RuleAction>,
    ) -> InterceptResult {
        if !Self::is_dns_query(packet) {
            return InterceptResult::PassThrough;
        }

        let ihl = ((packet[0] & 0x0F) * 4) as usize;
        let udp_header_len = 8;
        let dns_payload_start = ihl + udp_header_len;

        if packet.len() <= dns_payload_start {
            return InterceptResult::PassThrough;
        }

        let dns_data = &packet[dns_payload_start..];
        let query_info = match parse_dns_query(dns_data) {
            Some(info) => info,
            None => return InterceptResult::PassThrough,
        };

        trace!(
            "[DNS] Intercepted query for domain: '{}', type: {}",
            query_info.qname,
            query_info.qtype
        );

        // 1. Проверка Mozilla Canary Domain -> форсируем NXDOMAIN для отключения DoH в Firefox
        if query_info
            .qname
            .eq_ignore_ascii_case(MOZILLA_CANARY_DOMAIN)
        {
            debug!(
                "[DNS] Canary domain matched: '{}' -> Returning NXDOMAIN",
                query_info.qname
            );
            if let Some(resp) = self.build_synthetic_dns_response(packet, &query_info, true) {
                return InterceptResult::Handled(resp);
            }
            return InterceptResult::Drop;
        }

        // 2. Служебные домены Captive Portal никогда не блокируются AdBlock (п. 5.3 ТЗ)
        let is_captive_probe = CAPTIVE_PORTAL_DOMAINS
            .iter()
            .any(|d| query_info.qname.eq_ignore_ascii_case(d));

        // 3. Проверка в Local Overrides (client.toml) -> затем в скомпилированном кэше .abc -> Default Proxy
        let mut action = self
            .local_overrides
            .lookup_domain(&query_info.qname)
            .or_else(|| abc_domain_lookup(&query_info.qname))
            .unwrap_or(RuleAction::Proxy);

        if is_captive_probe && action == RuleAction::Block {
            action = RuleAction::Proxy;
        }

        match action {
            RuleAction::Block => {
                log::info!(
                    "[DNS] Domain '{}' matched BLOCK -> returning 0.0.0.0",
                    query_info.qname
                );
                if let Some(resp) = self.build_synthetic_dns_response(packet, &query_info, false) {
                    InterceptResult::Handled(resp)
                } else {
                    InterceptResult::Drop
                }
            }
            RuleAction::Direct => {
                log::info!(
                    "[DNS] Domain '{}' matched DIRECT -> resolving for direct bypass",
                    query_info.qname
                );
                InterceptResult::DirectQuery
            }
            RuleAction::Proxy => {
                trace!("[DNS] Domain '{}' marked PROXY", query_info.qname);
                InterceptResult::PassThrough
            }
        }
    }

    /// Анализирует входящий DNS-ответ (из туннеля) и если домен имеет правило `Direct`,
    /// кэширует его A/AAAA записи и возвращает список IP для добавления в таблицу маршрутизации ОС.
    pub fn inspect_dns_response(
        &self,
        packet: &[u8],
        abc_domain_lookup: impl Fn(&str) -> Option<RuleAction>,
    ) -> Option<(String, Vec<IpAddr>)> {
        if !Self::is_dns_response(packet) {
            return None;
        }
        let ihl = ((packet[0] & 0x0F) * 4) as usize;
        let dns_data = &packet[(ihl + 8)..];
        let qname = parse_dns_question_qname(dns_data)?;

        let action = self
            .local_overrides
            .lookup_domain(&qname)
            .or_else(|| abc_domain_lookup(&qname))
            .unwrap_or(RuleAction::Proxy);

        if action != RuleAction::Direct {
            return None;
        }

        let (resolved_ips, min_ttl) = parse_dns_answers_ips_and_ttl(dns_data);
        if !resolved_ips.is_empty() {
            self.direct_cache.insert_batch(
                &resolved_ips,
                RuleAction::Direct,
                Duration::from_secs(min_ttl as u64),
            );
        }
        Some((qname, resolved_ips))
    }

    /// Выполняет прямой UDP DNS-запрос через выделенные Direct DNS серверы (в обход туннеля),
    /// извлекает A/AAAA записи и TTL в `DirectIpCache`,
    /// и возвращает собранный IPv4/UDP ответный пакет с валидными контрольными суммами.
    pub async fn resolve_direct_dns_packet(
        &self,
        original_packet: &[u8],
        _dns_servers: &[String],
    ) -> Option<(Bytes, Vec<IpAddr>)> {
        let ihl = ((original_packet[0] & 0x0F) * 4) as usize;
        if original_packet.len() <= ihl + 8 {
            return None;
        }
        let dns_query_payload = &original_packet[(ihl + 8)..];

        let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        let mut recv_buf = vec![0u8; 1500];

        let mut received_len = None;
        for upstream_ip in DIRECT_UPSTREAM_DNS_IPS {
            let upstream_addr = SocketAddr::new(IpAddr::V4(upstream_ip), 53);
            if socket.send_to(dns_query_payload, upstream_addr).await.is_err() {
                continue;
            }
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_millis(1200), socket.recv_from(&mut recv_buf))
                    .await
            {
                received_len = Some(n);
                break;
            }
        }

        let n = received_len?;
        let dns_resp = &recv_buf[..n];
        let (resolved_ips, min_ttl) = parse_dns_answers_ips_and_ttl(dns_resp);

        if !resolved_ips.is_empty() {
            self.direct_cache.insert_batch(
                &resolved_ips,
                RuleAction::Direct,
                Duration::from_secs(min_ttl as u64),
            );
        }

        let reply_pkt = build_ipv4_udp_dns_reply(original_packet, dns_resp)?;
        Some((reply_pkt, resolved_ips))
    }

    /// Формирует синтетический DNS-ответ с пересчетом IPv4 и UDP контрольных сумм
    fn build_synthetic_dns_response(
        &self,
        original_packet: &[u8],
        query: &DnsQueryInfo,
        nxdomain: bool,
    ) -> Option<Bytes> {
        let ihl = ((original_packet[0] & 0x0F) * 4) as usize;

        // Строим тело DNS-ответа
        let mut dns_response = BytesMut::with_capacity(128);

        // Transaction ID
        dns_response.extend_from_slice(&query.transaction_id.to_be_bytes());

        // Flags
        if nxdomain {
            // QR=1, AA=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
            dns_response.extend_from_slice(&[0x81, 0x83]);
        } else {
            // QR=1, AA=1, RD=1, RA=1, RCODE=0 (NoError)
            dns_response.extend_from_slice(&[0x81, 0x80]);
        }

        // Questions = 1
        dns_response.extend_from_slice(&[0x00, 0x01]);

        if nxdomain {
            // Answers = 0
            dns_response.extend_from_slice(&[0x00, 0x00]);
        } else {
            // Answers = 1
            dns_response.extend_from_slice(&[0x00, 0x01]);
        }
        // Authority RRs = 0, Additional RRs = 0
        dns_response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Копируем секцию Question (QNAME + QTYPE + QCLASS) из исходного DNS пакета
        let orig_dns_payload = &original_packet[(ihl + 8)..];
        let mut q_end = 12; // Смещение после заголовка DNS
        while q_end < orig_dns_payload.len() && orig_dns_payload[q_end] != 0 {
            let label_len = orig_dns_payload[q_end] as usize;
            q_end += 1 + label_len;
        }
        q_end += 1; // Пропускаем нуль-терминатор QNAME
        q_end += 4; // QTYPE (2) + QCLASS (2)

        if q_end > orig_dns_payload.len() {
            return None;
        }
        dns_response.extend_from_slice(&orig_dns_payload[12..q_end]);

        // Answer Resource Record (если не NXDOMAIN)
        if !nxdomain {
            // Name pointer к началу QNAME (смещение 12 в DNS заголовке = 0xC00C)
            dns_response.extend_from_slice(&[0xC0, 0x0C]);

            if query.qtype == 28 {
                // AAAA: type=28, class=1 (IN), ttl=3600 (0x0E10), rdlength=16 (::)
                dns_response.extend_from_slice(&[0x00, 0x1C, 0x00, 0x01]);
                dns_response.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]);
                dns_response.extend_from_slice(&[0x00, 0x10]);
                dns_response.extend_from_slice(&[0u8; 16]); // ::
            } else {
                // A: type=1, class=1 (IN), ttl=3600 (0x0E10), rdlength=4 (0.0.0.0)
                dns_response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                dns_response.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]);
                dns_response.extend_from_slice(&[0x00, 0x04]);
                dns_response.extend_from_slice(&[0, 0, 0, 0]); // 0.0.0.0
            }
        }

        build_ipv4_udp_dns_reply(original_packet, &dns_response)
    }
}

/// Собирает полный IPv4 + UDP пакет ответа на базе исходного пакета запроса и тела DNS-ответа
fn build_ipv4_udp_dns_reply(original_packet: &[u8], dns_response: &[u8]) -> Option<Bytes> {
    let ihl = ((original_packet[0] & 0x0F) * 4) as usize;
    if original_packet.len() < ihl + 8 {
        return None;
    }

    let original_src_ip: [u8; 4] = [
        original_packet[12],
        original_packet[13],
        original_packet[14],
        original_packet[15],
    ];
    let original_dst_ip: [u8; 4] = [
        original_packet[16],
        original_packet[17],
        original_packet[18],
        original_packet[19],
    ];

    let original_src_port = [original_packet[ihl], original_packet[ihl + 1]];
    let original_dst_port = [original_packet[ihl + 2], original_packet[ihl + 3]];

    let udp_len = (8 + dns_response.len()) as u16;
    let total_ip_len = (20 + udp_len) as usize;
    let mut reply_packet = vec![0u8; total_ip_len];

    // 1. IPv4 Header (20 байт)
    reply_packet[0] = 0x45; // Version 4, IHL 5
    reply_packet[1] = 0x00; // DSCP / ECN
    reply_packet[2..4].copy_from_slice(&(total_ip_len as u16).to_be_bytes());
    reply_packet[4..6].copy_from_slice(&0x414Eu16.to_be_bytes()); // Identification
    reply_packet[6..8].copy_from_slice(&[0x40, 0x00]); // Don't Fragment
    reply_packet[8] = 64; // TTL
    reply_packet[9] = 17; // Protocol UDP

    // Своп IP: Src становится прежним Dst, Dst становится клиентом
    reply_packet[12..16].copy_from_slice(&original_dst_ip);
    reply_packet[16..20].copy_from_slice(&original_src_ip);

    // Расчет IPv4 Header Checksum
    compute_ipv4_checksum(&mut reply_packet[0..20]);

    // 2. UDP Header (8 байт)
    reply_packet[20..22].copy_from_slice(&original_dst_port);
    reply_packet[22..24].copy_from_slice(&original_src_port);
    reply_packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
    reply_packet[26..28].copy_from_slice(&[0, 0]);

    // 3. DNS Payload
    reply_packet[28..total_ip_len].copy_from_slice(dns_response);

    // 4. Расчет UDP Checksum с псевдозаголовком IPv4
    compute_udp_v4_checksum(
        original_dst_ip,
        original_src_ip,
        &mut reply_packet[20..total_ip_len],
    );

    Some(Bytes::from(reply_packet))
}

/// Извлекает имя домена и тип запроса из DNS пакета
fn parse_dns_query(dns_bytes: &[u8]) -> Option<DnsQueryInfo> {
    if dns_bytes.len() < 12 {
        return None;
    }
    let transaction_id = u16::from_be_bytes([dns_bytes[0], dns_bytes[1]]);
    let flags = u16::from_be_bytes([dns_bytes[2], dns_bytes[3]]);
    let qdcount = u16::from_be_bytes([dns_bytes[4], dns_bytes[5]]);

    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    let mut labels = Vec::new();

    while pos < dns_bytes.len() {
        let len = dns_bytes[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if pos + len > dns_bytes.len() {
            return None;
        }
        let label = std::str::from_utf8(&dns_bytes[pos..pos + len]).ok()?;
        labels.push(label);
        pos += len;
    }

    if pos + 4 > dns_bytes.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([dns_bytes[pos], dns_bytes[pos + 1]]);
    let qname = labels.join(".");

    Some(DnsQueryInfo {
        transaction_id,
        flags,
        qname,
        qtype,
    })
}

/// Извлекает QNAME из секции Question DNS-пакета (запроса или ответа)
fn parse_dns_question_qname(dns_bytes: &[u8]) -> Option<String> {
    parse_dns_query(dns_bytes).map(|info| info.qname)
}

/// Пропускает DNS-имя (с учетом сжатия указателей 0xC0) и возвращает новую позицию
fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    while pos < buf.len() {
        let b = buf[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if (b & 0xC0) == 0xC0 {
            if pos + 2 > buf.len() {
                return None;
            }
            return Some(pos + 2);
        }
        let len = b as usize;
        pos += 1 + len;
    }
    None
}

/// Извлекает все IP-адреса из секции Answers (A и AAAA) и минимальный TTL из DNS-ответа
pub fn parse_dns_answers_ips_and_ttl(dns_bytes: &[u8]) -> (Vec<IpAddr>, u32) {
    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;

    if dns_bytes.len() < 12 {
        return (ips, 300);
    }

    let qdcount = u16::from_be_bytes([dns_bytes[4], dns_bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([dns_bytes[6], dns_bytes[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = match skip_dns_name(dns_bytes, pos) {
            Some(p) if p + 4 <= dns_bytes.len() => p + 4,
            _ => return (ips, 300),
        };
    }

    for _ in 0..ancount {
        pos = match skip_dns_name(dns_bytes, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > dns_bytes.len() {
            break;
        }
        let rtype = u16::from_be_bytes([dns_bytes[pos], dns_bytes[pos + 1]]);
        let ttl = u32::from_be_bytes([
            dns_bytes[pos + 4],
            dns_bytes[pos + 5],
            dns_bytes[pos + 6],
            dns_bytes[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([dns_bytes[pos + 8], dns_bytes[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > dns_bytes.len() {
            break;
        }

        if rtype == 1 && rdlength == 4 {
            let ip = IpAddr::V4(Ipv4Addr::new(
                dns_bytes[pos],
                dns_bytes[pos + 1],
                dns_bytes[pos + 2],
                dns_bytes[pos + 3],
            ));
            ips.push(ip);
            min_ttl = min_ttl.min(ttl);
        } else if rtype == 28 && rdlength == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&dns_bytes[pos..pos + 16]);
            ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            min_ttl = min_ttl.min(ttl);
        }

        pos += rdlength;
    }

    let effective_ttl = if min_ttl == u32::MAX {
        300
    } else {
        min_ttl.max(30)
    };
    (ips, effective_ttl)
}
