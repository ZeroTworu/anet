//! Внутритуннельный перехватчик DNS-запросов (In-Tunnel DNS Interceptor).
//!
//! Перехватывает UDP-пакеты на порту 53, выполняет сопоставление доменов по правилам
//! AdBlock / Split-Tunneling и генерирует синтетические ответы с корректными контрольными суммами.

use anet_filter_core::{
    compute_ipv4_checksum, compute_udp_v4_checksum, LocalOverrides, RuleAction,
    MOZILLA_CANARY_DOMAIN,
};
use bytes::{Bytes, BytesMut};
use log::{debug, trace};
use std::sync::Arc;

use crate::direct_ip_cache::DirectIpCache;

/// Результат обработки пакета перехватчиком
pub enum InterceptResult {
    /// DNS-запрос перехвачен и обработан локально (сгенерирован ответный IP/UDP пакет)
    Handled(Bytes),
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

        trace!("[DNS] Intercepted query for domain: '{}', type: {}", query_info.qname, query_info.qtype);

        // 1. Проверка Mozilla Canary Domain -> форсируем NXDOMAIN для отключения DoH в Firefox
        if query_info.qname.eq_ignore_ascii_case(MOZILLA_CANARY_DOMAIN) {
            debug!("[DNS] Canary domain matched: '{}' -> Returning NXDOMAIN", query_info.qname);
            if let Some(resp) = self.build_synthetic_dns_response(packet, &query_info, true) {
                return InterceptResult::Handled(resp);
            }
            return InterceptResult::Drop;
        }

        // 2. Проверка в Local Overrides (client.toml)
        let action = self
            .local_overrides
            .lookup_domain(&query_info.qname)
            // 3. Проверка в скомпилированном кэше .abc
            .or_else(|| abc_domain_lookup(&query_info.qname))
            // 4. По умолчанию - Proxy
            .unwrap_or(RuleAction::Proxy);

        match action {
            RuleAction::Block => {
                debug!("[DNS] Domain '{}' matched BLOCK -> Synthetic 0.0.0.0", query_info.qname);
                if let Some(resp) = self.build_synthetic_dns_response(packet, &query_info, false) {
                    InterceptResult::Handled(resp)
                } else {
                    InterceptResult::Drop
                }
            }
            RuleAction::Direct => {
                // Прямой запрос: домен должен резолвиться напрямую.
                // В базовом цикле мы пропускаем запрос через прямой сокет или даем туннелю знать
                trace!("[DNS] Domain '{}' marked DIRECT", query_info.qname);
                InterceptResult::PassThrough
            }
            RuleAction::Proxy => {
                trace!("[DNS] Domain '{}' marked PROXY", query_info.qname);
                InterceptResult::PassThrough
            }
        }
    }

    /// Формирует синтетический DNS-ответ с пересчетом IPv4 и UDP контрольных сумм
    fn build_synthetic_dns_response(
        &self,
        original_packet: &[u8],
        query: &DnsQueryInfo,
        nxdomain: bool,
    ) -> Option<Bytes> {
        let ihl = ((original_packet[0] & 0x0F) * 4) as usize;
        let original_src_ip: [u8; 4] = [
            original_packet[12], original_packet[13], original_packet[14], original_packet[15],
        ];
        let original_dst_ip: [u8; 4] = [
            original_packet[16], original_packet[17], original_packet[18], original_packet[19],
        ];

        let original_src_port = [original_packet[ihl], original_packet[ihl + 1]];
        let original_dst_port = [original_packet[ihl + 2], original_packet[ihl + 3]];

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

        // Собираем полный IP/UDP пакет
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

        // Своп IP: Src становится прежним Dst (обычно 10.0.0.1 или DNS сервера), Dst становится клиентом
        reply_packet[12..16].copy_from_slice(&original_dst_ip);
        reply_packet[16..20].copy_from_slice(&original_src_ip);

        // Расчет IPv4 Header Checksum
        compute_ipv4_checksum(&mut reply_packet[0..20]);

        // 2. UDP Header (8 байт)
        // Своп портов: Src port становится 53 (original_dst_port), Dst port становится портом клиента
        reply_packet[20..22].copy_from_slice(&original_dst_port);
        reply_packet[22..24].copy_from_slice(&original_src_port);
        reply_packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
        reply_packet[26..28].copy_from_slice(&[0, 0]); // Временно обнуляем

        // 3. DNS Payload
        reply_packet[28..total_ip_len].copy_from_slice(&dns_response);

        // 4. Расчет UDP Checksum с псевдозаголовком IPv4
        compute_udp_v4_checksum(original_dst_ip, original_src_ip, &mut reply_packet[20..total_ip_len]);

        Some(Bytes::from(reply_packet))
    }
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
