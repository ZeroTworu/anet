use bytes::Bytes;
use std::net::Ipv4Addr;

/// Уникальный идентификатор зонда ANet до шлюза (ASCII "AN" = 0x414E)
pub const PROBE_IDENTIFIER: u16 = 0x414E;

/// Идентификатор внутритуннельного ICMP-зонда глобальной связности (ASCII "AW" = 0x4157).
/// Сервер не перехватывает его в userspace (т.к. ident != PROBE_IDENTIFIER), а маршрутизирует через NAT во внешний мир.
pub const PROBE_WORLD_IDENTIFIER: u16 = 0x4157;

/// Идентификатор внутритуннельного ICMP-зонда доступности РФ-узлов (ASCII "AD" = 0x4144).
pub const PROBE_DOMESTIC_IDENTIFIER: u16 = 0x4144;

/// Глобальные публичные IPv4-узлы для проверки выхода в мировой интернет сквозь туннель.
pub const TUNNEL_WORLD_PROBE_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(9, 9, 9, 9),
];

/// Российские публичные IPv4-узлы (Яндекс.DNS) для проверки связности с РФ сквозь туннель.
pub const TUNNEL_DOMESTIC_PROBE_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(77, 88, 8, 8),
    Ipv4Addr::new(77, 88, 8, 1),
    Ipv4Addr::new(87, 250, 250, 242),
];

/// Вычисление стандартной 16-битной контрольной суммы Интернета (RFC 1071).
pub fn internet_checksum(buf: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = buf.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Формирует чистый, валидный IPv4 ICMP Echo Request пакет (Type 8, Code 0)
/// с таймстемпом в микросекундах внутри полезной нагрузки.
/// Пакет не отличим от обычного пользовательского трафика и передается внутри шифрованного туннеля.
pub fn build_ipv4_icmp_echo_request(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ident: u16,
    seq: u16,
    timestamp_micros: u64,
) -> Bytes {
    // 20 байт IPv4 Header + 8 байт ICMP Header + 8 байт Timestamp Payload = 36 байт
    let mut packet = [0u8; 36];

    // --- IPv4 Header (20 байт) ---
    packet[0] = 0x45; // Version 4, IHL 5 (20 байт)
    packet[1] = 0x00; // DSCP / ECN
    packet[2..4].copy_from_slice(&36u16.to_be_bytes()); // Total Length = 36
    packet[4..6].copy_from_slice(&ident.to_be_bytes()); // Identification
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags: DF (Don't Fragment)
    packet[8] = 64; // TTL
    packet[9] = 1; // Protocol: ICMP (1)
    packet[10..12].copy_from_slice(&[0, 0]); // Checksum placeholder
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    let ip_csum = internet_checksum(&packet[0..20]);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // --- ICMP Header & Payload (16 байт) ---
    packet[20] = 8; // Type 8: Echo Request
    packet[21] = 0; // Code 0
    packet[22..24].copy_from_slice(&[0, 0]); // ICMP Checksum placeholder
    packet[24..26].copy_from_slice(&ident.to_be_bytes());
    packet[26..28].copy_from_slice(&seq.to_be_bytes());
    packet[28..36].copy_from_slice(&timestamp_micros.to_be_bytes());

    let icmp_csum = internet_checksum(&packet[20..36]);
    packet[22..24].copy_from_slice(&icmp_csum.to_be_bytes());

    Bytes::copy_from_slice(&packet)
}

/// Проверяет, является ли полученный из туннеля пакет ответом сервера (ICMP Echo Reply, Type 0, Code 0)
/// на наш зонд. В случае совпадения возвращает (sequence, timestamp_micros).
pub fn parse_ipv4_icmp_echo_reply(
    packet: &[u8],
    expected_dst: Ipv4Addr,
    expected_ident: u16,
) -> Option<(u16, u64)> {
    if packet.len() < 36 {
        return None;
    }

    // Проверяем версию IPv4
    if (packet[0] >> 4) != 4 {
        return None;
    }

    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 16 {
        return None;
    }

    // Протокол должен быть ICMP (1)
    if packet[9] != 1 {
        return None;
    }

    // Сверяем IP назначения: должен совпадать с виртуальным IP клиента
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if dst != expected_dst {
        return None;
    }

    // ICMP Payload
    let icmp = &packet[ihl..];
    // Type 0 (Echo Reply), Code 0
    if icmp[0] != 0 || icmp[1] != 0 {
        return None;
    }

    let ident = u16::from_be_bytes([icmp[4], icmp[5]]);
    if ident != expected_ident {
        return None;
    }

    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&icmp[8..16]);
    let timestamp_micros = u64::from_be_bytes(ts_bytes);

    Some((seq, timestamp_micros))
}

/// Обрабатывает входящий внутритуннельный пакет в userspace сервера.
/// Если это ICMP Echo Request (Type 8, Code 0) с PROBE_IDENTIFIER,
/// мгновенно формирует ответный ICMP Echo Reply (Type 0) с тем же seq и timestamp,
/// меняя местами IP-адреса отправителя и получателя.
pub fn handle_in_tunnel_icmp_probe(packet: &[u8]) -> Option<Bytes> {
    if packet.len() < 36 {
        return None;
    }

    // Проверяем IPv4
    if (packet[0] >> 4) != 4 {
        return None;
    }

    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 16 {
        return None;
    }

    // Протокол ICMP (1)
    if packet[9] != 1 {
        return None;
    }

    let icmp = &packet[ihl..];
    // Type 8 (Echo Request), Code 0
    if icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }

    let ident = u16::from_be_bytes([icmp[4], icmp[5]]);
    if ident != PROBE_IDENTIFIER {
        return None;
    }

    // Формируем чистый Echo Reply (Type 0)
    let mut reply = packet.to_vec();

    // Меняем местами IP src и dst в IPv4-заголовке
    let src = [packet[12], packet[13], packet[14], packet[15]];
    let dst = [packet[16], packet[17], packet[18], packet[19]];
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);

    // Пересчитываем контрольную сумму заголовка IPv4
    reply[10..12].copy_from_slice(&[0, 0]);
    let ip_csum = internet_checksum(&reply[0..ihl]);
    reply[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // Устанавливаем Type 0 (Echo Reply), Code 0
    reply[ihl] = 0;
    reply[ihl + 1] = 0;

    // Пересчитываем контрольную сумму ICMP
    reply[ihl + 2..ihl + 4].copy_from_slice(&[0, 0]);
    let icmp_csum = internet_checksum(&reply[ihl..]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    Some(Bytes::from(reply))
}

#[inline]
fn update_checksum_u16(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum = (!old_csum as u32) + (!old_val as u32) + (new_val as u32);
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Динамический TCP MSS Clamping «на лету» в userspace (работает на любой ОС без iptables и root).
/// Для 99.99% пакетов (не содержащих флага TCP SYN) выполняется за 3 машинных инструкции без аллокаций и копирований.
/// На пакетах TCP SYN / SYN+ACK ограничивает опцию MSS до `max_ip_mtu - 40` (с пересчетом контрольной суммы по RFC 1624),
/// гарантируя, что ни клиент (даже Android с MTU 1280), ни сервер (даже с TUN MTU 1400) никогда не отправят
/// TCP-сегмент крупнее лимита транспорта (например, VP8 RTP кадра или CF WARP MTU).
#[inline]
pub fn clamp_tcp_mss_bytes(packet: Bytes, max_ip_mtu: usize) -> Bytes {
    if packet.len() < 44 || (packet[0] >> 4) != 4 || packet[9] != 6 {
        return packet;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 24 {
        return packet;
    }
    // Проверяем флаг SYN (бит 1 в байте флагов TCP по смещению ihl + 13)
    if (packet[ihl + 13] & 0x02) == 0 {
        return packet;
    }

    let doff = ((packet[ihl + 12] >> 4) as usize) * 4;
    if doff < 24 || packet.len() < ihl + doff {
        return packet;
    }

    let target_mss = max_ip_mtu.saturating_sub(ihl + 20).clamp(536, 1460) as u16;
    let opts_end = ihl + doff;
    let mut idx = ihl + 20;

    while idx < opts_end {
        let kind = packet[idx];
        if kind == 0 {
            break; // End of Option List
        }
        if kind == 1 {
            idx += 1; // NOP
            continue;
        }
        if idx + 1 >= opts_end {
            break;
        }
        let len = packet[idx + 1] as usize;
        if len < 2 || idx + len > opts_end {
            break;
        }
        if kind == 2 && len == 4 {
            let cur_mss = u16::from_be_bytes([packet[idx + 2], packet[idx + 3]]);
            if cur_mss > target_mss {
                let mut buf = packet.to_vec();
                buf[idx + 2..idx + 4].copy_from_slice(&target_mss.to_be_bytes());
                let old_csum = u16::from_be_bytes([buf[ihl + 16], buf[ihl + 17]]);
                let new_csum = update_checksum_u16(old_csum, cur_mss, target_mss);
                buf[ihl + 16..ihl + 18].copy_from_slice(&new_csum.to_be_bytes());
                return Bytes::from(buf);
            }
            break;
        }
        idx += len;
    }

    packet
}

/// Проверяет, является ли пакет исходящим QUIC / HTTP/3 пакетом (IPv4 UDP на порт 443).
#[inline]
pub fn is_quic_udp_443_packet(packet: &[u8]) -> bool {
    if packet.len() < 28 || (packet[0] >> 4) != 4 || packet[9] != 17 {
        return false;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return false;
    }
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    dst_port == 443
}

/// Генерирует мгновенный пакет отклонения (TCP RST или ICMP / ICMPv6 Destination Unreachable)
/// вместо «тихого дропа» (Drop). Это позволяет ОС, браузерам и Telegram за 0.05 мс получить
/// `ECONNREFUSED` / `ENETUNREACH` и мгновенно переключиться:
/// - с IPv6 (2000::/3 на мобильных сетях) на IPv4 внутри туннеля;
/// - с DoT (853) / DoH (443) на стандартный UDP:53 DNS без 10-секундного зависания «Адрес не найден»;
/// - с QUIC (UDP:443) на стабильный TCP:443 с нашим TCP MSS Clamping.
pub fn build_reject_packet(packet: &[u8]) -> Option<Bytes> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => build_ipv4_reject_packet(packet),
        6 => build_ipv6_reject_packet(packet),
        _ => None,
    }
}

fn build_ipv4_reject_packet(packet: &[u8]) -> Option<Bytes> {
    if packet.len() < 28 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }
    let proto = packet[9];
    let src_ip = [packet[12], packet[13], packet[14], packet[15]];
    let dst_ip = [packet[16], packet[17], packet[18], packet[19]];

    if proto == 6 {
        // TCP -> формируем 40-байтный IPv4 TCP RST+ACK
        if packet.len() < ihl + 20 {
            return None;
        }
        let tcp = &packet[ihl..];
        let flags = tcp[13];
        // Не отвечаем RST на RST
        if (flags & 0x04) != 0 {
            return None;
        }
        let src_port = [tcp[0], tcp[1]];
        let dst_port = [tcp[2], tcp[3]];
        let seq_num = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let doff = ((tcp[12] >> 4) as usize) * 4;
        let payload_len = packet.len().saturating_sub(ihl + doff) as u32;

        let (rst_seq, rst_ack, rst_flags) = if (flags & 0x10) != 0 {
            // Есть ACK -> RST с seq = ack_num
            (ack_num, 0u32, 0x04u8)
        } else {
            // SYN без ACK -> RST+ACK с ack = seq_num + payload_len + 1
            let syn_fin = u32::from((flags & 0x01) != 0 || (flags & 0x02) != 0);
            (0u32, seq_num.wrapping_add(payload_len).wrapping_add(syn_fin), 0x14u8)
        };

        let mut rst = [0u8; 40];
        rst[0] = 0x45;
        rst[2..4].copy_from_slice(&40u16.to_be_bytes());
        rst[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        rst[8] = 64;
        rst[9] = 6; // TCP
        rst[12..16].copy_from_slice(&dst_ip);
        rst[16..20].copy_from_slice(&src_ip);
        let ip_csum = internet_checksum(&rst[0..20]);
        rst[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // TCP header (20 bytes)
        rst[20..22].copy_from_slice(&dst_port);
        rst[22..24].copy_from_slice(&src_port);
        rst[24..28].copy_from_slice(&rst_seq.to_be_bytes());
        rst[28..32].copy_from_slice(&rst_ack.to_be_bytes());
        rst[32] = 0x50; // Data offset = 5 (20 bytes)
        rst[33] = rst_flags;

        // TCP pseudo-header + header checksum
        let mut pseudo = [0u8; 32];
        pseudo[0..4].copy_from_slice(&dst_ip);
        pseudo[4..8].copy_from_slice(&src_ip);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
        pseudo[12..32].copy_from_slice(&rst[20..40]);
        let tcp_csum = internet_checksum(&pseudo);
        rst[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

        return Some(Bytes::copy_from_slice(&rst));
    }

    if proto == 17 {
        // UDP -> формируем IPv4 ICMP Destination Unreachable: Port Unreachable (Type 3, Code 3)
        let quoted_len = (ihl + 8).min(packet.len());
        let total_len = 20 + 8 + quoted_len;
        let mut icmp_pkt = vec![0u8; total_len];

        icmp_pkt[0] = 0x45;
        icmp_pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        icmp_pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        icmp_pkt[8] = 64;
        icmp_pkt[9] = 1; // ICMP
        icmp_pkt[12..16].copy_from_slice(&dst_ip);
        icmp_pkt[16..20].copy_from_slice(&src_ip);
        let ip_csum = internet_checksum(&icmp_pkt[0..20]);
        icmp_pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // ICMP Type 3 (Destination Unreachable), Code 3 (Port Unreachable)
        icmp_pkt[20] = 3;
        icmp_pkt[21] = 3;
        icmp_pkt[28..28 + quoted_len].copy_from_slice(&packet[..quoted_len]);
        let icmp_csum = internet_checksum(&icmp_pkt[20..]);
        icmp_pkt[22..24].copy_from_slice(&icmp_csum.to_be_bytes());

        return Some(Bytes::from(icmp_pkt));
    }

    None
}

fn build_ipv6_reject_packet(packet: &[u8]) -> Option<Bytes> {
    if packet.len() < 40 {
        return None;
    }
    let next_hdr = packet[6];
    let src_ip = &packet[8..24];
    let dst_ip = &packet[24..40];

    if next_hdr == 6 && packet.len() >= 60 {
        // IPv6 TCP -> возвращаем мгновенный IPv6 TCP RST+ACK (60 байт)
        let tcp = &packet[40..];
        let flags = tcp[13];
        if (flags & 0x04) != 0 {
            return None;
        }
        let src_port = [tcp[0], tcp[1]];
        let dst_port = [tcp[2], tcp[3]];
        let seq_num = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let doff = ((tcp[12] >> 4) as usize) * 4;
        let payload_len = packet.len().saturating_sub(40 + doff) as u32;

        let (rst_seq, rst_ack, rst_flags) = if (flags & 0x10) != 0 {
            (ack_num, 0u32, 0x04u8)
        } else {
            let syn_fin = u32::from((flags & 0x01) != 0 || (flags & 0x02) != 0);
            (0u32, seq_num.wrapping_add(payload_len).wrapping_add(syn_fin), 0x14u8)
        };

        let mut rst = [0u8; 60];
        rst[0] = 0x60; // Version 6
        rst[4..6].copy_from_slice(&20u16.to_be_bytes()); // Payload length = 20 (TCP header)
        rst[6] = 6; // Next Header = TCP
        rst[7] = 64; // Hop Limit
        rst[8..24].copy_from_slice(dst_ip);
        rst[24..40].copy_from_slice(src_ip);

        rst[40..42].copy_from_slice(&dst_port);
        rst[42..44].copy_from_slice(&src_port);
        rst[44..48].copy_from_slice(&rst_seq.to_be_bytes());
        rst[48..52].copy_from_slice(&rst_ack.to_be_bytes());
        rst[52] = 0x50;
        rst[53] = rst_flags;

        let mut pseudo = [0u8; 60];
        pseudo[0..16].copy_from_slice(dst_ip);
        pseudo[16..32].copy_from_slice(src_ip);
        pseudo[32..36].copy_from_slice(&20u32.to_be_bytes());
        pseudo[39] = 6; // TCP
        pseudo[40..60].copy_from_slice(&rst[40..60]);
        let tcp_csum = internet_checksum(&pseudo);
        rst[56..58].copy_from_slice(&tcp_csum.to_be_bytes());

        return Some(Bytes::copy_from_slice(&rst));
    }

    // Для остальных IPv6 пакетов (UDP/ICMPv6) -> ICMPv6 Destination Unreachable (Type 1, Code 4 - Port Unreachable)
    if next_hdr == 58 {
        return None; // Не отвечаем ICMPv6 на ICMPv6
    }
    let quoted_len = packet.len().min(88);
    let icmp6_len = 8 + quoted_len;
    let total_len = 40 + icmp6_len;
    let mut reply = vec![0u8; total_len];

    reply[0] = 0x60;
    reply[4..6].copy_from_slice(&(icmp6_len as u16).to_be_bytes());
    reply[6] = 58; // ICMPv6
    reply[7] = 64;
    reply[8..24].copy_from_slice(dst_ip);
    reply[24..40].copy_from_slice(src_ip);

    reply[40] = 1; // Type 1: Destination Unreachable
    reply[41] = 4; // Code 4: Port Unreachable
    reply[48..48 + quoted_len].copy_from_slice(&packet[..quoted_len]);

    let mut pseudo = Vec::with_capacity(40 + icmp6_len);
    pseudo.extend_from_slice(dst_ip);
    pseudo.extend_from_slice(src_ip);
    pseudo.extend_from_slice(&(icmp6_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&reply[40..]);
    let csum = internet_checksum(&pseudo);
    reply[42..44].copy_from_slice(&csum.to_be_bytes());

    Some(Bytes::from(reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_computation() {
        let data = [
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
        ];
        let csum = internet_checksum(&data);
        assert_ne!(csum, 0);
        let mut with_csum = data;
        with_csum[10..12].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(internet_checksum(&with_csum), 0);
    }

    #[test]
    fn test_echo_request_and_reply_match() {
        let client_ip = Ipv4Addr::new(172, 112, 224, 2);
        let gateway_ip = Ipv4Addr::new(172, 112, 224, 1);
        let req = build_ipv4_icmp_echo_request(
            client_ip,
            gateway_ip,
            PROBE_IDENTIFIER,
            42,
            123456789,
        );

        assert_eq!(req.len(), 36);
        assert_eq!(req[0], 0x45);
        assert_eq!(req[9], 1); // ICMP
        assert_eq!(req[20], 8); // Echo Request

        // Обрабатываем зонд функцией сервера в userspace
        let rep = handle_in_tunnel_icmp_probe(&req).expect("Failed to handle probe");
        assert_eq!(rep[20], 0); // Echo Reply

        let parsed = parse_ipv4_icmp_echo_reply(&rep, client_ip, PROBE_IDENTIFIER);
        assert_eq!(parsed, Some((42, 123456789)));
    }

    #[test]
    fn test_tcp_mss_clamping_preserves_valid_checksum() {
        // 44-байтный IPv4 TCP SYN с опцией MSS = 1460 (0x05B4)
        let mut syn = vec![
            0x45, 0x00, 0x00, 44, 0x12, 0x34, 0x40, 0x00, 64, 6, 0x00, 0x00,
            172, 112, 224, 2, 149, 154, 167, 50,
            // TCP header (24 bytes, doff=6)
            0xC0, 0x01, 0x01, 0xBB, // src=49153, dst=443
            0x00, 0x00, 0x00, 0x01, // seq=1
            0x00, 0x00, 0x00, 0x00, // ack=0
            0x60, 0x02, 0xFA, 0xF0, // doff=6 (24B), flags=SYN (0x02), win=64240
            0x00, 0x00, 0x00, 0x00, // csum=0, urg=0
            0x02, 0x04, 0x05, 0xB4, // Option Kind=2 (MSS), Len=4, MSS=1460
        ];
        // Вычисляем исходную контрольную сумму TCP
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&syn[12..20]);
        pseudo.extend_from_slice(&[0, 6, 0, 24]);
        pseudo.extend_from_slice(&syn[20..44]);
        let orig_csum = internet_checksum(&pseudo);
        syn[36..38].copy_from_slice(&orig_csum.to_be_bytes());

        // Зажимаем под MTU 960 (ожидаемый MSS = 920 = 0x0398)
        let clamped = clamp_tcp_mss_bytes(Bytes::from(syn), 960);
        assert_eq!(u16::from_be_bytes([clamped[42], clamped[43]]), 920);

        // Проверяем валидность TCP-чексуммы после инкрементального пересчета
        let mut verify_pseudo = Vec::new();
        verify_pseudo.extend_from_slice(&clamped[12..20]);
        verify_pseudo.extend_from_slice(&[0, 6, 0, 24]);
        verify_pseudo.extend_from_slice(&clamped[20..44]);
        assert_eq!(internet_checksum(&verify_pseudo), 0);
    }
}

