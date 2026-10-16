use bytes::Bytes;
use std::net::Ipv4Addr;

/// Уникальный идентификатор зонда ANet (ASCII "AN" = 0x414E)
pub const PROBE_IDENTIFIER: u16 = 0x414E;

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
}
