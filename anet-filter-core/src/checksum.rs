//! Вычисление и валидация контрольных сумм IP/UDP для внутритуннельного сетевого стека (TUN).
//! Соответствует спецификациям RFC 791, RFC 768, RFC 1071 и RFC 8200.

/// Вычисляет и записывает 16-битную контрольную сумму заголовка IPv4 (RFC 791, RFC 1071).
///
/// Контрольная сумма записывается со смещением 10..12 в переданном срезе заголовка `header`.
/// Длина `header` должна быть не менее 20 байт и кратна 4 (IHL * 4).
pub fn compute_ipv4_checksum(header: &mut [u8]) {
    if header.len() < 20 {
        return;
    }
    // Обнуляем старое значение контрольной суммы (байты 10 и 11)
    header[10] = 0;
    header[11] = 0;

    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }

    // Сворачиваем 32-битную сумму в 16 бит
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !(sum as u16);
    let bytes = checksum.to_be_bytes();
    header[10] = bytes[0];
    header[11] = bytes[1];
}

/// Проверяет валидность контрольной суммы заголовка IPv4.
pub fn verify_ipv4_checksum(header: &[u8]) -> bool {
    if header.len() < 20 {
        return false;
    }
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    (sum as u16) == 0xFFFF
}

/// Вычисляет и записывает контрольную сумму UDP для IPv4 (RFC 768, RFC 1071).
///
/// Включает 12-байтный псевдозаголовок IPv4:
/// - Source IP (4 байта)
/// - Destination IP (4 байта)
/// - Zero (1 байт, 0x00)
/// - Protocol (1 байт, 17 = 0x11)
/// - UDP Length (2 байта)
///
/// Внимание (RFC 768): если расчетная сумма равна 0x0000, в пакет записывается 0xFFFF,
/// так как 0x0000 означает "контрольная сумма отсутствует".
pub fn compute_udp_v4_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_packet: &mut [u8]) {
    if udp_packet.len() < 8 {
        return;
    }
    // Обнуляем поле checksum в заголовке UDP (байты 6..8)
    udp_packet[6] = 0;
    udp_packet[7] = 0;

    let udp_len = udp_packet.len() as u16;
    let mut sum: u32 = 0;

    // 1. IPv4 Pseudo-Header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 17u32; // Protocol UDP
    sum += udp_len as u32;

    // 2. UDP Header + Payload
    let mut i = 0;
    while i + 1 < udp_packet.len() {
        let word = u16::from_be_bytes([udp_packet[i], udp_packet[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < udp_packet.len() {
        sum += (udp_packet[i] as u32) << 8;
    }

    // Сворачиваем в 16 бит
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let mut checksum = !(sum as u16);
    if checksum == 0 {
        checksum = 0xFFFF;
    }
    let bytes = checksum.to_be_bytes();
    udp_packet[6] = bytes[0];
    udp_packet[7] = bytes[1];
}

/// Вычисляет и записывает обязательную контрольную сумму UDP для IPv6 (RFC 8200).
///
/// Включает 40-байтный псевдозаголовок IPv6:
/// - Source IPv6 (16 байт)
/// - Destination IPv6 (16 байт)
/// - Upper-Layer Packet Length (4 байта)
/// - Zero (3 байта) + Next Header (1 байт, 17 = 0x11)
pub fn compute_udp_v6_checksum(src_ip: [u8; 16], dst_ip: [u8; 16], udp_packet: &mut [u8]) {
    if udp_packet.len() < 8 {
        return;
    }
    udp_packet[6] = 0;
    udp_packet[7] = 0;

    let udp_len = udp_packet.len() as u32;
    let mut sum: u32 = 0;

    // 1. IPv6 Pseudo-Header
    for chunk in src_ip.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst_ip.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += (udp_len >> 16) & 0xFFFF;
    sum += udp_len & 0xFFFF;
    sum += 17u32; // Next Header = UDP

    // 2. UDP Header + Payload
    let mut i = 0;
    while i + 1 < udp_packet.len() {
        let word = u16::from_be_bytes([udp_packet[i], udp_packet[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < udp_packet.len() {
        sum += (udp_packet[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let mut checksum = !(sum as u16);
    if checksum == 0 {
        checksum = 0xFFFF;
    }
    let bytes = checksum.to_be_bytes();
    udp_packet[6] = bytes[0];
    udp_packet[7] = bytes[1];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_header_checksum_known_vector() {
        // Стандартный IPv4 заголовок (RFC 1071 / Wikipedia example):
        // 45 00 00 73 00 00 40 00 40 11 b8 61 c0 a8 00 01 c0 a8 00 c7
        let mut header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        compute_ipv4_checksum(&mut header);
        assert_eq!(header[10], 0xb8);
        assert_eq!(header[11], 0x61);
        assert!(verify_ipv4_checksum(&header));
    }

    #[test]
    fn test_udp_v4_checksum_known_vector() {
        let src_ip = [10, 0, 0, 1];
        let dst_ip = [10, 0, 0, 2];
        let mut udp_packet = vec![
            0x00, 0x35, // Src port 53 (DNS)
            0xC0, 0x01, // Dst port 49153
            0x00, 0x0C, // Length 12 (8 header + 4 payload)
            0x00, 0x00, // Checksum placeholder
            0xDE, 0xAD, 0xBE, 0xEF, // Payload
        ];
        compute_udp_v4_checksum(src_ip, dst_ip, &mut udp_packet);
        let csum = u16::from_be_bytes([udp_packet[6], udp_packet[7]]);
        assert_ne!(csum, 0);

        // Проверяем инвариант с псевдозаголовком
        let mut sum: u32 = 0;
        sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
        sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
        sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
        sum += 17u32;
        sum += udp_packet.len() as u32;
        for chunk in udp_packet.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF);
    }
}
