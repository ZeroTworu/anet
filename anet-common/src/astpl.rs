//! Пользовательская (Userspace) реализация протокола ASTP-L (Anet Stream Transport Protocol - Lite).
//!
//! Обеспечивает побайтовую совместимость с ядерными программами XDP/TC в `anet-ebpf`:
//! - 8-байтный заголовок `[nonce_prefix: u32 (BE)][seq: u32 (BE)]`
//! - потоковый шифр `Xoroshiro128+` с двухступенчатым прогревом состояния
//! - проверка криптографических инвариантов внутреннего IPv4-заголовка с откатом буфера при коллизиях

use anyhow::{anyhow, bail, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::net::Ipv4Addr;

/// Размер заголовка ASTP-L: `[nonce_prefix: u32 (4B)][seq: u32 (4B)]`.
pub const ASTPL_HEADER_LEN: usize = 8;

/// Минимальный размер внутреннего IPv4-заголовка (без опций, IHL = 5).
pub const ASTPL_MIN_IPV4_LEN: usize = 20;

/// Минимальный размер датаграммы ASTP-L Data Plane (`8 + 20 = 28` байт).
pub const ASTPL_MIN_PACKET_LEN: usize = ASTPL_HEADER_LEN + ASTPL_MIN_IPV4_LEN;

/// Потоковый шифр на базе ГПСЧ `Xoroshiro128+` с 2-раундовым прогревом состояния.
/// Полностью идентичен реализации в `anet-ebpf-common` / `anet-ebpf`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Xoroshiro128Plus {
    pub s0: u64,
    pub s1: u64,
}

impl Xoroshiro128Plus {
    #[inline(always)]
    pub fn new(seed: u64, seq: u32) -> Self {
        let seq64 = seq as u64;
        let mut rng = Self {
            s0: seed ^ ((seq64 << 32) | (!seq64 & 0xFFFF_FFFF)),
            s1: seed
                .wrapping_add(0x9E37_79B9_7F4A_7C15)
                .wrapping_mul(seq64 | 1),
        };
        let _ = rng.next_u64();
        let _ = rng.next_u64();
        rng
    }

    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        let s0 = self.s0;
        let mut s1 = self.s1;
        let result = s0.wrapping_add(s1);

        s1 ^= s0;
        self.s0 = s0.rotate_left(24) ^ s1 ^ (s1 << 16);
        self.s1 = s1.rotate_left(37);

        result
    }

    /// Накладывает гамму `Xoroshiro128+` на буфер блоками по 8 байт (Little-Endian) + хвост `1..7` байт.
    #[inline(always)]
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        let mut chunks = buf.chunks_exact_mut(8);
        for chunk in &mut chunks {
            let block = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
            let masked = (block ^ self.next_u64()).to_le_bytes();
            chunk.copy_from_slice(&masked);
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let tail_mask = self.next_u64().to_le_bytes();
            for i in 0..rem.len() {
                rem[i] ^= tail_mask[i];
            }
        }
    }
}

/// Упаковывает и шифрует внутренний IPv4-пакет в UDP-датаграмму ASTP-L:
/// `[nonce_prefix (4B)][seq (4B, BE)][Encrypted IPv4 Payload]`.
#[inline]
pub fn wrap_astpl_packet(
    nonce_prefix: &[u8; 4],
    seq: u32,
    crypto_seed: u64,
    inner_ipv4: &[u8],
) -> Bytes {
    let safe_seq = if seq == 0 { 1 } else { seq };
    let mut out = BytesMut::with_capacity(ASTPL_HEADER_LEN + inner_ipv4.len());
    out.put_slice(nonce_prefix);
    out.put_u32(safe_seq);
    out.put_slice(inner_ipv4);

    let mut rng = Xoroshiro128Plus::new(crypto_seed, safe_seq);
    rng.apply_keystream(&mut out[ASTPL_HEADER_LEN..]);

    out.freeze()
}

/// Формирует управляющий пакет ASTP-L (`Seq == 0`), который пропускается XDP в Userspace.
#[inline]
pub fn wrap_astpl_control_packet(nonce_prefix: &[u8; 4], payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(ASTPL_HEADER_LEN + payload.len());
    out.put_slice(nonce_prefix);
    out.put_u32(0);
    out.put_slice(payload);
    out.freeze()
}

/// Расшифровывает датаграмму ASTP-L на месте и проверяет инварианты внутреннего IPv4-пакета.
/// Если задан `expected_src_ip`, дополнительно проверяет anti-spoofing (`inner.src_ip == expected_src_ip`).
/// При несовпадении инвариантов откатывает XOR обратно, оставляя `datagram` в исходном виде.
#[inline]
pub fn unwrap_astpl_packet_in_place<'a>(
    crypto_seed: u64,
    datagram: &'a mut [u8],
    expected_src_ip: Option<Ipv4Addr>,
) -> Result<([u8; 4], u32, &'a [u8])> {
    if datagram.len() < ASTPL_HEADER_LEN {
        bail!("ASTP-L datagram shorter than 8-byte header");
    }

    let nonce_prefix: [u8; 4] = datagram[0..4]
        .try_into()
        .map_err(|_| anyhow!("invalid nonce_prefix slice"))?;
    let seq = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);

    if seq == 0 {
        return Ok((nonce_prefix, 0, &datagram[ASTPL_HEADER_LEN..]));
    }

    if datagram.len() < ASTPL_MIN_PACKET_LEN {
        bail!("ASTP-L data packet shorter than minimum IPv4 header");
    }

    let payload = &mut datagram[ASTPL_HEADER_LEN..];
    let mut rng = Xoroshiro128Plus::new(crypto_seed, seq);
    rng.apply_keystream(payload);

    let version = payload[0] >> 4;
    let ihl = payload[0] & 0x0F;
    let tot_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let src_ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);

    let valid = version == 4
        && ihl >= 5
        && tot_len >= ASTPL_MIN_IPV4_LEN
        && tot_len <= payload.len()
        && expected_src_ip.is_none_or(|expected| src_ip == expected);

    if !valid {
        // Откатываем XOR обратно, чтобы не повредить буфер при случайной коллизии префикса
        let mut rollback = Xoroshiro128Plus::new(crypto_seed, seq);
        rollback.apply_keystream(payload);
        bail!("ASTP-L inner IPv4 invariant check failed");
    }

    Ok((nonce_prefix, seq, &payload[..tot_len]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::icmp_probe::{build_ipv4_icmp_echo_request, PROBE_IDENTIFIER};

    #[test]
    fn xoroshiro_roundtrip_with_unaligned_tail() {
        let seed = 0xDEAD_BEEF_CAFE_BABEu64;
        let seq = 42u32;
        let src_ip = Ipv4Addr::new(10, 0, 0, 3);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 1);

        // 36 байт (36 % 8 == 4 байта хвоста)
        let inner = build_ipv4_icmp_echo_request(src_ip, dst_ip, PROBE_IDENTIFIER, 7, 999_999);
        let prefix = [0xAA, 0xBB, 0xCC, 0xDD];

        let wrapped = wrap_astpl_packet(&prefix, seq, seed, &inner);
        assert_eq!(wrapped.len(), ASTPL_HEADER_LEN + inner.len());
        assert_eq!(&wrapped[0..4], &prefix);
        assert_eq!(&wrapped[4..8], &seq.to_be_bytes());
        assert_ne!(&wrapped[8..], inner.as_ref());

        let mut buf = wrapped.to_vec();
        let (parsed_prefix, parsed_seq, decrypted) =
            unwrap_astpl_packet_in_place(seed, &mut buf, Some(src_ip)).unwrap();
        assert_eq!(parsed_prefix, prefix);
        assert_eq!(parsed_seq, seq);
        assert_eq!(decrypted, inner.as_ref());
    }

    #[test]
    fn invalid_inner_packet_rolls_back_xor() {
        let seed = 0x1234_5678_9ABC_DEF0u64;
        let mut fake_datagram = vec![
            1, 2, 3, 4, // nonce_prefix
            0, 0, 0, 9, // seq = 9
            // 24 байта произвольного хендшейка (не валидный внутренний IPv4)
            0xFE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        ];
        let original = fake_datagram.clone();

        let res = unwrap_astpl_packet_in_place(
            seed,
            &mut fake_datagram,
            Some(Ipv4Addr::new(10, 0, 0, 5)),
        );
        assert!(res.is_err());
        assert_eq!(fake_datagram, original);
    }
}
