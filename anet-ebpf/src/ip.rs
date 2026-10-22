//! Разбор голых IPv4-пакетов на TUN-интерфейсе.
//!
//! TUN без PI-заголовка (то же допущение, что уже используется в
//! `anet-server::utils::extract_ip_dst` на стороне userspace: version-nibble
//! в самом первом байте, без Ethernet/PI-префикса). Поддерживаем только
//! IPv4 — как и весь остальной ANet (`IpPool`, `TunParams` и т.д. — только
//! `Ipv4Addr`).

use core::mem;
use anet_ebpf_common::Xoroshiro128Plus;
use aya_ebpf::programs::{TcContext, XdpContext};

const IPV4_VERSION: u8 = 4;
const IPV4_HEADER_MIN_LEN: usize = 20;
const IPV4_SRC_OFFSET: usize = 12;
const IPV4_DST_OFFSET: usize = 16;

pub const ETH_P_IP_BE: u16 = 0x0800u16.to_be();
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_UDP: u8 = 17;

/// Максимальное число 8-байтных блоков шифрования (200 * 8 = 1600 байт > стандартного MTU).
/// Константная верхняя граница гарантирует быстрое доказательство конечности цикла BPF-верификатором.
pub const MAX_CRYPT_BLOCKS: usize = 200;

/// Заголовок Ethernet II (14 байт).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub ether_type: u16, // Big-Endian
}

impl EthHdr {
    pub const LEN: usize = 14;
}

/// Стандартный заголовок IPv4 без опций (IHL = 5, 20 байт).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Hdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,  // Big-Endian
    pub id: u16,       // Big-Endian
    pub frag_off: u16, // Big-Endian
    pub ttl: u8,
    pub proto: u8,
    pub check: u16,    // Big-Endian
    pub src_addr: u32, // Big-Endian
    pub dst_addr: u32, // Big-Endian
}

impl Ipv4Hdr {
    pub const LEN: usize = 20;

    #[inline(always)]
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    #[inline(always)]
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }
}

/// Заголовок UDP (8 байт).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpHdr {
    pub source: u16, // Big-Endian
    pub dest: u16,   // Big-Endian
    pub len: u16,    // Big-Endian
    pub check: u16,  // Big-Endian
}

impl UdpHdr {
    pub const LEN: usize = 8;
}

/// Универсальная обёртка над `XdpContext` и `TcContext` со строгой проверкой
/// границ пакета (`data .. data_end`) для BPF-верификатора.
pub enum ContextWrapper<'a> {
    Xdp(&'a XdpContext),
    Tc(&'a TcContext),
}

impl<'a> ContextWrapper<'a> {
    #[inline(always)]
    pub fn data(&self) -> usize {
        match self {
            Self::Xdp(ctx) => ctx.data(),
            Self::Tc(ctx) => ctx.data(),
        }
    }

    #[inline(always)]
    pub fn data_end(&self) -> usize {
        match self {
            Self::Xdp(ctx) => ctx.data_end(),
            Self::Tc(ctx) => ctx.data_end(),
        }
    }

    #[inline(always)]
    pub fn ptr_at<T>(&self, offset: usize) -> Result<*const T, ()> {
        let start = self.data();
        let end = self.data_end();
        let len = mem::size_of::<T>();

        if start + offset + len > end {
            return Err(());
        }
        Ok((start + offset) as *const T)
    }

    #[inline(always)]
    pub fn ptr_at_mut<T>(&self, offset: usize) -> Result<*mut T, ()> {
        let start = self.data();
        let end = self.data_end();
        let len = mem::size_of::<T>();

        if start + offset + len > end {
            return Err(());
        }
        Ok((start + offset) as *mut T)
    }

    #[inline(always)]
    pub fn read_unaligned<T: Copy>(&self, offset: usize) -> Result<T, ()> {
        let ptr = self.ptr_at::<T>(offset)?;
        Ok(unsafe { core::ptr::read_unaligned(ptr) })
    }

    #[inline(always)]
    pub fn write_unaligned<T: Copy>(&self, offset: usize, val: T) -> Result<(), ()> {
        let ptr = self.ptr_at_mut::<T>(offset)?;
        unsafe {
            core::ptr::write_unaligned(ptr, val);
        }
        Ok(())
    }
}

/// Бесцикловое вычисление контрольной суммы 20-байтного заголовка IPv4 (RFC 1071).
/// Возвращает `u16` в сетевом порядке байт (Big-Endian), готовый для записи в `Ipv4Hdr::check`.
#[inline(always)]
pub fn ipv4_header_checksum(hdr: &Ipv4Hdr) -> u16 {
    let w0 = u16::from_be_bytes([hdr.version_ihl, hdr.tos]) as u32;
    let w1 = u16::from_be(hdr.tot_len) as u32;
    let w2 = u16::from_be(hdr.id) as u32;
    let w3 = u16::from_be(hdr.frag_off) as u32;
    let w4 = u16::from_be_bytes([hdr.ttl, hdr.proto]) as u32;
    // w5 (check) = 0
    let src = u32::from_be(hdr.src_addr);
    let w6 = (src >> 16) & 0xFFFF;
    let w7 = src & 0xFFFF;
    let dst = u32::from_be(hdr.dst_addr);
    let w8 = (dst >> 16) & 0xFFFF;
    let w9 = dst & 0xFFFF;

    let mut sum = w0 + w1 + w2 + w3 + w4 + w6 + w7 + w8 + w9;
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    (!(sum as u16)).to_be()
}

/// Шифрует или расшифровывает полезную нагрузку пакета в памяти (`payload_offset .. data_end`)
/// потоковым шифром `Xoroshiro128+` блоками по 8 байт + хвост `1..7` байт.
/// Возвращает длину обработанной полезной нагрузки в байтах.
#[inline(always)]
pub fn xoroshiro_crypt_packet(
    w: &ContextWrapper<'_>,
    payload_offset: usize,
    seed: u64,
    seq: u32,
) -> Result<usize, ()> {
    let start = w.data();
    let end = w.data_end();
    if start + payload_offset > end {
        return Err(());
    }
    let payload_len = end - (start + payload_offset);

    let mut rng = Xoroshiro128Plus::new(seed, seq);
    let mut off = payload_offset;

    for _ in 0..MAX_CRYPT_BLOCKS {
        if start + off + 8 > end {
            break;
        }
        let block = u64::from_le(w.read_unaligned::<u64>(off)?);
        let masked = (block ^ rng.next_u64()).to_le();
        w.write_unaligned::<u64>(off, masked)?;
        off += 8;
    }

    if start + off < end {
        let tail_mask = rng.next_u64().to_le_bytes();
        for i in 0..7usize {
            let byte_off = off + i;
            if start + byte_off + 1 > end {
                break;
            }
            let b = w.read_unaligned::<u8>(byte_off)?;
            w.write_unaligned::<u8>(byte_off, b ^ tail_mask[i])?;
        }
    }

    Ok(payload_len)
}

#[inline(always)]
unsafe fn read_be32(base: usize, offset: usize) -> u32 {
    // Rust 2024: unsafe fn больше не даёт implicit-unsafe своему телу —
    // разыменование и арифметику над сырым указателем нужно оборачивать явно,
    // даже находясь уже внутри unsafe fn.
    unsafe {
        let ptr = (base + offset) as *const u8;
        let b0 = *ptr as u32;
        let b1 = *ptr.add(1) as u32;
        let b2 = *ptr.add(2) as u32;
        let b3 = *ptr.add(3) as u32;
        (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }
}

#[inline(always)]
fn is_ipv4(base: usize, end: usize) -> bool {
    if base + 1 > end {
        return false;
    }
    let first_byte = unsafe { *(base as *const u8) };
    (first_byte >> 4) == IPV4_VERSION
}

pub fn parse_dst_ipv4(ctx: &TcContext) -> Option<u32> {
    let base = ctx.data();
    let end = ctx.data_end();
    if base + IPV4_HEADER_MIN_LEN > end || !is_ipv4(base, end) {
        return None;
    }
    Some(unsafe { read_be32(base, IPV4_DST_OFFSET) })
}

pub fn parse_src_ipv4(ctx: &XdpContext) -> Option<u32> {
    let base = ctx.data();
    let end = ctx.data_end();
    if base + IPV4_HEADER_MIN_LEN > end || !is_ipv4(base, end) {
        return None;
    }
    Some(unsafe { read_be32(base, IPV4_SRC_OFFSET) })
}
