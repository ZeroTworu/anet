//! Разбор голых IPv4-пакетов на TUN-интерфейсе.
//!
//! TUN без PI-заголовка (то же допущение, что уже используется в
//! `anet-server::utils::extract_ip_dst` на стороне userspace: version-nibble
//! в самом первом байте, без Ethernet/PI-префикса). Поддерживаем только
//! IPv4 — как и весь остальной ANet (`IpPool`, `TunParams` и т.д. — только
//! `Ipv4Addr`).

use aya_ebpf::programs::{TcContext, XdpContext};

const IPV4_VERSION: u8 = 4;
const IPV4_HEADER_MIN_LEN: usize = 20;
const IPV4_SRC_OFFSET: usize = 12;
const IPV4_DST_OFFSET: usize = 16;

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
