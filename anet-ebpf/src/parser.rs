use core::mem::size_of;
use core::result::Result::{self, Ok, Err};
use aya_ebpf::programs::XdpContext;
use core::net::{Ipv4Addr, Ipv6Addr};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use core::convert::From;
use crate::ipproto;

pub struct ParseResult {
    pub source_port: u16,
    pub destination_port: u16,

    pub destination_addr_v4: u32,
    pub source_addr_v4: u32,

    pub destination_addr_v6: u128,
    pub source_addr_v6: u128,

    pub proto: IpProto,

    pub input: bool,
    pub output: bool,

    pub v4: bool,
    pub ifindex: u32,
}

pub struct UnhandledProtocolError {
    pub proto: IpProto,

    pub dst_v4: u32,
    pub src_v4: u32,

    pub dst_v6: u128,
    pub src_v6: u128,

    pub ifindex: u32,
    pub input: bool,
    pub v4: bool,
}

impl UnhandledProtocolError {
    pub fn empty() -> Self {
        Self {
            proto: IpProto::Reserved,
            dst_v4: 0u32,
            src_v4: 0u32,
            dst_v6: 0u128,
            src_v6: 0u128,
            ifindex: 0u32,
            input: false,
            v4: false,
        }
    }

    pub fn proto_as_u8(&self) -> u8 {
        return ipproto::as_u8(&self.proto);
    }
}

pub struct ContextWrapper {
    pub data: usize,
    pub data_end: usize,
    pub ifindex: u32,
}

impl ContextWrapper {
    #[inline(always)]
    pub fn from_xdp(ctx: &XdpContext) -> Self {
        unsafe { Self::from_usize(ctx.data(), ctx.data_end(), (*ctx.ctx).ingress_ifindex) }
    }

    #[inline(always)]
    pub fn from_usize(data: usize, data_end: usize, ifindex: u32) -> Self {
        Self {
            data,
            data_end,
            ifindex,
        }
    }

    #[inline(always)]
    pub fn ptr_at_u<T>(&self, offset: usize) -> Result<*const T, UnhandledProtocolError> {
        let len = size_of::<T>();
        if self.data + offset + len > self.data_end {
            return Err(UnhandledProtocolError::empty());
        }
        Ok((self.data + offset) as *const T)
    }

    pub fn to_parse_result(
        &self,
        v4: bool,
        input: bool,
    ) -> Result<ParseResult, UnhandledProtocolError> {
        let (proto, destination_addr_v4, source_addr_v4, destination_addr_v6, source_addr_v6) =
            if v4 {
                let ipv4hdr: Ipv4Hdr = unsafe { *self.ptr_at_u(EthHdr::LEN)? };
                (
                    ipv4hdr.proto,
                    Ipv4Addr::from(u32::from_be(ipv4hdr.dst_addr)).to_bits(),
                    Ipv4Addr::from(u32::from_be(ipv4hdr.src_addr)).to_bits(),
                    0u128,
                    0u128,
                )
            } else {
                let ipv6hdr: Ipv6Hdr = unsafe { *self.ptr_at_u(EthHdr::LEN)? };

                (
                    ipv6hdr.next_hdr,
                    0u32,
                    0u32,
                    Ipv6Addr::from(unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 }).to_bits(),
                    Ipv6Addr::from(unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 }).to_bits(),
                )
            };

        let len = if v4 { Ipv4Hdr::LEN } else { Ipv6Hdr::LEN };

        let (source_port, destination_port) = match proto {
            IpProto::Tcp => {
                let tcphdr: TcpHdr = unsafe { *self.ptr_at_u(EthHdr::LEN + len)? };
                (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
            }
            IpProto::Udp => {
                let udphdr: UdpHdr = unsafe { *self.ptr_at_u(EthHdr::LEN + len)? };
                (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
            }
            _ => {
                return Err(UnhandledProtocolError {
                    proto,
                    dst_v4: destination_addr_v4,
                    src_v4: source_addr_v4,
                    dst_v6: destination_addr_v6,
                    src_v6: source_addr_v6,
                    ifindex: self.ifindex,
                    input,
                    v4,
                });
            }
        };

        Ok(ParseResult {
            source_port,
            destination_port,
            source_addr_v4,
            destination_addr_v4,
            proto,
            input,
            destination_addr_v6,
            source_addr_v6,
            output: !input,
            v4,
            ifindex: self.ifindex,
        })
    }
}
