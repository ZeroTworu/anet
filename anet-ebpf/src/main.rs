#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::XskMap, programs::XdpContext, EbpfContext};
use network_types::ip::IpProto;
use core::ptr::addr_of;
use aya_log_ebpf::{error, info};
use anet_ebpf::parser::ContextWrapper;


#[map]
static XSK_MAP: XskMap = XskMap::with_max_entries(1, 0); // По числу очередей

// Глобальная переменная, которую мы подменим из Rust (userspace)
#[unsafe(no_mangle)]
pub static mut TARGET_PORT: u16 = 1;

#[xdp]
pub fn anet_redirect(ctx: XdpContext) -> u32 {
    match try_anet_redirect(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_anet_redirect(ctx: &XdpContext) -> Result<u32, ()> {
    let wrapper = ContextWrapper::from_xdp(ctx);
    let target_port = unsafe { core::ptr::read_volatile(addr_of!(TARGET_PORT)) };

    if let Ok(pkt) = wrapper.to_parse_result(true, true) {
        if pkt.proto == IpProto::Udp && pkt.destination_port == target_port {

            // Читаем первые 4 байта Payload как u32
            // Смещение: 42 байта (14 Eth + 20 IP + 8 UDP)
            let mut payload_prefix: u32 = 0;
            if let Ok(ptr) = wrapper.ptr_at_u::<u32>(42) {
                // Используем read_unaligned, так как в сетевом пакете
                // данные могут быть не выровнены по 4 байта
                payload_prefix = unsafe { core::ptr::read_unaligned(ptr) };
            }

            // В aya-log используем {:x} для hex-вывода
            // info!(ctx, "[eBPF] REDIRECT! SRC: {} | Prefix: {:x}",
            //     pkt.source_addr_v4,
            //     payload_prefix
            // );

            return match XSK_MAP.redirect(0, 0) {
                Ok(ret) => {
                    //info!(ctx, "[eBPF] REDIRECT BY OK! {}", ret);
                    Ok(ret)
                },
                Err(err) => {
                    error!(ctx, "[eBPF] PASS BY ERR! {}", err);
                    Ok(xdp_action::XDP_PASS)
                }
            }
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}