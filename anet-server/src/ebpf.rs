use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, include_bytes_aligned};
use aya::maps::{XskMap, MapData, Array};
use aya::programs::xdp::XdpLinkId;
use anyhow::Context;
use log::{info, warn, error};
use parking_lot::Mutex;
use std::any::Any;

pub struct EbpfManager {
    pub bpf: Mutex<Ebpf>,
    // Храним линки как динамические объекты.
    // Пока жив менеджер, линки живы, и программа сидит в ядре.
    _link: XdpLinkId,
}

impl EbpfManager {
    pub async fn load_and_attach(iface: &str, port: u16) -> anyhow::Result<Self> {
        let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/anet_kern")))
            .context("Failed to load eBPF bytecode")?;

        // 1. Установка TARGET_PORT (Код поиска секции .data)
        {
            let map_name = bpf.maps()
                .map(|(name, _)| name)
                .find(|name| name.contains(".data"))
                .map(|s| s.to_string());

            if let Some(name) = map_name {
                let map = bpf.map_mut(&name).context("Failed to get mutable map")?;
                let mut data_map: Array<_, u16> = Array::try_from(map)?;
                data_map.set(0, &port, 0).context("Failed to set TARGET_PORT")?;
                info!("BPF: Set TARGET_PORT to {} in map '{}'", port, name);
            } else {
                warn!("BPF: .data map not found! Check if TARGET_PORT is used in kernel code.");
            }
        }

        // 2. Загрузка программы
        let prog: &mut Xdp = bpf.program_mut("anet_redirect")
            .context("Program anet_redirect not found")?
            .try_into()?;

        prog.load()?;

        // 3. Привязка к интерфейсу
        // Мы сохраняем возвращаемый объект Link, чтобы он не удалился!
        let link = prog.attach(iface, XdpFlags::DRV_MODE)
            .or_else(|e| {
                warn!("BPF: DRV_MODE failed ({:?}), attempting SKB_MODE with REPLACE...", e);
                prog.attach(iface, XdpFlags::SKB_MODE)
            })
            .or_else(|e| {
                warn!("BPF: SKB_MODE failed ({:?}), attempting default with REPLACE...", e);
                prog.attach(iface, XdpFlags::REPLACE)
            })
            .context("Failed to attach BPF in any mode")?;

        info!("BPF: Attached to {} (Port {})", iface, port);

        Ok(Self {
            bpf: Mutex::new(bpf),
            _link: link,
        })
    }

    /// Регистрация сокета (XDP_REDIRECT)
    pub fn set_xsk(&self, queue_id: u32, fd: i32) -> anyhow::Result<()> {
        let mut bpf_guard = self.bpf.lock();
        let map = bpf_guard.map_mut("XSK_MAP").context("XSK_MAP not found")?;
        let mut xsk_map = XskMap::try_from(map)?;

        xsk_map.set(queue_id, fd, 0)?;
        info!("[AF_XDP] Registered socket FD {} for queue {}", fd, queue_id);
        Ok(())
    }
}
