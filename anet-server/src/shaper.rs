//! Управление eBPF-шейпером трафика (per-user `speed_limit`) поверх TUN-
//! интерфейса сервера. Ядерная часть — крейт `anet-ebpf`, встроенная прямо
//! в бинарь `anet-server` (см. `build.rs` + `aya::include_bytes_aligned!`),
//! так что для деплоя не нужен отдельный `.o`/`.bpf`-файл — всё в одном
//! исполняемом файле, как и остальные бинарники ANet.
//!
//! Топология: `tc_egress` (clsact egress TUN, download клиента, EDT/`fq`,
//! без потерь) + `xdp_ingress` (generic/SKB-mode XDP TUN, upload клиента,
//! Token Bucket, дропает лишнее). Подробности — в `anet-ebpf/src/main.rs`.

use anet_ebpf_common::{EdtState, RateRule, TokenBucketState, EDT_STATE, RULES, TB_STATE};
use anyhow::{Context, Result};
use aya::maps::HashMap as AyaHashMap;
use aya::programs::tc::{SchedClassifier, TcAttachType};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use log::{info, warn};
use std::net::Ipv4Addr;
use std::process::Stdio;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Минимальный разумный "всплеск" — если считать 10% скорости слишком
/// маленьким burst (низкий speed_limit), первый же пакет крупнее burst
/// никогда не пройдёт Token Bucket. 64 KiB покрывает типичный TCP-сегмент
/// с запасом на джиттер ANet stealth-конфига.
const MIN_BURST_BYTES: u64 = 65536;

pub struct Shaper {
    ebpf: Mutex<Ebpf>,
    iface: String,
}

impl Shaper {
    /// Загружает встроенный eBPF-объект и вешает обе программы на `iface`
    /// (актуальное имя TUN-интерфейса сервера, после `TunManager::run()`).
    /// Требует `CAP_BPF` + `CAP_NET_ADMIN` (или root).
    pub async fn attach(iface: &str) -> Result<Self> {
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/anet-ebpf"));
        let mut ebpf = Ebpf::load(bytes).context("Failed to load embedded anet-ebpf object")?;

        // Логи из BPF (aya_log_ebpf::debug!) необязательны для работы шейпера;
        // при желании включить — сверьте инициализацию с версией aya-log,
        // закреплённой в Cargo.lock (API периодически меняется между релизами).
        // if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        //     warn!("[Shaper] eBPF logger init failed (non-fatal): {}", e);
        // }

        Self::ensure_clsact(iface).await;
        Self::ensure_fq_qdisc(iface).await;
        // Best-effort: если TC-фильтр остался от предыдущего аварийно
        // завершившегося процесса — снимаем его, иначе свежий attach() ниже
        // может упасть с "File exists".
        Self::cleanup_stale_filter(iface).await;

        let egress: &mut SchedClassifier = ebpf
            .program_mut("tc_egress")
            .context("tc_egress program missing from anet-ebpf object")?
            .try_into()?;
        egress.load()?;
        egress
            .attach(iface, TcAttachType::Egress)
            .context("Failed to attach tc_egress to TUN egress")?;

        // XDP только в SKB(generic)-режиме: TUN не поддерживает native/driver XDP.
        let ingress: &mut Xdp = ebpf
            .program_mut("xdp_ingress")
            .context("xdp_ingress program missing from anet-ebpf object")?
            .try_into()?;
        ingress.load()?;
        ingress
            .attach(iface, XdpFlags::SKB_MODE)
            .context("Failed to attach xdp_ingress to TUN ingress (generic/SKB mode)")?;

        info!("[Shaper] Attached tc_egress + xdp_ingress to '{}'", iface);

        Ok(Self {
            ebpf: Mutex::new(ebpf),
            iface: iface.to_string(),
        })
    }

    async fn ensure_clsact(iface: &str) {
        let output = Command::new("tc")
            .args(["qdisc", "add", "dev", iface, "clsact"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await;
        if let Ok(output) = output {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
                if !stderr.contains("file exists") {
                    warn!("[Shaper] 'tc qdisc add clsact' warning: {}", stderr.trim());
                }
            }
        }
    }

    async fn ensure_fq_qdisc(iface: &str) {
        let output = Command::new("tc")
            .args(["qdisc", "replace", "dev", iface, "root", "fq"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await;
        match output {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(
                    "[Shaper] 'tc qdisc replace root fq' failed: {} — EDT-пейсинг работать не \
                     будет, download клиентов пойдёт без ограничения.",
                    stderr.trim()
                );
            }
            Err(e) => warn!("[Shaper] Failed to execute 'tc qdisc replace root fq': {}", e),
            _ => {}
        }
    }

    async fn cleanup_stale_filter(iface: &str) {
        let _ = Command::new("tc")
            .args(["filter", "del", "dev", iface, "egress"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await;
        let _ = Command::new("ip")
            .args(["link", "set", "dev", iface, "xdpgeneric", "off"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await;
    }

    /// Устанавливает (или обновляет) ограничение скорости для туннельного
    /// IP клиента. `kbps` — килобиты в секунду, как в схеме `rates`/`groups`.
    pub async fn set_limit(&self, ip: Ipv4Addr, kbps: u32) -> Result<()> {
        let rate_bytes_per_sec = (kbps as u64) * 1000 / 8;
        let burst_bytes = (rate_bytes_per_sec / 10).max(MIN_BURST_BYTES);
        let rule = RateRule { rate_bytes_per_sec, burst_bytes };
        let key = u32::from_be_bytes(ip.octets());

        let mut ebpf = self.ebpf.lock().await;
        let mut rules: AyaHashMap<_, u32, RateRule> =
            AyaHashMap::try_from(ebpf.map_mut(RULES).context("RATE_RULES map missing")?)?;
        rules.insert(key, rule, 0)?;

        info!("[Shaper] Limit set: {} -> {} kbps (burst {} bytes)", ip, kbps, burst_bytes);
        Ok(())
    }

    /// Снимает ограничение и чистит накопленное состояние для IP. Вызывается
    /// при полном освобождении сессии (`remove_client`, истечение
    /// suspend-окна), чтобы карты не росли безгранично при переиспользовании
    /// адресов из пула.
    pub async fn clear_limit(&self, ip: Ipv4Addr) {
        let key = u32::from_be_bytes(ip.octets());
        let mut ebpf = self.ebpf.lock().await;

        if let Ok(map) = ebpf.map_mut(RULES).context("RATE_RULES map missing") {
            if let Ok(mut rules) = AyaHashMap::<_, u32, RateRule>::try_from(map) {
                let _ = rules.remove(&key);
            }
        }
        if let Ok(map) = ebpf.map_mut(EDT_STATE).context("EDT_STATE map missing") {
            if let Ok(mut edt) = AyaHashMap::<_, u32, EdtState>::try_from(map) {
                let _ = edt.remove(&key);
            }
        }
        if let Ok(map) = ebpf.map_mut(TB_STATE).context("TB_STATE map missing") {
            if let Ok(mut tb) = AyaHashMap::<_, u32, TokenBucketState>::try_from(map) {
                let _ = tb.remove(&key);
            }
        }
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }
}
