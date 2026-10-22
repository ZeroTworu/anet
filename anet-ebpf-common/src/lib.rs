#![no_std]

//! Общие POD-типы карт между ядерной частью (`anet-ebpf`, `no_std`) и
//! управляющим кодом в `anet-server` (`feature = "user"`).

/// Имена BPF-карт — общие константы, чтобы не разъезжались строки между
/// ядерной и userspace частью.
pub const RULES: &str = "RATE_RULES";
pub const EDT_STATE: &str = "EDT_STATE";
pub const TB_STATE: &str = "TB_STATE";

pub const ASTPL_CONFIG_MAP: &str = "ASTPL_CONFIG";
pub const ASTPL_INGRESS_MAP: &str = "ASTPL_INGRESS_MAP";
pub const ASTPL_EGRESS_MAP: &str = "ASTPL_EGRESS_MAP";

/// Размер заголовка ASTP-L: `[nonce_prefix: u32 (4B)][seq: u32 (4B)]`
pub const ASTPL_HEADER_LEN: usize = 8;

/// Полный размер внешней L3+L4+ASTP-L инкапсуляции:
/// `Outer IPv4 (20) + Outer UDP (8) + ASTP-L Header (8) = 36 байт`
pub const ASTPL_ENCAP_LEN: usize = 20 + 8 + ASTPL_HEADER_LEN;

/// Правило ограничения скорости для одного клиентского IP внутри туннельной
/// сети. Общее на оба направления — в схеме БД ANet (`rates`/`groups`)
/// `speed_limit` один на пользователя, отдельных up/down лимитов нет.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RateRule {
    /// Скорость в байтах/сек (переведено из kbps на стороне userspace,
    /// чтобы в горячем пути BPF не было деления при каждом применении лимита).
    pub rate_bytes_per_sec: u64,
    /// Максимальный "всплеск" в байтах: для Token Bucket — стартовый запас
    /// токенов, для EDT — верхняя граница того, насколько далеко в будущее
    /// можно спланировать отправку пакета.
    pub burst_bytes: u64,
}

/// Состояние EDT (Earliest Departure Time) для egress-пейсинга (download).
/// Пакеты не дропаются — фактическую задержку и порядок берёт на себя
/// qdisc `fq`, которому мы лишь проставляем `tstamp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EdtState {
    /// Ближайший разрешённый момент отправки следующего пакета, нс
    /// (CLOCK_MONOTONIC, тот же таймлайн что и `bpf_ktime_get_ns`).
    pub next_departure_ns: u64,
}

/// Состояние Token Bucket для ingress-шейпинга (upload). Лишнее дропается.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TokenBucketState {
    pub tokens: i64,
    pub last_update_ns: u64,
}

/// Глобальная конфигурация ASTP-L, передаваемая из `anet-server` в eBPF.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AstplConfig {
    /// UDP-порт ASTP-L в сетевом порядке байт (Big-Endian)
    pub astpl_port_be: u16,
    pub _pad: u16,
    /// Внешний IPv4-адрес сервера на физическом интерфейсе (Big-Endian)
    pub server_ip_be: u32,
    /// Индекс физического интерфейса (eth0) для `bpf_redirect_neigh`
    pub eth_ifindex: u32,
    pub _pad2: u32,
}

/// Запись входящей сессии в `ASTPL_INGRESS_MAP` (ключ — `nonce_prefix: u32` в Big-Endian).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IngressSessionData {
    /// 64-битный мастер-ключ сессии для `Xoroshiro128+`
    pub crypto_seed: u64,
    /// Счётчик принятых расшифрованных байт (для синхронизации с `ClientRegistry`)
    pub rx_bytes: u64,
    /// Таймстемп `bpf_ktime_get_ns()` последнего валидного пакета
    pub last_seen_ns: u64,
    /// Внутренний VPN IP клиента (Big-Endian, для anti-spoofing и поиска в `ASTPL_EGRESS_MAP`)
    pub assigned_ip: u32,
    /// Последний принятый `Seq` (Host-Order)
    pub last_seq: u32,
    /// Текущий внешний IPv4 клиента (Big-Endian, отслеживание NAT Rebinding)
    pub client_ip: u32,
    /// Текущий внешний UDP-порт клиента (Big-Endian, отслеживание NAT Rebinding)
    pub client_port: u16,
    /// Явное выравнивание до 40 байт (всегда 0)
    pub _pad: u16,
}

/// Запись маршрутизации в `ASTPL_EGRESS_MAP` (ключ — `assigned_ip: u32` в Big-Endian).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EgressRoutingData {
    /// 64-битный мастер-ключ сессии для `Xoroshiro128+`
    pub crypto_seed: u64,
    /// Счётчик отправленных байт (для синхронизации с `ClientRegistry`)
    pub tx_bytes: u64,
    /// Таймстемп `bpf_ktime_get_ns()` последней отправки
    pub last_seen_ns: u64,
    /// Текущий внешний IPv4 клиента в интернете (Big-Endian, обновляется из XDP при роуминге)
    pub dst_ip: u32,
    /// 4-байтный идентификатор сессии для заголовка ASTP-L (Big-Endian)
    pub nonce_prefix: u32,
    /// Счётчик исходящих пакетов (Host-Order, инкрементируется в eBPF, `>= 1`)
    pub tx_seq: u32,
    /// Текущий внешний UDP-порт клиента (Big-Endian, обновляется из XDP при роуминге)
    pub dst_port: u16,
    /// Явное выравнивание до 40 байт (всегда 0)
    pub _pad: u16,
}

/// Потоковый шифр на базе ГПСЧ `Xoroshiro128+` с 2-раундовым прогревом состояния.
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
        // Обязательный прогрев (2 раунда), чтобы первый блок гаммы не был линейной суммой seed и seq
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

    /// Поблочное (по 8 байт Little-Endian + хвост 1..7 байт) наложение гаммы на буфер.
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

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateRule {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EdtState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TokenBucketState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for AstplConfig {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for IngressSessionData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EgressRoutingData {}
