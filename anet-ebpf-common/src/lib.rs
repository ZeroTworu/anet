#![no_std]

//! Общие POD-типы карт между ядерной частью (`anet-ebpf`, `no_std`) и
//! управляющим кодом в `anet-server` (`feature = "user"`).

/// Имена BPF-карт — общие константы, чтобы не разъезжались строки между
/// ядерной и userspace частью.
pub const RULES: &str = "RATE_RULES";
pub const EDT_STATE: &str = "EDT_STATE";
pub const TB_STATE: &str = "TB_STATE";

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

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateRule {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EdtState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TokenBucketState {}
