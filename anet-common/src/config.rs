use crate::boring_tls::{TlsClientConfig, TlsFingerprint, TlsFragConfig};
use crate::consts::{
    MAX_VIDEO_BATCH_BYTES, WRTC_BATCHER_MAX_BYTES, WRTC_BATCHER_MAX_DELAY_MS,
    WRTC_COLIBRI_WS_READ_TIMEOUT_SECS, WRTC_DOWNLINK_PACING_NS_PER_BYTE, WRTC_MIN_TUN_MTU,
    WRTC_PACING_HORIZON_NS, WRTC_TCP_PORT_HOP_ATTEMPTS, WRTC_TCP_PORT_HOP_TIMEOUT_MS,
    WRTC_UDP_ICE_SOCKET_COUNT, WRTC_UPLINK_BURST_MAX_PACKETS, WRTC_UPLINK_PACING_NS_PER_BYTE,
    WRTC_VIDEO_BATCH_MAX_PACKETS, WRTC_VIDEO_MTU_OVERHEAD,
};
use serde::{Deserialize, Deserializer, Serialize};

fn default_tls_verify_peer() -> bool {
    true
}

fn default_tls_frag_length() -> String {
    "10..20".to_string()
}

fn default_tls_frag_delay_ms() -> String {
    "0".to_string()
}

/// Разбирает диапазон в стиле Xcore (`"10..20"`, `"10-20"`, `"16"`), возвращая `(min, max)`.
/// Некорректные или пустые значения откатываются к `(default_lo, default_hi)` с нижней границей `min_allowed`.
pub fn parse_range_pair(
    raw: &str,
    default_lo: u64,
    default_hi: u64,
    min_allowed: u64,
) -> (u64, u64) {
    let trimmed = raw.trim();
    let (def_lo, def_hi) = (
        default_lo.max(min_allowed),
        default_hi.max(default_lo).max(min_allowed),
    );
    if trimmed.is_empty() {
        return (def_lo, def_hi);
    }

    let parsed = if let Some((a, b)) = trimmed.split_once("..") {
        match (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
            (Ok(x), Ok(y)) => Some((x, y)),
            _ => None,
        }
    } else if let Some((a, b)) = trimmed.split_once('-') {
        match (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
            (Ok(x), Ok(y)) => Some((x, y)),
            _ => None,
        }
    } else if let Ok(v) = trimmed.parse::<u64>() {
        Some((v, v))
    } else {
        None
    };

    match parsed {
        Some((a, b)) => {
            let lo = a.min(b).max(min_allowed);
            let hi = a.max(b).max(lo);
            (lo, hi)
        }
        None => (def_lo, def_hi),
    }
}

fn deserialize_range_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RangeOrInt {
        Str(String),
        Uint(u64),
        Int(i64),
    }
    match RangeOrInt::deserialize(deserializer)? {
        RangeOrInt::Str(s) => Ok(s),
        RangeOrInt::Uint(u) => Ok(u.to_string()),
        RangeOrInt::Int(i) => Ok(i.max(0).to_string()),
    }
}

fn deserialize_opt_range_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OptRangeOrInt {
        Str(String),
        Uint(u64),
        Int(i64),
    }
    match Option::<OptRangeOrInt>::deserialize(deserializer)? {
        None => Ok(None),
        Some(OptRangeOrInt::Str(s)) => {
            let t = s.trim();
            if t.is_empty() {
                Ok(None)
            } else {
                Ok(Some(t.to_string()))
            }
        }
        Some(OptRangeOrInt::Uint(u)) => Ok(Some(u.to_string())),
        Some(OptRangeOrInt::Int(i)) => Ok(Some(i.max(0).to_string())),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct StealthConfig {
    /// Минимальная задержка джиттера (наносекунды)
    pub min_jitter_ns: u64,
    /// Максимальная задержка джиттера (наносекунды)
    pub max_jitter_ns: u64,
    /// Шаг выравнивания паддинга (байты)
    pub padding_step: u16,

    /// Старая ASTP-фрагментация первого пакета рукопожатия (уровень L4 поверх UDP/TCP для QUIC и VNC).
    /// НЕ влияет на TLS ClientHello — для разрезки TLS рукопожатия используйте `tls_frag_enabled`.
    pub frag_enabled: bool,
    /// Минимальное число частей старой ASTP-фрагментации.
    pub frag_min_chunks: u8,
    /// Максимальное число частей старой ASTP-фрагментации.
    pub frag_max_chunks: u8,
    /// Диапазон числа частей старой ASTP-фрагментации в стиле Xcore (`"2..4"`).
    /// Если задан — имеет приоритет над `frag_min_chunks` / `frag_max_chunks`.
    #[serde(default, deserialize_with = "deserialize_opt_range_string")]
    pub frag_chunks: Option<String>,

    /// Включить L4 TCP-фрагментацию исходящего TLS `ClientHello` (`tlshello`) для обхода DPI/ТСПУ,
    /// режущего соединения по SNI или размеру первого TLS-рекорда (WSS, AHTTP, IMAPS, WRTC, TURNS).
    pub tls_frag_enabled: bool,
    /// Длина кусков TLS `ClientHello` в байтах в формате `"X..Y"` или `"N"` (по умолчанию `"10..20"`).
    #[serde(
        default = "default_tls_frag_length",
        deserialize_with = "deserialize_range_string"
    )]
    pub tls_frag_length: String,
    /// Межфрагментная пауза между кусками TLS `ClientHello` в миллисекундах (`"0"` или `"1..5"`).
    /// При `"0"` клиент всё равно сбрасывает и уступает управление планировщику, чтобы сегменты уходили раздельно.
    #[serde(
        default = "default_tls_frag_delay_ms",
        deserialize_with = "deserialize_range_string"
    )]
    pub tls_frag_delay_ms: String,

    /// Профиль TLS-отпечатка ClientHello и синхронизированных HTTP-заголовков:
    /// "auto" | "chrome" | "firefox" | "safari" | "randomized"
    pub tls_fingerprint: TlsFingerprint,

    /// Защита от активного спуфинга ТСПУ (MITM / подмены сертификата при TLS-рукопожатии).
    /// Строго опционально через конфиг, по умолчанию — включено (`true`).
    #[serde(default = "default_tls_verify_peer")]
    pub tls_verify_peer: bool,

    /// Опциональный SHA-256 пиннинг сертификата или публичного ключа (SPKI) сервера (Hex или Base64).
    pub tls_pin_sha256: Option<String>,

    /// Опциональный путь к PEM-файлу корневого/серверного сертификата или сам PEM-текст.
    pub tls_ca_cert: Option<String>,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            min_jitter_ns: 0,
            max_jitter_ns: 0,
            padding_step: 0,
            frag_enabled: false,
            frag_min_chunks: 2,
            frag_max_chunks: 3,
            frag_chunks: None,
            tls_frag_enabled: false,
            tls_frag_length: default_tls_frag_length(),
            tls_frag_delay_ms: default_tls_frag_delay_ms(),
            tls_fingerprint: TlsFingerprint::Auto,
            tls_verify_peer: true,
            tls_pin_sha256: None,
            tls_ca_cert: None,
        }
    }
}

impl StealthConfig {
    pub fn to_tls_frag_config(&self) -> TlsFragConfig {
        let (min_len, max_len) = parse_range_pair(&self.tls_frag_length, 10, 20, 1);
        let (min_delay_ms, max_delay_ms) = parse_range_pair(&self.tls_frag_delay_ms, 0, 0, 0);
        TlsFragConfig {
            enabled: self.tls_frag_enabled,
            min_len: min_len as usize,
            max_len: max_len as usize,
            min_delay_ms,
            max_delay_ms,
        }
    }

    pub fn to_tls_client_config(&self) -> TlsClientConfig {
        TlsClientConfig {
            fingerprint: self.tls_fingerprint,
            random_seed: rand::random(),
            verify_peer: self.tls_verify_peer,
            pin_sha256: self.tls_pin_sha256.clone(),
            ca_cert: self.tls_ca_cert.clone(),
            tls_frag: self.to_tls_frag_config(),
        }
    }
}

/// Тонкие настройки транспорта WebRTC (секции `[wrtc]` в `client.toml` и `server.toml`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct WrtcConfig {
    /// Таймаут установки TCP/TLS-соединения к HTTP API ВКС-провайдера (в секундах).
    pub http_connect_timeout_secs: u64,
    /// Общий таймаут выполнения HTTP-запросов авторизации и резолва комнаты (в секундах).
    pub http_request_timeout_secs: u64,
    /// Таймаут подключения и MUC-хендшейка сигналинга XMPP WebSocket (в секундах).
    pub xmpp_handshake_timeout_secs: u64,
    /// Таймаут отправки одного фрейма в WebSocket для Colibri-WS и XMPP-WS (в секундах).
    pub ws_write_timeout_secs: u64,
    /// Таймаут установки параллельного канала Colibri WebSocket до медиасервера JVB (в секундах).
    pub colibri_ws_connect_timeout_secs: u64,
    /// Таймаут чтения входящих кадров из Colibri WebSocket до его фонового переподключения (в секундах, по умолчанию 25 с).
    pub colibri_ws_read_timeout_secs: u64,

    /// Количество быстрых попыток смены эфемерного исходного TCP-порта (`src_port`) при обходе L4 ECMP / LAG фильтрации.
    pub tcp_port_hop_attempts: usize,
    /// Таймаут одной попытки `TcpStream::connect` при быстром переборе эфемерных TCP-портов (в миллисекундах).
    pub tcp_port_hop_timeout_ms: u64,
    /// Количество параллельных локальных UDP-сокетов (`0.0.0.0:0`) для сбора множественных ICE `host` кандидатов.
    pub udp_ice_socket_count: usize,

    /// Размер системных буферов приёма и отправки (`SO_RCVBUF` / `SO_SNDBUF`) UDP-сокета WebRTC (в байтах).
    pub udp_socket_buffer_size: usize,
    /// Количество потоков выделенного реактора обработки пакетов `webrtc-rs`.
    pub reactor_pool_size: usize,

    /// Таймаут перехода ICE-агента в состояние `Disconnected` при отсутствии пакетов (в миллисекундах).
    pub ice_disconnected_timeout_ms: u64,
    /// Таймаут окончательного разрыва ICE-соединения `Failed` (в миллисекундах).
    pub ice_failed_timeout_ms: u64,
    /// Интервал отправки STUN Consent Freshness / ICE keepalive запросов (в миллисекундах).
    pub ice_keepalive_interval_ms: u64,
    /// Максимальный интервал проактивного обновления TURN-аллокации и учётных данных (Refresh) (в секундах).
    pub turn_refresh_interval_secs: u64,
    /// Разрешить использование TURN и TURNS (`turns_proxy`) релеев для `PeerConnection` к медиасерверу JVB.
    /// При `false` для связи с JVB используются только прямые UDP кандидаты (`host` + STUN `srflx`),
    /// что исключает двойной релей через TURN/TCP-прокси и таймауты `TURN transaction timed out` при работе через WARP.
    pub jvb_use_turn: bool,
    /// Режим приоритета `TURNS Proxy` (TLS 1.3 поверх TCP:443, RFC 5766) для условий «БС» / жесткого бана UDP.
    /// При `true` автоматически поднимает локальный прокси TURNS TCP:443 в приоритетном `Tier 2` (вместо заслона `Tier 0: STUN`).
    pub turns_proxy_priority: bool,

    /// Максимальный размер буфера приёма SCTP DataChannel (в байтах).
    pub sctp_max_receive_buffer_size: u32,
    /// MTU для SCTP-фреймов внутри DTLS (в байтах).
    pub sctp_mtu: u32,
    /// Максимальный размер буфера приёма входящих UDP/RTP-пакетов в движке WebRTC (в байтах).
    pub receive_mtu: usize,

    /// Суммарный сетевой оверхед инкапсуляции `media_video` (IPv4 + UDP + SRTP + RTP + VP8 + Tag + ASTP, в байтах),
    /// вычитаемый из MTU сервера для предотвращения фрагментации и дропов на пограничных каналах.
    pub video_mtu_overhead: u16,
    /// Минимально допустимый MTU TUN-интерфейса после вычета `video_mtu_overhead` (в байтах).
    pub min_tun_mtu: u16,
    /// Верхний предел размера полезной нагрузки микро-батча для одного VP8 RTP кадра (в байтах).
    pub max_video_batch_bytes: usize,
    /// Максимальное количество IP-пакетов, склеиваемых в один VP8 RTP микро-батч (`1` отключает склейку).
    pub video_batch_max_packets: usize,
    /// Максимальное число пакетов, вычитываемых из TUN за один цикл отправки.
    pub uplink_burst_max_packets: usize,
    /// Максимальный размер пачки пакетов (в байтах) для `PacketBatcher` (Colibri-WS / DataChannel).
    pub ws_batcher_max_bytes: usize,
    /// Максимальная задержка накопления пачки (в миллисекундах) для `PacketBatcher`.
    pub ws_batcher_max_delay_ms: u64,
    /// Интервал отправки фоновых пустых ключевых кадров VP8 во время простоя туннеля (в миллисекундах).
    pub video_keepalive_interval_ms: u64,
    /// Пейсинг EDT micro-pacer на Downlink сервером (нc/байт; `18` ≈ 444 Мбит/с, `0` — отключить pacing).
    pub downlink_pacing_ns_per_byte: u64,
    /// Пейсинг EDT micro-pacer на Uplink клиентом (нc/байт; `22` ≈ 363 Мбит/с, `0` — отключить pacing).
    pub uplink_pacing_ns_per_byte: u64,
    /// Горизонт накопления EDT micro-pacer в наносекундах (по умолчанию `3_000_000`, т.е. 3 мс).
    pub pacing_horizon_ns: u64,

    /// Время нахождения PeerConnection в состоянии `Disconnected` (в секундах),
    /// после которого сторожевой таймер принудительно пересоздаёт сессию.
    pub watchdog_disconnected_timeout_secs: u64,
    /// Льготный период на старте сессии (в секундах) для открытия хотя бы одного сигнального канала (DataChannel или Colibri-WS).
    pub watchdog_channel_grace_secs: u64,
    /// Таймаут корректного закрытия `PeerConnection` при завершении сессии (в секундах).
    pub peer_close_timeout_secs: u64,

    /// Интервал отправки внутритуннельных `anet_ping` сообщений от клиента к серверу (в секундах).
    pub tunnel_ping_interval_secs: u64,
    /// Таймаут ожидания `anet_pong` от сервера до разрыва и переподключения клиента (в секундах).
    pub tunnel_ping_timeout_secs: u64,
    /// Время ожидания клиентов в пустой комнате ВКС на сервере до плановой ротации сессии (в секундах).
    pub server_idle_room_rotation_secs: u64,
}

impl Default for WrtcConfig {
    fn default() -> Self {
        Self {
            http_connect_timeout_secs: 10,
            http_request_timeout_secs: 15,
            xmpp_handshake_timeout_secs: 15,
            ws_write_timeout_secs: 15,
            colibri_ws_connect_timeout_secs: 10,
            colibri_ws_read_timeout_secs: WRTC_COLIBRI_WS_READ_TIMEOUT_SECS,
            tcp_port_hop_attempts: WRTC_TCP_PORT_HOP_ATTEMPTS,
            tcp_port_hop_timeout_ms: WRTC_TCP_PORT_HOP_TIMEOUT_MS,
            udp_ice_socket_count: WRTC_UDP_ICE_SOCKET_COUNT,
            udp_socket_buffer_size: 8 * 1024 * 1024,
            reactor_pool_size: 4,
            ice_disconnected_timeout_ms: 10_000,
            ice_failed_timeout_ms: 25_000,
            ice_keepalive_interval_ms: 2_000,
            turn_refresh_interval_secs: 90,
            jvb_use_turn: false,
            turns_proxy_priority: false,
            sctp_max_receive_buffer_size: 8 * 1024 * 1024,
            sctp_mtu: 1200,
            receive_mtu: 1600,
            video_mtu_overhead: WRTC_VIDEO_MTU_OVERHEAD,
            min_tun_mtu: WRTC_MIN_TUN_MTU as u16,
            max_video_batch_bytes: MAX_VIDEO_BATCH_BYTES,
            video_batch_max_packets: WRTC_VIDEO_BATCH_MAX_PACKETS,
            uplink_burst_max_packets: WRTC_UPLINK_BURST_MAX_PACKETS,
            ws_batcher_max_bytes: WRTC_BATCHER_MAX_BYTES,
            ws_batcher_max_delay_ms: WRTC_BATCHER_MAX_DELAY_MS,
            video_keepalive_interval_ms: 1000,
            downlink_pacing_ns_per_byte: WRTC_DOWNLINK_PACING_NS_PER_BYTE,
            uplink_pacing_ns_per_byte: WRTC_UPLINK_PACING_NS_PER_BYTE,
            pacing_horizon_ns: WRTC_PACING_HORIZON_NS,
            watchdog_disconnected_timeout_secs: 8,
            watchdog_channel_grace_secs: 12,
            peer_close_timeout_secs: 3,
            tunnel_ping_interval_secs: 15,
            tunnel_ping_timeout_secs: 45,
            server_idle_room_rotation_secs: 1800,
        }
    }
}

/// Настройки фоновой диагностики сетевой связности и индикатора пульса (секция `[connectivity]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct ConnectivityConfig {
    /// Включить фоновый мониторинг состояния сети и контрольных точек (`true` / `false`).
    pub enabled: bool,

    /// Интервал отправки внутритуннельных ICMP-пингов для замера RTT при активном VPN (в секундах, рекомендуется 1–2 с).
    pub ping_interval_secs: u64,

    /// Интервал опроса глобальных и локальных контрольных точек для диагностики маршрутов (в секундах, рекомендуется 2–6 с).
    #[serde(alias = "interval_secs")]
    pub probe_interval_secs: u64,

    /// Таймаут ожидания ответа от одной контрольной точки (в миллисекундах).
    pub timeout_ms: u64,

    /// Глобальные контрольные точки для проверки доступности внешних международных маршрутов.
    pub global_targets: Vec<String>,

    /// Локальные контрольные точки для определения режима ограниченной внутренней связности.
    pub domestic_targets: Vec<String>,
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ping_interval_secs: 2,
            probe_interval_secs: 4,
            timeout_ms: 2500,
            global_targets: vec![
                "https://www.google.com/generate_204".to_string(),
                "https://connectivitycheck.gstatic.com/generate_204".to_string(),
                "https://store.steampowered.com/favicon.ico".to_string(),
            ],
            domestic_targets: vec![
                "https://ya.ru".to_string(),
                "https://vk.com".to_string(),
                "https://dzen.ru".to_string(),
            ],
        }
    }
}

impl ConnectivityConfig {
    /// Извлекает `ConnectivityConfig` из произвольной строки TOML.
    /// Поддерживает как штатную секцию `[connectivity]`, так и резервный поиск `global_targets` / `domestic_targets`,
    /// если они случайно оказались в корне, в `[main]`, `[wrtc]`, `[routing]` или после `[[servers]]`.
    pub fn from_toml_str(raw_toml: &str) -> Self {
        let mut cfg = Self::default();
        cfg.apply_toml_fallbacks(raw_toml);
        cfg
    }

    pub fn apply_toml_fallbacks(&mut self, raw_toml: &str) {
        let Ok(root_val) = toml::from_str::<toml::Value>(raw_toml) else {
            return;
        };
        let Some(root_table) = root_val.as_table() else {
            return;
        };

        let mut has_explicit_global = false;
        let mut has_explicit_domestic = false;

        if let Some(conn_val) = root_table.get("connectivity") {
            if let Some(conn_table) = conn_val.as_table() {
                has_explicit_global = conn_table.contains_key("global_targets");
                has_explicit_domestic = conn_table.contains_key("domestic_targets");
            }
            if let Ok(parsed) = conn_val.clone().try_into::<ConnectivityConfig>() {
                *self = parsed;
            }
        }

        if !has_explicit_global {
            if let Some(targets) = find_string_array_in_toml(root_table, "global_targets") {
                if !targets.is_empty() {
                    self.global_targets = targets;
                }
            }
        }

        if !has_explicit_domestic {
            if let Some(targets) = find_string_array_in_toml(root_table, "domestic_targets") {
                if !targets.is_empty() {
                    self.domestic_targets = targets;
                }
            }
        }
    }
}

fn extract_non_empty_string_vec(val: &toml::Value) -> Option<Vec<String>> {
    let arr = val.as_array()?;
    let vec: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(str::trim))
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if vec.is_empty() { None } else { Some(vec) }
}

fn find_string_array_in_toml(
    root: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Option<Vec<String>> {
    if let Some(v) = root.get(key).and_then(extract_non_empty_string_vec) {
        return Some(v);
    }
    for (section_name, section_val) in root {
        if section_name == "connectivity" {
            continue;
        }
        if let Some(table) = section_val.as_table() {
            if let Some(v) = table.get(key).and_then(extract_non_empty_string_vec) {
                return Some(v);
            }
        } else if let Some(arr) = section_val.as_array() {
            for item in arr.iter().rev() {
                if let Some(table) = item.as_table() {
                    if let Some(v) = table.get(key).and_then(extract_non_empty_string_vec) {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// Пользовательское описание или переопределение браузерного профиля (`[[browser_profiles]]` в `client.toml` и `server.toml`).
/// Позволяет переопределять параметры встроенных профилей (`Chrome`, `Firefox`, `Safari`) без пересборки бинарника.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct BrowserProfileConfig {
    /// Имя профиля ("Chrome", "Firefox", "Safari"). Сопоставляется без учёта регистра.
    pub name: String,
    /// Список шифров TLS 1.2 в формате BoringSSL (`SSL_CTX_set_cipher_list`).
    pub cipher_list: Option<String>,
    /// Список эллиптических кривых / групп (`SSL_CTX_set1_curves_list`).
    pub curves: Option<String>,
    /// Список алгоритмов подписи (`SSL_CTX_set1_sigalgs_list`).
    pub sigalgs: Option<String>,
    /// Включить TLS GREASE (`SSL_CTX_set_grease_enabled`).
    pub grease: Option<bool>,
    /// Включить случайную перестановку расширений ClientHello (`SSL_CTX_set_permute_extensions`).
    pub permute_extensions: Option<bool>,
    /// Включить поддержку TLS Session Ticket (`false` выставляет `SslOptions::NO_TICKET`).
    pub session_ticket: Option<bool>,
    /// Включить расширение `status_request` / OCSP Stapling (`0x0005`).
    pub ocsp_stapling: Option<bool>,
    /// Включить расширение `signed_certificate_timestamp` / SCT (`0x0012`).
    pub signed_cert_timestamps: Option<bool>,
    /// Флаг ECH GREASE (`0xfe0d`) в профиле браузера.
    pub ech_grease: Option<bool>,
    /// Флаг ALPS для `h2` (`0x4469`) в профиле браузера.
    pub alps_h2: Option<bool>,
    /// Список алгоритмов сжатия сертификатов (`0x001b`, например `["brotli"]` или `["zlib", "brotli"]`).
    pub cert_compression: Vec<String>,
    /// Пул строк `User-Agent`, из которых случайно выбирается одна на сессию.
    pub user_agents: Vec<String>,
    /// Дополнительные или переопределяемые HTTP-заголовки в формате `"Header-Name: Value"`.
    pub headers: Vec<String>,
    /// Порядок заголовков при формировании HTTP/1.1 WebSocket Upgrade запроса.
    pub ws_headers_order: Vec<String>,
    /// Начальный размер окна потока HTTP/2 (`SETTINGS_INITIAL_WINDOW_SIZE`).
    pub h2_initial_stream_window_size: Option<u32>,
    /// Начальный размер окна соединения HTTP/2 (`WINDOW_UPDATE`).
    pub h2_initial_connection_window_size: Option<u32>,
    /// Максимальный размер списка заголовков HTTP/2 (`SETTINGS_MAX_HEADER_LIST_SIZE`).
    pub h2_max_header_list_size: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_range_pair_supports_xcore_syntax() {
        assert_eq!(parse_range_pair("10..20", 8, 16, 1), (10, 20));
        assert_eq!(parse_range_pair(" 20 .. 10 ", 8, 16, 1), (10, 20));
        assert_eq!(parse_range_pair("5-15", 8, 16, 1), (5, 15));
        assert_eq!(parse_range_pair("16", 8, 16, 1), (16, 16));
        assert_eq!(parse_range_pair("0", 10, 20, 1), (1, 1));
        assert_eq!(parse_range_pair("", 10, 20, 1), (10, 20));
        assert_eq!(parse_range_pair("bad", 10, 20, 1), (10, 20));
    }

    #[test]
    fn stealth_config_deserializes_tlshello_and_astp_ranges() {
        let raw = r#"
            frag_enabled = true
            frag_chunks = "3..6"
            tls_frag_enabled = true
            tls_frag_length = "12..24"
            tls_frag_delay_ms = "1..3"
        "#;
        let cfg: StealthConfig = toml::from_str(raw).unwrap();
        assert!(cfg.frag_enabled);
        assert_eq!(cfg.frag_chunks.as_deref(), Some("3..6"));
        assert!(cfg.tls_frag_enabled);
        let tls_frag = cfg.to_tls_frag_config();
        assert!(tls_frag.enabled);
        assert_eq!(tls_frag.min_len, 12);
        assert_eq!(tls_frag.max_len, 24);
        assert_eq!(tls_frag.min_delay_ms, 1);
        assert_eq!(tls_frag.max_delay_ms, 3);
    }
}
