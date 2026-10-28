use crate::boring_tls::{TlsClientConfig, TlsFingerprint};
use crate::consts::WRTC_VIDEO_MTU_OVERHEAD;
use serde::{Deserialize, Serialize};

fn default_tls_verify_peer() -> bool {
    true
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

    /// Фрагментировать самый первый пакет рукопожатия (до появления
    /// сессионного ключа, поэтому вне обычного padding/jitter-конвейера).
    pub frag_enabled: bool,
    /// Минимальное число частей, на которое дробится хендшейк.
    pub frag_min_chunks: u8,
    /// Максимальное число частей, на которое дробится хендшейк.
    pub frag_max_chunks: u8,

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
            tls_fingerprint: TlsFingerprint::Auto,
            tls_verify_peer: true,
            tls_pin_sha256: None,
            tls_ca_cert: None,
        }
    }
}

impl StealthConfig {
    pub fn to_tls_client_config(&self) -> TlsClientConfig {
        TlsClientConfig {
            fingerprint: self.tls_fingerprint,
            random_seed: rand::random(),
            verify_peer: self.tls_verify_peer,
            pin_sha256: self.tls_pin_sha256.clone(),
            ca_cert: self.tls_ca_cert.clone(),
        }
    }
}

/// Тонкие настройки транспорта WebRTC (секции `[wrtc]` в `client.toml` и `server.toml`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct WrtcConfig {
    /// Таймаут установки TCP/TLS-соединения к HTTP API Контур.Толк (в секундах).
    pub http_connect_timeout_secs: u64,
    /// Общий таймаут выполнения HTTP-запросов авторизации и резолва комнаты (в секундах).
    pub http_request_timeout_secs: u64,
    /// Таймаут подключения и MUC-хендшейка сигналинга XMPP WebSocket (в секундах).
    pub xmpp_handshake_timeout_secs: u64,
    /// Таймаут отправки одного фрейма в WebSocket для Colibri-WS и XMPP-WS (в секундах).
    pub ws_write_timeout_secs: u64,
    /// Таймаут установки параллельного канала Colibri WebSocket до медиасервера JVB (в секундах).
    pub colibri_ws_connect_timeout_secs: u64,

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

    /// Максимальный размер буфера приёма SCTP DataChannel (в байтах).
    pub sctp_max_receive_buffer_size: u32,
    /// MTU для SCTP-фреймов внутри DTLS (в байтах).
    pub sctp_mtu: u32,
    /// Максимальный размер буфера приёма входящих UDP/RTP-пакетов в движке WebRTC (в байтах).
    pub receive_mtu: usize,

    /// Суммарный сетевой оверхед инкапсуляции `media_video` (IPv4 + UDP + SRTP + RTP + VP8 + Tag + ASTP, в байтах),
    /// вычитаемый из MTU сервера для предотвращения фрагментации и дропов на пограничных каналах с PMTU 1400.
    pub video_mtu_overhead: u16,
    /// Интервал отправки фоновых пустых ключевых кадров VP8 во время простоя туннеля (в миллисекундах).
    pub video_keepalive_interval_ms: u64,

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
    /// Время ожидания клиентов в пустой комнате Контур.Толк на сервере до плановой ротации сессии (в секундах).
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
            udp_socket_buffer_size: 8 * 1024 * 1024,
            reactor_pool_size: 4,
            ice_disconnected_timeout_ms: 10_000,
            ice_failed_timeout_ms: 25_000,
            ice_keepalive_interval_ms: 2_000,
            turn_refresh_interval_secs: 90,
            sctp_max_receive_buffer_size: 8 * 1024 * 1024,
            sctp_mtu: 1200,
            receive_mtu: 1600,
            video_mtu_overhead: WRTC_VIDEO_MTU_OVERHEAD,
            video_keepalive_interval_ms: 1000,
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
