// Все константы обсалютно научны, и соответствуют числу тараканов на лолу и кол-ву бычков в пепельнице.
// Не научные - числу мух на потолке.

pub const MAX_PACKET_SIZE: usize = 2048;
// Увеличено с 1024 до 4096 для сглаживания сетевого джиттера
pub const CHANNEL_BUFFER_SIZE: usize = 4096;
pub const NONCE_PREFIX_LEN: usize = 4;
pub const NONCE_LEN: usize = 12;
pub const PADDING_MTU: usize = 1450;
/// Nonce (12) + Poly1305 tag (16) + sequence (8) + payload length (2).
pub const TRANSPORT_ENVELOPE_OVERHEAD: usize = 38;
pub const PROTO_PAD_FIELD_OVERHEAD: usize = 3;

// Минимальный размер пакета рукопожатия для фильтрации мусора на сервере
// Nonce (12) + Tag (16) + Min Protobuf (~50)
pub const MIN_HANDSHAKE_LEN: usize = 78;

/// Бюджет коалесценции для группировки мелких IP-пакетов перед записью в сокет.
pub const COALESCE_BUDGET_BYTES: usize = 64 * 1024;

/// Безопасный бюджет коалесценции для SSH/VNC (16 KB)
/// Гарантирует, что размер пакета никогда не превысит стандартное окно SSH-канала (32 KB),
/// предотвращая переполнение буферов и панику CryptoVec::resize.
pub const CRYPTO_COALESCE_BUDGET_BYTES: usize = 16 * 1024;

pub const MAX_UDP_PAYLOAD_SIZE: usize = 1450;

// =========================================================================
// Константы транспорта WebRTC (Ktalk / Jitsi JVB / VP8 Media Video)
// =========================================================================

/// Минимальный валидный заголовок ключевого кадра VP8 (20 байт, 16x16, legacy).
/// Позволяет мосту JVB / SFU успешно валидировать битовый поток VP8
/// и форвардить пакеты подписчикам без отсечения по decode-timeout.
pub const VP8_KEYFRAME_HEADER: [u8; 20] = [
    0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00,
    0x10, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
    0x99, 0x84, 0x88, 0xfc,
];

/// Валидный заголовок ключевого кадра VP8 с разрешением 1920x1080 (FullHD, 20 байт).
/// Исключает занижение целевого битрейта в BitrateController JVB из-за 16x16 разрешения.
pub const VP8_KEYFRAME_1080P_HEADER: [u8; 20] = [
    0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x80, 0x07,
    0x38, 0x04, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
    0x99, 0x84, 0x88, 0xfc,
];

/// Валидный заголовок межкадрового пакета VP8 (P-frame / Interframe, bit 0 = 1, 20 байт).
/// Предотвращает сброс Vp8FrameMap и пересоздание контекста проекции на каждом пакете в SFU JVB.
pub const VP8_INTERFRAME_HEADER: [u8; 20] = [
    0x31, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x80, 0x07,
    0x38, 0x04, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
    0x99, 0x84, 0x88, 0xfc,
];

/// Общая 10-байтная сигнатура хвоста заголовка ANet VP8 (байты 10..20).
pub const VP8_HEADER_TAIL_MAGIC: [u8; 10] = [
    0x00, 0x47, 0x08, 0x85, 0x85, 0x88, 0x99, 0x84, 0x88, 0xfc,
];

/// Маркер микро-батча нескольких IP-пакетов внутри одного VP8 RTP кадра.
/// Любой валидный IPv4 (0x4x) или IPv6 (0x6x) пакет гарантированно не начинается с 0x00.
pub const VIDEO_BATCH_MARKER: u8 = 0x00;

/// Верхний предел размера полезной нагрузки микро-батча для одного VP8 RTP пакета (в байтах).
/// При оверхеде 110 байт даёт не более 1370 байт на физическом UDP-сокете (безопасно для PMTU 1400).
pub const MAX_VIDEO_BATCH_BYTES: usize = 1260;

/// Дефолтный полный сетевой оверхед инкапсуляции WebRTC Video (в байтах):
/// 20B (IPv4) + 8B (UDP) + 16B (SRTP) + 12B (RTP) + 4B (VP8 Desc) + 20B (VP8 Hdr) + 2B (Tag) + 28B (ASTP) = 110 байт.
pub const WRTC_VIDEO_MTU_OVERHEAD: u16 = 110;

/// Минимально допустимый MTU TUN-интерфейса после вычета заголовков WebRTC Video.
pub const WRTC_MIN_TUN_MTU: i32 = 1200;

/// Размер префикса VP8 + Client Tag перед зашифрованным ASTP-кадром в RTP-пакете:
/// 4B (VP8 Payload Descriptor) + 20B (VP8 Frame Header) + 2B (Client Tag) = 26 байт.
pub const VP8_ASTP_PREFIX_LEN: usize = 4 + VP8_KEYFRAME_HEADER.len() + 2;

/// Зарезервированный тег для широковещательных или нетегированных кадров.
pub const TAG_UNTAGGED: u16 = 0x0000;

/// Минимальная длина валидного тегированного ASTP-кадра внутри видеопотока:
/// 2B (Client Tag) + 12B (Nonce) + 20B (Min IPv4) + 16B (Poly1305 MAC) = 50 байт.
pub const WRTC_MIN_ASTP_VIDEO_FRAME_LEN: usize = 50;

/// Минимальный размер корректного IPv4-пакета (без опций).
pub const WRTC_MIN_IP_PACKET_LEN: usize = 20;

/// Параметры кодеков WebRTC (Opus / VP8).
pub const WRTC_OPUS_PAYLOAD_TYPE: u8 = 111;
pub const WRTC_OPUS_CLOCK_RATE: u32 = 48000;
pub const WRTC_OPUS_CHANNELS: u16 = 2;
pub const WRTC_OPUS_SILENCE_FRAME: [u8; 3] = [0xf8, 0xff, 0xfe];

pub const WRTC_VP8_PRIMARY_PAYLOAD_TYPE: u8 = 100;
pub const WRTC_VP8_FALLBACK_PAYLOAD_TYPE: u8 = 96;
pub const WRTC_VP8_CLOCK_RATE: u32 = 90000;
pub const WRTC_VP8_RTP_TS_STEP: u32 = 300;
pub const WRTC_DEFAULT_MAX_VIDEO_HEIGHT: u32 = 2160;

/// Параметры генерации ключевых кадров VP8 для прохождения фильтрации JVB SFU.
pub const WRTC_KEYFRAME_INTERVAL_MASK: u32 = 31;
pub const WRTC_INITIAL_FORCE_KEYFRAMES: u32 = 8;
pub const WRTC_REASSERT_FORCE_KEYFRAMES: u32 = 16;
pub const WRTC_BURST_KEYFRAME_COUNT: usize = 4;
pub const WRTC_BURST_KEYFRAME_INTERVAL_MS: u64 = 25;

/// Размеры внутренних очередей и буферов подсистемы WebRTC.
pub const WRTC_COLIBRI_CHANNEL_CAPACITY: usize = 16384;
pub const WRTC_VIDEO_CHANNEL_CAPACITY: usize = 32768;
pub const WRTC_WS_FALLBACK_CHANNEL_CAPACITY: usize = 8192;
pub const WRTC_P2P_CHANNEL_CAPACITY: usize = 4096;
pub const WRTC_XMPP_CHANNEL_CAPACITY: usize = 128;
pub const WRTC_XMPP_RAW_WS_CHANNEL_CAPACITY: usize = 32;
pub const WRTC_DUPLEX_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Параметры микро-батчирования и коалесценции пакетов в WebRTC.
pub const WRTC_BATCHER_MAX_BYTES: usize = 16384;
pub const WRTC_BATCHER_MAX_DELAY_MS: u64 = 2;
pub const WRTC_VIDEO_BATCH_MAX_PACKETS: usize = 16;
pub const WRTC_UPLINK_BURST_MAX_PACKETS: usize = 64;

/// Внутренние интервалы опроса ICE, ретраев DataChannel и фоновых задач.
pub const WRTC_ICE_GATHER_POLL_ATTEMPTS: usize = 50;
pub const WRTC_ICE_GATHER_POLL_INTERVAL_MS: u64 = 30;
pub const WRTC_P2P_ICE_GATHER_POLL_INTERVAL_MS: u64 = 50;
pub const WRTC_DC_SEND_MAX_RETRIES: usize = 3;
pub const WRTC_DC_SEND_RETRY_DELAY_MS: u64 = 10;
pub const WRTC_CONSTRAINTS_RETRY_ATTEMPTS: usize = 30;
pub const WRTC_CONSTRAINTS_RETRY_INTERVAL_MS: u64 = 100;
pub const WRTC_CLIENT_CONSTRAINTS_REASSERT_COUNT: usize = 10;
pub const WRTC_CLIENT_CONSTRAINTS_REASSERT_INTERVAL_SECS: u64 = 2;
pub const WRTC_WATCHDOG_TICK_SECS: u64 = 2;
pub const WRTC_DISCOVER_BROADCAST_INTERVAL_SECS: u64 = 2;
pub const WRTC_SERVER_RETRY_DELAY_SECS: u64 = 5;
pub const WRTC_SERVER_RECONNECT_PAUSE_SECS: u64 = 2;
pub const WRTC_HANDSHAKE_PROCESS_TIMEOUT_SECS: u64 = 10;
pub const WRTC_SDP_RENEGOTIATE_TIMEOUT_SECS: u64 = 5;

/// Дефолтные резервные реквизиты JVB при отсутствии кандидатов в Jingle.
pub const WRTC_DEFAULT_FALLBACK_JVB_IP: &str = "89.169.16.6";
pub const WRTC_DEFAULT_FALLBACK_JVB_PORT: u16 = 10002;