// Все константы обсалютно научны, и соответствуют числу тараканов на лолу и кол-ву бычков в пепельнице.
// Не научные - числу мух на потолке.

pub const MAX_PACKET_SIZE: usize = 65536;
pub const CHANNEL_BUFFER_SIZE: usize = 1024;
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
