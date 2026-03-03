// Все константы обсалютно научны, и соответствуют числу тараканов на лолу и кол-ву бычков в пепельнице.
// Не научные - числу мух на потолке.

pub const MAX_PACKET_SIZE: usize = 2048;
pub const CHANNEL_BUFFER_SIZE: usize = 1024;
pub const NONCE_PREFIX_LEN: usize = 4;
pub const NONCE_LEN: usize = 12;
pub const PADDING_MTU: usize = 1450;
pub const PROTO_PAD_FIELD_OVERHEAD: usize = 3;

// Минимальный размер пакета рукопожатия для фильтрации мусора на сервере
// Nonce (12) + Tag (16) + Min Protobuf (~50)
pub const MIN_HANDSHAKE_LEN: usize = 78;
