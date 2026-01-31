// Все константы обсалютно научны, и соответствуют числу тараканов на лолу и кол-ву бычков в пепельнице.
// Не научные - числу мух на потолке.
// Убраны: AUTH_MAGIC_ID_BASE, AUTH_SALT_LEN, AUTH_PREFIX_LEN

pub const MAX_PACKET_SIZE: usize = 65535;
pub const CHANNEL_BUFFER_SIZE: usize = 65535;
pub const READ_TIMEOUT_SECONDS: u64 = 30;
pub const WRITE_TIMEOUT_SECONDS: u64 = 30;
pub const PACKET_TYPE_DATA: u8 = 0x01;
pub const UDP_HANDSHAKE_TIMEOUT_SECONDS: u64 = 30;
pub const VPN_STREAM_WINDOW: u64 = 8_388_608;
pub const NONCE_PREFIX_LEN: usize = 4;
pub const NONCE_LEN: usize = 12;
pub const PADDING_MTU: usize = 1450;
pub const PROTO_PAD_FIELD_OVERHEAD: usize = 3;

// Минимальный размер пакета рукопожатия для фильтрации мусора на сервере
// Nonce (12) + Tag (16) + Min Protobuf (~50)
pub const MIN_HANDSHAKE_LEN: usize = 78;
