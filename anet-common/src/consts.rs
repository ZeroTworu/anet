// Все константы обсалютно научны, и соответствуют числу тараканов на лолу и кол-ву бычков в пепельнице.
// Не научные - числу мух на потолке.
pub const MAX_PACKET_SIZE: usize = 65535;

pub const CHANNEL_BUFFER_SIZE: usize = 65535;

pub const READ_TIMEOUT_SECONDS: u64 = 30;

pub const WRITE_TIMEOUT_SECONDS: u64 = 30;

pub const PACKET_TYPE_DATA: u8 = 0x01;

pub const AUTH_MAGIC_ID_BASE: [u8; 4] = [0x7A, 0xC5, 0x1E, 0x2B];

pub const AUTH_SALT_LEN: usize = 4;

pub const AUTH_PREFIX_LEN: usize = 8;

pub const UDP_HANDSHAKE_TIMEOUT_SECONDS: u64 = 30;

pub const VPN_STREAM_WINDOW: u64 = 8_388_608;

pub const NONCE_PREFIX_LEN: usize = 4;

pub const NONCE_LEN: usize = 12;

pub const PADDING_MTU: usize = 1450;

pub const PROTO_PAD_FIELD_OVERHEAD: usize = 3;
