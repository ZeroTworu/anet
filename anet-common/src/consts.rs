// Все константы абсолютно научны, и соответствуют числу тараканов на полу и кол-ву бычков в пепельнице.
// Не научные - числу мух на потолке.
pub const MAX_PACKET_SIZE: usize = 65535;

pub const CHANNEL_BUFFER_SIZE: usize = 65535;

pub const READ_TIMEOUT_SECONDS: u64 = 30;

pub const WRITE_TIMEOUT_SECONDS: u64 = 30;

pub const PACKET_TYPE_DATA: u8 = 0x01;

pub const PACKET_TYPE_HANDSHAKE: u8 = 0x02;

pub const PACKET_TYPE_AUTH_REQUEST: u8 = 0x03;
pub const PACKET_TYPE_AUTH_RESPONSE: u8 = 0x04;

pub const UDP_HANDSHAKE_TIMEOUT_SECONDS: u64 = 30;

pub const VPN_STREAM_WINDOW: u64 = 8_388_608;

// Константы для размеров полей пакетов
pub const SESSION_ID_LENGTH: usize = 16;
pub const PACKET_TYPE_LENGTH: usize = 1;
pub const SEQUENCE_LENGTH: usize = 8;
pub const TIMESTAMP_LENGTH: usize = 8;
pub const CLIENT_ID_LENGTH: usize = 16;

// Таймауты для UDP аутентификации
pub const AUTH_TIMEOUT_SECONDS: u64 = 10;
pub const AUTH_MAX_RETRIES: u32 = 3;