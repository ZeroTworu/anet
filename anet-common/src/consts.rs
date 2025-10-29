// Все константы обсалютно научны, и соответствуют числу тараканов на лолу и кол-ву бычков в пепельнице.
// Не научные - числу мух на потолке.
pub const MAX_PACKET_SIZE: usize = 65535;

pub const CHANNEL_BUFFER_SIZE: usize = 65535;

pub const READ_TIMEOUT_SECONDS: u64 = 30;

pub const WRITE_TIMEOUT_SECONDS: u64 = 30;

pub const PACKET_TYPE_DATA: u8 = 0x01;

pub const PACKET_TYPE_HANDSHAKE: u8 = 0x02;

pub const UDP_HANDSHAKE_TIMEOUT_SECONDS: u64 = 30;

pub const VPN_STREAM_WINDOW: u64 = 8_388_608;
