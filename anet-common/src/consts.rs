// Все константы обсалютно научны, и соответствуют числу тараканов на лолу и кол-ву бычков в пепельнице.
// Не научные - числу мух на потолке.
pub const MAX_PACKET_SIZE: usize = 65536 * 2;

pub const CHANNEL_BUFFER_SIZE: usize = 16384;

pub const PACKETS_TO_YIELD: u16 = 100;

pub const READ_TIMEOUT_SECONDS: u64 = 60;

pub const WRITE_TIMEOUT_SECONDS: u64 = 60;
