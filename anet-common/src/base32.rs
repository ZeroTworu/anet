const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Debug, PartialEq, Eq)]
pub enum Base32Error {
    InvalidCharacter(char),
    InvalidLength,
}

impl std::fmt::Display for Base32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Base32Error::InvalidCharacter(c) => write!(f, "Invalid base32 character: '{}'", c),
            Base32Error::InvalidLength => write!(f, "Invalid base32 length or remaining bits"),
        }
    }
}

impl std::error::Error for Base32Error {}

/// Encodes raw bytes to RFC 4648 Base32 string without padding, using lowercase alphabet 'a-z2-7'.
pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut result = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

/// Decodes an RFC 4648 Base32 string (case-insensitive, ignores internal dots) into raw bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, Base32Error> {
    let mut result = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for ch in input.chars() {
        if ch == '.' || ch == '-' {
            continue; // Skip domain label separators
        }
        let val = match ch {
            'a'..='z' => (ch as u8 - b'a') as u64,
            'A'..='Z' => (ch as u8 - b'A') as u64,
            '2'..='7' => (ch as u8 - b'2' + 26) as u64,
            _ => return Err(Base32Error::InvalidCharacter(ch)),
        };

        buffer = (buffer << 5) | val;
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            result.push(((buffer >> bits_left) & 0xFF) as u8);
        }
    }

    Ok(result)
}

/// Formats a continuous base32/base36 string into DNS labels of up to `max_label_len` chars (standard 63), separated by dots.
pub fn split_into_labels(base32_str: &str, max_label_len: usize) -> String {
    let mut out = String::with_capacity(base32_str.len() + base32_str.len() / max_label_len + 1);
    let mut start = 0;
    while start < base32_str.len() {
        let end = (start + max_label_len).min(base32_str.len());
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&base32_str[start..end]);
        start = end;
    }
    out
}

/// Formats a continuous base32/base36 string into DNS labels while inserting up to 2 interior `'-'`
/// characters at deterministic positions derived from `salt` (when `salt > 0`).
/// Because both `decode` and `decode_base36` ignore `'-'` and `'.'`, salted QNAMEs decode to the
/// exact same bytes on the server while bypassing recursive resolver negative/SERVFAIL caching and query coalescing.
pub fn split_into_salted_labels(encoded: &str, max_label_len: usize, salt: u16) -> String {
    if salt == 0 || encoded.len() < 6 {
        return split_into_labels(encoded, max_label_len);
    }

    let safe_max = max_label_len.clamp(8, 63);
    // Reserve 2 chars in the first two labels so inserting '-' never exceeds 63 chars per label
    let chunk_step = safe_max - 1;
    let mut out = String::with_capacity(encoded.len() + encoded.len() / chunk_step + 4);
    let mut start = 0;
    let mut label_idx = 0usize;

    while start < encoded.len() {
        let end = (start + chunk_step).min(encoded.len());
        let slice = &encoded[start..end];
        if !out.is_empty() {
            out.push('.');
        }
        if label_idx < 2 && slice.len() >= 4 {
            let s_val = if label_idx == 0 {
                (salt as usize) & 0xFF
            } else {
                ((salt as usize) >> 8) ^ ((salt as usize) & 0x3F)
            };
            let insert_pos = 1 + (s_val % (slice.len() - 1));
            out.push_str(&slice[..insert_pos]);
            out.push('-');
            out.push_str(&slice[insert_pos..]);
        } else {
            out.push_str(slice);
        }
        start = end;
        label_idx += 1;
    }
    out
}

/// Joins DNS labels back into a continuous string by removing all dots and hyphens.
pub fn join_labels(domain_prefix: &str) -> String {
    domain_prefix
        .chars()
        .filter(|&c| c != '.' && c != '-')
        .collect()
}

const BASE36_CHARS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const B36_POWERS: [u64; 11] = [
    1,
    36,
    1_296,
    46_656,
    1_679_616,
    60_466_176,
    2_176_782_336,
    78_364_164_096,
    2_821_109_907_456,
    101_559_956_668_416,
    3_656_158_440_062_976,
];

/// Encodes raw bytes into lowercase Base36 ('0-9a-z') using 7-byte -> 11-char blocks (5.17 bits/char).
/// Tail blocks of 1..6 bytes are encoded into 2, 4, 5, 7, 8, 10 chars respectively.
pub fn encode_base36(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    const TAIL_CHARS: [usize; 8] = [0, 2, 4, 5, 7, 8, 10, 11];
    let full_blocks = data.len() / 7;
    let rem = data.len() % 7;
    let mut out = String::with_capacity(full_blocks * 11 + TAIL_CHARS[rem]);

    for chunk in data.chunks(7) {
        let mut val: u64 = 0;
        for &b in chunk {
            val = (val << 8) | (b as u64);
        }
        let clen = TAIL_CHARS[chunk.len()];
        let mut chars = [b'0'; 11];
        for i in (0..clen).rev() {
            chars[i] = BASE36_CHARS[(val % 36) as usize];
            val /= 36;
        }
        for &c in &chars[..clen] {
            out.push(c as char);
        }
    }

    out
}

/// Decodes a lowercase/uppercase Base36 string (ignoring dots) back into raw bytes.
pub fn decode_base36(input: &str) -> Result<Vec<u8>, Base32Error> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'.' && b != b'-')
        .collect();
    if clean.is_empty() {
        return Ok(Vec::new());
    }

    let full_blocks = clean.len() / 11;
    let rem = clean.len() % 11;
    let rem_bytes = match rem {
        0 => 0,
        2 => 1,
        4 => 2,
        5 => 3,
        7 => 4,
        8 => 5,
        10 => 6,
        _ => return Err(Base32Error::InvalidLength),
    };

    let mut out = Vec::with_capacity(full_blocks * 7 + rem_bytes);

    for chunk in clean.chunks(11) {
        let b_len = match chunk.len() {
            11 => 7,
            10 => 6,
            8 => 5,
            7 => 4,
            5 => 3,
            4 => 2,
            2 => 1,
            _ => return Err(Base32Error::InvalidLength),
        };
        let _ = B36_POWERS[0];
        let mut val: u64 = 0;
        for &ch in chunk {
            let digit = match ch {
                b'0'..=b'9' => (ch - b'0') as u64,
                b'a'..=b'z' => (ch - b'a' + 10) as u64,
                b'A'..=b'Z' => (ch - b'A' + 10) as u64,
                _ => return Err(Base32Error::InvalidCharacter(ch as char)),
            };
            val = val
                .checked_mul(36)
                .and_then(|v| v.checked_add(digit))
                .ok_or(Base32Error::InvalidLength)?;
        }
        for shift_idx in (0..b_len).rev() {
            out.push(((val >> (shift_idx * 8)) & 0xFF) as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"Hello, ANet DoH World! 1234567890",
        ];

        for &case in cases {
            let enc = encode(case);
            let dec = decode(&enc).expect("decode failed");
            assert_eq!(dec.as_slice(), case);

            let enc36 = encode_base36(case);
            let dec36 = decode_base36(&enc36).expect("decode_base36 failed");
            assert_eq!(dec36.as_slice(), case);
        }
    }

    #[test]
    fn test_case_insensitivity_and_dots() {
        let data = b"DNS over HTTPS with Base36 & Base32";
        let enc = encode(data);
        let labels = split_into_labels(&enc, 5);
        let upper_labels = labels.to_uppercase();
        let dec = decode(&upper_labels).expect("decode with uppercase and dots failed");
        assert_eq!(dec.as_slice(), data);

        let enc36 = encode_base36(data);
        let labels36 = split_into_labels(&enc36, 7);
        let upper36 = labels36.to_uppercase();
        let dec36 = decode_base36(&upper36).expect("decode_base36 with uppercase and dots failed");
        assert_eq!(dec36.as_slice(), data);
    }
}
