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

/// Formats a continuous base32 string into DNS labels of up to `max_label_len` chars (standard 63), separated by dots.
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

/// Joins DNS labels back into a continuous base32 string by removing all dots.
pub fn join_labels(domain_prefix: &str) -> String {
    domain_prefix.replace('.', "")
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
        }
    }

    #[test]
    fn test_case_insensitivity_and_dots() {
        let data = b"DNS over HTTPS";
        let enc = encode(data);
        let labels = split_into_labels(&enc, 5);
        let upper_labels = labels.to_uppercase();
        let dec = decode(&upper_labels).expect("decode with uppercase and dots failed");
        assert_eq!(dec.as_slice(), data);
    }
}
