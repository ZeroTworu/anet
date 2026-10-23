use chacha20poly1305::chacha20::ChaCha20;
use chacha20poly1305::chacha20::cipher::{KeyIvInit, StreamCipher};

/// ASTP-L (ChaCha20 stream cipher mode with 0-byte overhead).
///
/// Designed specifically for extreme size-constrained environments (such as DNS queries)
/// where a 16-byte Poly1305 tag cannot be afforded.
#[derive(Clone)]
pub struct AstpLiteCipher {
    key: [u8; 32],
}

impl AstpLiteCipher {
    pub fn new(shared_key: &[u8; 32]) -> Self {
        Self { key: *shared_key }
    }

    /// Generates a deterministic 12-byte Nonce from `(sequence, session_id)`:
    /// `[sequence (4B BE)] || [session_id (4B BE)] || [0x00, 0x00, 0x00, 0x00]`
    #[inline]
    pub fn make_nonce(sequence: u32, session_id: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&sequence.to_be_bytes());
        nonce[4..8].copy_from_slice(&session_id.to_be_bytes());
        nonce
    }

    /// Encrypts or decrypts a buffer in-place by XORing it with the ChaCha20 keystream.
    ///
    /// Because ChaCha20 is a symmetric stream cipher, encryption and decryption are
    /// the exact same operation and add 0 bytes of overhead.
    pub fn apply_keystream(&self, sequence: u32, session_id: u32, data: &mut [u8]) {
        let nonce = Self::make_nonce(sequence, session_id);
        let mut cipher = ChaCha20::new((&self.key).into(), (&nonce).into());
        cipher.apply_keystream(data);
    }

    /// Encrypts or decrypts bytes, returning an allocated `Vec<u8>`.
    pub fn process_copy(&self, sequence: u32, session_id: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = data.to_vec();
        self.apply_keystream(sequence, session_id, &mut buf);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_stream_symmetry() {
        let key = [42u8; 32];
        let cipher = AstpLiteCipher::new(&key);

        let sequence = 1001;
        let session_id = 9999;
        let original_data = b"ANet DoH TUN Payload over DNS Query";

        let mut encrypted = original_data.to_vec();
        cipher.apply_keystream(sequence, session_id, &mut encrypted);

        // Ciphertext should differ from plaintext
        assert_ne!(&encrypted[..], &original_data[..]);
        assert_eq!(encrypted.len(), original_data.len()); // 0-byte overhead

        let mut decrypted = encrypted;
        cipher.apply_keystream(sequence, session_id, &mut decrypted);

        assert_eq!(&decrypted[..], &original_data[..]);
    }
}
