/// ASTP-L (RFC 8439 ChaCha20 stream cipher mode with 0-byte overhead).
///
/// Designed specifically for extreme size-constrained environments (such as DNS queries)
/// where a 16-byte Poly1305 tag cannot be afforded.
#[derive(Clone)]
pub struct AstpLiteCipher {
    key: [u8; 32],
}

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    // "expand 32-byte k"
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;

    for i in 0..8 {
        let offset = i * 4;
        state[4 + i] = u32::from_le_bytes([
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ]);
    }

    state[12] = counter;
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let mut working = state;
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(state[i]).to_le_bytes();
        let offset = i * 4;
        out[offset..offset + 4].copy_from_slice(&word);
    }
    out
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
        let mut counter = 0u32;
        for chunk in data.chunks_mut(64) {
            let block = chacha20_block(&self.key, counter, &nonce);
            for (b, k) in chunk.iter_mut().zip(block.iter()) {
                *b ^= *k;
            }
            counter = counter.wrapping_add(1);
        }
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
