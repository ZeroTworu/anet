use crate::config::Config;
use anet_common::consts::{AUTH_PREFIX_LEN, MAX_PACKET_SIZE, NONCE_LEN};
use anet_common::crypto_utils::{self, derive_shared_key, generate_key_fingerprint, sign_data};
use anet_common::encryption::Cipher;
use anet_common::protocol::{
    AuthRequest, AuthResponse, DhClientExchange, EncryptedAuthRequest, EncryptedAuthResponse,
    Message as AnetMessage, message::Content,
};
use anyhow::{Context, Result};
use base64::prelude::*;
use bytes::{BufMut, Bytes, BytesMut};
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{info, warn};
use prost::Message;
use rand::RngCore;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_RETRIES: u32 = 10;
const INITIAL_DELAY: u64 = 5;
const MAX_DELAY: u64 = 60;

pub struct AuthHandler {
    server_addr: SocketAddr,
    server_public_key: VerifyingKey,
    ephemeral_secret: StaticSecret,
    signing_key: SigningKey,
    client_public_key: VerifyingKey,
    client_id: String,
}

impl AuthHandler {
    pub fn new(cfg: &Config) -> Result<Self> {
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);

        let private_key_bytes = BASE64_STANDARD
            .decode(&cfg.keys.private_key)
            .context("Failed to decode client private key")?;
        let signing_key = SigningKey::from_bytes(
            &private_key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid private key length"))?,
        );

        let client_public_key = signing_key.verifying_key();
        let client_id = generate_key_fingerprint(&client_public_key);

        let server_pub_bytes = BASE64_STANDARD
            .decode(&cfg.keys.server_pub_key)
            .context("Failed to decode server public key")?;
        let server_public_key = VerifyingKey::from_bytes(
            &server_pub_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid server public key length"))?,
        )?;

        Ok(Self {
            server_addr: cfg.main.address.parse()?,
            server_public_key,
            ephemeral_secret,
            signing_key,
            client_public_key,
            client_id,
        })
    }

    pub async fn authenticate(&self) -> Result<(AuthResponse, [u8; 32])> {
        let local_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let mut delay = INITIAL_DELAY;

        for attempt in 1..=MAX_RETRIES {
            match self.attempt_handshake(&local_socket, delay).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!(
                        "[AUTH] Handshake attempt {} failed: {}. Retrying...",
                        attempt, e
                    );
                    delay = (delay * 2).min(MAX_DELAY);
                    sleep(Duration::from_secs(delay)).await;
                }
            }
        }
        Err(anyhow::anyhow!(
            "Authentication failed after {} retries.",
            MAX_RETRIES
        ))
    }

    async fn attempt_handshake(
        &self,
        socket: &Arc<UdpSocket>,
        delay: u64,
    ) -> Result<(AuthResponse, [u8; 32])> {
        let client_pub_key = PublicKey::from(&self.ephemeral_secret);
        let client_signed_dh_key = sign_data(&self.signing_key, client_pub_key.as_bytes());
        let dh_init_msg = AnetMessage {
            content: Some(Content::DhClientExchange(DhClientExchange {
                public_key: client_pub_key.as_bytes().to_vec(),
                client_signed_dh_key,
                client_public_key: self.client_public_key.to_bytes().to_vec(),
            })),
        };
        let request_packet = self.create_obf_packet(&dh_init_msg)?;
        info!("[AUTH] Phase I: Sending DH exchange request.");
        socket
            .send_to(&request_packet, self.server_addr)
            .await
            .context("Failed Phase I send")?;

        let (response_buf, len) = self.wait_for_response(socket, delay).await?;
        let shared_key = self.handle_phase_ii_response(&response_buf, len)?;
        info!("[AUTH] Phase II complete. Shared secret derived.");

        self.perform_phase_iii_iv(socket, shared_key, delay).await
    }

    fn handle_phase_ii_response(&self, response_buf: &[u8], len: usize) -> Result<[u8; 32]> {
        let response_message = self.decode_obf_response(response_buf, len)?;
        let (server_pub_key_bytes, server_signature) = match response_message.content {
            Some(Content::DhServerExchange(dh)) if dh.public_key.len() == 32 => {
                (dh.public_key, dh.server_signed_dh_key)
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unexpected or invalid response in Phase II"
                ));
            }
        };

        crypto_utils::verify_signature(
            &self.server_public_key,
            &server_pub_key_bytes,
            &server_signature,
        )
        .context("Server signature verification failed")?;
        info!("[AUTH] Server signature verified successfully.");

        let server_key_array: [u8; 32] = server_pub_key_bytes
            .as_slice()
            .try_into()
            .context("Failed to convert server public key bytes to a fixed-size array")?;

        let server_pub_key = PublicKey::from(server_key_array);
        let shared_secret = self.ephemeral_secret.diffie_hellman(&server_pub_key);
        Ok(derive_shared_key(&shared_secret))
    }

    async fn perform_phase_iii_iv(
        &self,
        socket: &Arc<UdpSocket>,
        shared_key: [u8; 32],
        delay: u64,
    ) -> Result<(AuthResponse, [u8; 32])> {
        let (request_packet, cipher) = self.create_encrypted_auth_request(&shared_key)?;
        info!(
            "[AUTH] Phase III: Sending Encrypted Auth Request ({} bytes).",
            request_packet.len()
        );
        socket
            .send_to(&request_packet, self.server_addr)
            .await
            .context("Failed Phase III send")?;

        let (response_buf, len) = self.wait_for_response(socket, delay).await?;
        let response_message = self.decode_obf_response(&response_buf, len)?;

        if let Some(Content::EncryptedAuthResponse(enc_res)) = response_message.content {
            let auth_response = self.decrypt_auth_response(enc_res, &cipher)?;
            info!("[AUTH] Phase IV complete: Auth Response decrypted successfully.");
            Ok((auth_response, shared_key))
        } else {
            Err(anyhow::anyhow!("Unexpected Phase IV response content"))
        }
    }

    fn create_encrypted_auth_request(&self, shared_key: &[u8; 32]) -> Result<(Bytes, Cipher)> {
        let auth_payload = AnetMessage {
            content: Some(Content::AuthRequest(AuthRequest {
                client_id: self.client_id.clone(),
            })),
        };
        let mut raw_auth_request = Vec::new();
        auth_payload.encode(&mut raw_auth_request)?;

        let req_cipher = Cipher::new(shared_key);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = req_cipher.encrypt(&nonce_bytes, Bytes::from(raw_auth_request))?;

        let encrypted_req = EncryptedAuthRequest {
            ciphertext: ciphertext.to_vec(),
            nonce: nonce_bytes.to_vec(),
        };
        let wrapped_msg = AnetMessage {
            content: Some(Content::EncryptedAuthRequest(encrypted_req)),
        };
        let mut final_data = Vec::new();
        wrapped_msg.encode(&mut final_data)?;

        let prefix_info = crypto_utils::generate_prefix_with_salt();
        crypto_utils::xor_bytes(&mut final_data, &prefix_info.salt);

        let mut final_packet_obf = BytesMut::new();
        final_packet_obf.put_slice(&prefix_info.prefix);
        final_packet_obf.put_slice(&final_data);
        Ok((final_packet_obf.freeze(), req_cipher))
    }

    fn create_obf_packet(&self, message: &AnetMessage) -> Result<Bytes> {
        let mut request_data = Vec::new();
        message.encode(&mut request_data)?;
        let prefix_info = crypto_utils::generate_prefix_with_salt();
        crypto_utils::xor_bytes(&mut request_data, &prefix_info.salt);
        let mut packet = BytesMut::new();
        packet.put_slice(&prefix_info.prefix);
        packet.put_slice(&request_data);
        Ok(packet.freeze())
    }

    async fn wait_for_response(
        &self,
        socket: &Arc<UdpSocket>,
        delay: u64,
    ) -> Result<(Box<[u8]>, usize)> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE].into_boxed_slice();
        info!("[AUTH] Waiting for response for {} seconds...", delay);
        let (len, recv_addr) =
            tokio::time::timeout(Duration::from_secs(delay), socket.recv_from(&mut buf)).await??;
        if recv_addr != self.server_addr {
            return Err(anyhow::anyhow!(
                "Received packet from unexpected address {}",
                recv_addr
            ));
        }
        Ok((buf, len))
    }

    fn decode_obf_response(&self, response_buf: &[u8], len: usize) -> Result<AnetMessage> {
        if len <= AUTH_PREFIX_LEN {
            return Err(anyhow::anyhow!("Auth response too short"));
        }
        let prefix = &response_buf[..AUTH_PREFIX_LEN];
        if !crypto_utils::check_auth_prefix(prefix) {
            return Err(anyhow::anyhow!("Auth response prefix check failed"));
        }

        let salt =
            crypto_utils::extract_salt_from_prefix(prefix).context("Failed to extract salt")?;
        let mut payload = response_buf[AUTH_PREFIX_LEN..len].to_vec();
        crypto_utils::xor_bytes(&mut payload, &salt);

        Message::decode(Bytes::from(payload)).context("Failed to decode Protobuf message")
    }

    fn decrypt_auth_response(
        &self,
        enc_res: EncryptedAuthResponse,
        req_cipher: &Cipher,
    ) -> Result<AuthResponse> {
        if enc_res.nonce.len() != NONCE_LEN {
            return Err(anyhow::anyhow!("Invalid nonce length"));
        }

        let plaintext =
            req_cipher.decrypt(enc_res.nonce.as_slice(), Bytes::from(enc_res.ciphertext))?;
        let response_message: AnetMessage = Message::decode(plaintext)?;

        match response_message.content {
            Some(Content::AuthResponse(auth)) if !auth.quic_cert.is_empty() => Ok(auth),
            _ => Err(anyhow::anyhow!("Unexpected or invalid decrypted content")),
        }
    }
}
