use crate::config::CoreConfig;
use crate::events::{status, warn};
use anet_common::consts::{MAX_PACKET_SIZE, NONCE_LEN, PROTO_PAD_FIELD_OVERHEAD};
use anet_common::crypto_utils::{self, derive_shared_key, generate_key_fingerprint, sign_data};
use anet_common::encryption::Cipher;
use anet_common::padding_utils::{calculate_padding_needed, generate_random_padding};
use anet_common::protocol::{
    AuthRequest, AuthResponse, DhClientExchange, EncryptedAuthRequest, EncryptedAuthResponse,
    Message as AnetMessage, message::Content,
};
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anyhow::{Context, Result};
use async_trait::async_trait;
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
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::sleep;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_RETRIES: u32 = 10;
const INITIAL_DELAY: u64 = 5;
const MAX_DELAY: u64 = 60;

#[async_trait]
pub trait AuthChannel: Send + Sync {
    async fn send(&self, data: Bytes) -> Result<()>;
    async fn recv(&self, timeout: Duration) -> Result<Bytes>;
}

pub struct UdpAuthChannel {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
}

impl UdpAuthChannel {
    pub fn new(socket: Arc<UdpSocket>, target: SocketAddr) -> Self {
        Self { socket, target }
    }
}

#[async_trait]
impl AuthChannel for UdpAuthChannel {
    async fn send(&self, data: Bytes) -> Result<()> {
        self.socket.send_to(&data, self.target).await?;
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let (len, addr) = tokio::time::timeout(timeout, self.socket.recv_from(&mut buf))
            .await
            .context("UDP recv timeout")??;

        if addr != self.target {
            return Err(anyhow::anyhow!("Received packet from unexpected address"));
        }
        Ok(Bytes::copy_from_slice(&buf[..len]))
    }
}

pub struct StreamAuthChannel<S> {
    stream: Arc<Mutex<S>>,
}

impl<S> StreamAuthChannel<S> {
    pub fn new(stream: Arc<Mutex<S>>) -> Self {
        Self { stream }
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> AuthChannel for StreamAuthChannel<S> {
    async fn send(&self, data: Bytes) -> Result<()> {
        let mut stream = self.stream.lock().await;
        let framed = frame_packet(data);
        stream.write_all(&framed).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let stream_clone = self.stream.clone();

        let read_future = async move {
            let mut stream = stream_clone.lock().await;
            match read_next_packet(&mut *stream).await? {
                Some(packet) => Ok(packet),
                None => Err(anyhow::anyhow!("Stream closed (EOF)")),
            }
        };

        tokio::time::timeout(timeout, read_future)
            .await
            .context("Stream recv timeout")?
    }
}

pub struct AuthHandler {
    server_pub_key_bytes: Vec<u8>,
    server_public_key: VerifyingKey,
    ephemeral_secret: StaticSecret,
    signing_key: SigningKey,
    client_public_key: VerifyingKey,
    client_id: String,
    padding_step: u16,
}

impl AuthHandler {
    pub fn new(cfg: &CoreConfig) -> Result<Self> {
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
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid server public key length"))?,
        )?;

        Ok(Self {
            server_public_key,
            server_pub_key_bytes: server_pub_bytes,
            ephemeral_secret,
            signing_key,
            client_public_key,
            client_id,
            padding_step: cfg.stealth.padding_step,
        })
    }

    pub async fn authenticate(
        &self,
        channel: &dyn AuthChannel,
    ) -> Result<(AuthResponse, [u8; 32])> {
        let mut delay = INITIAL_DELAY;

        for attempt in 1..=MAX_RETRIES {
            match self.attempt_handshake(channel, delay).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!(
                        "[AUTH] Handshake attempt {} failed: {}. Retrying...",
                        attempt, e
                    );
                    warn(format!(
                        "[AUTH] Handshake attempt {} failed: {}",
                        attempt, e
                    ));
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
        channel: &dyn AuthChannel,
        delay: u64,
    ) -> Result<(AuthResponse, [u8; 32])> {
        let client_pub_key = PublicKey::from(&self.ephemeral_secret);
        let client_signed_dh_key = sign_data(&self.signing_key, client_pub_key.as_bytes());

        let mut dh_init_msg = AnetMessage {
            content: Some(Content::DhClientExchange(DhClientExchange {
                public_key: client_pub_key.as_bytes().to_vec(),
                client_signed_dh_key,
                client_public_key: self.client_public_key.to_bytes().to_vec(),
            })),
            padding: vec![],
        };

        let current_wire_len = dh_init_msg.encoded_len() + NONCE_LEN + PROTO_PAD_FIELD_OVERHEAD;
        let needed = calculate_padding_needed(current_wire_len, self.padding_step);
        dh_init_msg.padding = generate_random_padding(needed);

        let request_packet = self.create_handshake_packet(&dh_init_msg)?;

        info!("[AUTH] Phase I: Sending DH exchange request (Obfuscated).");
        status("[AUTH] Phase I: Sending DH exchange request.");

        channel
            .send(request_packet)
            .await
            .context("Failed Phase I send")?;

        let response_buf = channel.recv(Duration::from_secs(delay)).await?;

        let shared_key = self.handle_phase_ii_response(&response_buf)?;
        info!("[AUTH] Phase II complete. Shared secret derived.");
        status("[AUTH] Phase II complete. Shared secret derived.");

        self.perform_phase_iii_iv(channel, shared_key, delay).await
    }

    fn create_handshake_packet(&self, message: &AnetMessage) -> Result<Bytes> {
        let mut request_data = Vec::new();
        message.encode(&mut request_data)?;

        let cipher = crypto_utils::create_handshake_cipher(&self.server_pub_key_bytes);

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher.encrypt(&nonce, Bytes::from(request_data))?;

        let mut packet = BytesMut::with_capacity(NONCE_LEN + ciphertext.len());
        packet.put_slice(&nonce);
        packet.put(ciphertext);

        Ok(packet.freeze())
    }

    fn handle_phase_ii_response(&self, response_buf: &[u8]) -> Result<[u8; 32]> {
        let cipher = crypto_utils::create_handshake_cipher(&self.server_pub_key_bytes);

        if response_buf.len() < NONCE_LEN + 16 {
            return Err(anyhow::anyhow!("Response too short"));
        }

        let (nonce, ciphertext) = response_buf.split_at(NONCE_LEN);
        let plaintext = cipher
            .decrypt(nonce, Bytes::copy_from_slice(ciphertext))
            .context("Failed to decrypt Phase II response")?;

        let response_message: AnetMessage = Message::decode(plaintext)?;

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

        let server_key_array: [u8; 32] = server_pub_key_bytes
            .as_slice()
            .try_into()
            .context("Failed to convert server DH key")?;

        let server_pub_key = PublicKey::from(server_key_array);
        let shared_secret = self.ephemeral_secret.diffie_hellman(&server_pub_key);
        Ok(derive_shared_key(&shared_secret))
    }

    async fn perform_phase_iii_iv(
        &self,
        channel: &dyn AuthChannel,
        shared_key: [u8; 32],
        delay: u64,
    ) -> Result<(AuthResponse, [u8; 32])> {
        let (request_packet, cipher) = self.create_encrypted_auth_request(&shared_key)?;
        info!(
            "[AUTH] Phase III: Sending Encrypted Auth Request ({} bytes).",
            request_packet.len()
        );

        channel
            .send(request_packet)
            .await
            .context("Failed Phase III send")?;

        let response_buf = channel.recv(Duration::from_secs(delay)).await?;

        let handshake_cipher = crypto_utils::create_handshake_cipher(&self.server_pub_key_bytes);

        if response_buf.len() < NONCE_LEN {
            return Err(anyhow::anyhow!("Short response"));
        }
        let (nonce, ciphertext) = response_buf.split_at(NONCE_LEN);

        let plaintext_outer = handshake_cipher
            .decrypt(nonce, Bytes::copy_from_slice(ciphertext))
            .context("Failed to de-obfuscate Phase IV")?;

        let outer_msg: AnetMessage = Message::decode(plaintext_outer)?;

        if let Some(Content::EncryptedAuthResponse(enc_res)) = outer_msg.content {
            let auth_response = self.decrypt_auth_response(enc_res, &cipher)?;
            info!("[AUTH] Phase IV complete.");
            status("[AUTH] Phase IV complete.");
            Ok((auth_response, shared_key))
        } else {
            Err(anyhow::anyhow!("Unexpected Phase IV content"))
        }
    }

    fn create_encrypted_auth_request(&self, shared_key: &[u8; 32]) -> Result<(Bytes, Cipher)> {
        let mut auth_payload = AnetMessage {
            content: Some(Content::AuthRequest(AuthRequest {
                client_id: self.client_id.clone(),
            })),
            padding: vec![],
        };

        let current_wire_len = auth_payload.encoded_len() + PROTO_PAD_FIELD_OVERHEAD;
        let needed = calculate_padding_needed(current_wire_len, self.padding_step);
        auth_payload.padding = generate_random_padding(needed);

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
        let mut wrapped_msg = AnetMessage {
            content: Some(Content::EncryptedAuthRequest(encrypted_req)),
            padding: vec![],
        };

        let outer_len = wrapped_msg.encoded_len() + NONCE_LEN + PROTO_PAD_FIELD_OVERHEAD;
        let needed = calculate_padding_needed(outer_len, self.padding_step);
        wrapped_msg.padding = generate_random_padding(needed);

        let handshake_cipher = crypto_utils::create_handshake_cipher(&self.server_pub_key_bytes);

        let mut raw_wrapped = Vec::new();
        wrapped_msg.encode(&mut raw_wrapped)?;

        let mut obf_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut obf_nonce);

        let obf_ciphertext = handshake_cipher.encrypt(&obf_nonce, Bytes::from(raw_wrapped))?;

        let mut final_packet = BytesMut::with_capacity(NONCE_LEN + obf_ciphertext.len());
        final_packet.put_slice(&obf_nonce);
        final_packet.put(obf_ciphertext);

        Ok((final_packet.freeze(), req_cipher))
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
