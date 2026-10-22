use crate::config::CoreConfig;
use crate::events::{status, warn};
use anet_common::consts::{MAX_PACKET_SIZE, NONCE_LEN, PROTO_PAD_FIELD_OVERHEAD};
use anet_common::crypto_utils::{self, derive_shared_key, generate_key_fingerprint, sign_data};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::{FragmentConfig, send_fragmented_datagrams, write_fragmented};
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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::sleep;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_RETRIES: u32 = 10;
const INITIAL_DELAY: u64 = 6;
const MAX_DELAY: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDenyError {
    pub message: String,
}

impl AuthDenyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn is_node_transient(&self) -> bool {
        self.message.contains("Node is not accepting new connections")
            || self.message.contains("Все сервера авторизации недоступны")
    }
}

impl std::fmt::Display for AuthDenyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AuthDenyError {}

#[async_trait]
pub trait AuthChannel: Send + Sync {
    async fn send(&self, data: Bytes, frag: &FragmentConfig) -> Result<()>;
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
    async fn send(&self, data: Bytes, frag: &FragmentConfig) -> Result<()> {
        send_fragmented_datagrams(&data, frag, |chunk| async move {
            self.socket.send_to(&chunk, self.target).await.map(|_| ())
        })
            .await?;
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
    async fn send(&self, data: Bytes, frag: &FragmentConfig) -> Result<()> {
        let mut stream = self.stream.lock().await;
        let framed = frame_packet(data);
        // Получателю не нужны никакие изменения: поток (TCP/SSH/VNC, в
        // гарантирует доставку байт по порядку независимо от
        // того, сколькими сегментами это было разбито на передаче.
        write_fragmented(&mut *stream, &framed, frag).await?;
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
    frag_cfg: FragmentConfig,
    resume_session_id: Option<String>,
}

impl AuthHandler {
    pub fn new(cfg: &CoreConfig, server_pub_key_override: Option<&str>) -> Result<Self> {
        Self::new_with_resume(cfg, server_pub_key_override, None)
    }

    pub fn new_with_resume(
        cfg: &CoreConfig,
        server_pub_key_override: Option<&str>,
        resume_session_id: Option<String>,
    ) -> Result<Self> {
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

        // Если есть переопределенный ключ сервера — берем его, иначе глобальный
        let key_str = server_pub_key_override.unwrap_or(&cfg.keys.server_pub_key);
        if key_str.is_empty() {
            anyhow::bail!("Публичный ключ сервера (server_pub_key) не настроен!");
        }

        let server_pub_bytes = BASE64_STANDARD
            .decode(key_str)
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
            frag_cfg: FragmentConfig::from_stealth(&cfg.stealth),
            resume_session_id,
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
                    if e.downcast_ref::<AuthDenyError>().is_some() {
                        return Err(e);
                    }
                    warn!(
                        "[AUTH] Handshake attempt {} failed: {}. Retrying...",
                        attempt, e
                    );
                    warn(format!(
                        "[AUTH] Handshake attempt {} failed: {}",
                        attempt, e
                    ));
                    delay = (delay + 1).min(MAX_DELAY);
                    sleep(Duration::from_millis(600)).await;
                }
            }
        }
        Err(anyhow::anyhow!(
            "Authentication failed after {} retries.",
            MAX_RETRIES
        ))
    }

    /// Performs one handshake attempt on a stream transport.
    ///
    /// TCP/SSH/WebSocket/VNC cannot recover after the peer closes the stream:
    /// retrying on the same channel only delays failover and can turn the real
    /// connection error into an outer handshake timeout.
    pub async fn authenticate_once(
        &self,
        channel: &dyn AuthChannel,
    ) -> Result<(AuthResponse, [u8; 32])> {
        self.attempt_handshake(channel, INITIAL_DELAY).await
    }

    async fn attempt_handshake(
        &self,
        channel: &dyn AuthChannel,
        delay: u64,
    ) -> Result<(AuthResponse, [u8; 32])> {
        let client_pub_key = PublicKey::from(&self.ephemeral_secret);
        let mut signed_handshake = client_pub_key.as_bytes().to_vec();
        if let Some(session_id) = &self.resume_session_id {
            signed_handshake.extend_from_slice(session_id.as_bytes());
        }
        let client_signed_dh_key = sign_data(&self.signing_key, &signed_handshake);

        let mut dh_init_msg = AnetMessage {
            content: Some(Content::DhClientExchange(DhClientExchange {
                public_key: client_pub_key.as_bytes().to_vec(),
                client_signed_dh_key,
                client_public_key: self.client_public_key.to_bytes().to_vec(),
                resume_session_id: self.resume_session_id.clone().unwrap_or_default(),
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
            .send(request_packet, &self.frag_cfg)
            .await
            .context("Failed Phase I send")?;

        // Цикл ожидания Фазы II (игнорирует нерасшифровываемый мусор)
        let start_ii = std::time::Instant::now();
        let timeout_ii = Duration::from_secs(delay);
        let shared_key = loop {
            let elapsed = start_ii.elapsed();
            if elapsed >= timeout_ii {
                anyhow::bail!("Phase II timeout (no valid response)");
            }

            let response_buf = channel.recv(timeout_ii - elapsed).await?;
            match self.handle_phase_ii_response(&response_buf) {
                Ok(key) => break key,
                Err(e) => {
                    if e.downcast_ref::<AuthDenyError>().is_some() {
                        return Err(e);
                    }
                    log::warn!("[AUTH] Ignored packet during Phase II (likely noise): {}", e);
                    continue;
                }
            }
        };

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
            // Если сервер прислал ошибку вместо ключей DH
            Some(Content::AuthError(err)) => {
                warn!("[AUTH] Server rejected handshake in Phase II: {}", err.message);
                warn(format!("[CORE AUTH] {}", err.message));
                return Err(AuthDenyError::new(err.message).into());
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
        info!("[AUTH] Phase III: Sending Encrypted Auth Request ({} bytes).", request_packet.len());

        channel
            .send(request_packet, &self.frag_cfg)
            .await
            .context("Failed Phase III send")?;

        let handshake_cipher = crypto_utils::create_handshake_cipher(&self.server_pub_key_bytes);

        // ИСПРАВЛЕНИЕ: Цикл ожидания Фазы IV (игнорирует нерасшифровываемый мусор)
        let start_iv = std::time::Instant::now();
        let timeout_iv = Duration::from_secs(delay);

        loop {
            let elapsed = start_iv.elapsed();
            if elapsed >= timeout_iv {
                return Err(anyhow::anyhow!("Phase IV timeout (no valid response received)"));
            }

            let response_buf = channel.recv(timeout_iv - elapsed).await?;

            if response_buf.len() < NONCE_LEN {
                log::debug!("[AUTH] Ignored short packet in Phase IV");
                continue;
            }

            let (nonce, ciphertext) = response_buf.split_at(NONCE_LEN);

            let plaintext_outer = match handshake_cipher.decrypt(nonce, Bytes::copy_from_slice(ciphertext)) {
                Ok(pt) => pt,
                Err(e) => {
                    log::debug!("[AUTH] Ignored invalid packet in Phase IV (decryption failed): {}", e);
                    continue;
                }
            };

            let outer_msg: AnetMessage = match Message::decode(plaintext_outer) {
                Ok(msg) => msg,
                Err(e) => {
                    log::debug!("[AUTH] Ignored invalid packet in Phase IV (decode failed): {}", e);
                    continue;
                }
            };

            match outer_msg.content {
                Some(Content::EncryptedAuthResponse(enc_res)) => {
                    let auth_response = self.decrypt_auth_response(enc_res, &cipher)?;
                    info!("[AUTH] Phase IV complete.");
                    status("[AUTH] Phase IV complete.");
                    return Ok((auth_response, shared_key));
                }
                Some(Content::AuthError(err)) => {
                    warn!("[AUTH] Server rejected authentication in Phase IV: {}", err.message);
                    warn(format!("[CORE AUTH] {}", err.message));
                    return Err(AuthDenyError::new(err.message).into());
                }
                _ => {
                    log::debug!("[AUTH] Ignored unexpected Phase IV content");
                    continue;
                }
            }
        }
    }

    fn create_encrypted_auth_request(&self, shared_key: &[u8; 32]) -> Result<(Bytes, Cipher)> {
        let mut auth_payload = AnetMessage {
            content: Some(Content::AuthRequest(AuthRequest {
                client_id: self.client_id.clone(),
                resume_session_id: self.resume_session_id.clone().unwrap_or_default(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use anet_common::protocol::{AuthDenyNotification, DhServerExchange};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockAuthChannel {
        responses: Mutex<VecDeque<Bytes>>,
        send_count: AtomicUsize,
    }

    impl MockAuthChannel {
        fn new(responses: Vec<Bytes>) -> Self {
            Self {
                responses: Mutex::new(VecDeque::from(responses)),
                send_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl AuthChannel for MockAuthChannel {
        async fn send(&self, _data: Bytes, _frag: &FragmentConfig) -> Result<()> {
            self.send_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn recv(&self, _timeout: Duration) -> Result<Bytes> {
            let mut q = self.responses.lock().await;
            q.pop_front()
                .ok_or_else(|| anyhow::anyhow!("No more mock responses"))
        }
    }

    fn make_test_handler_and_server_key() -> (AuthHandler, SigningKey, Vec<u8>) {
        let client_signing = SigningKey::from_bytes(&[11u8; 32]);
        let server_signing = SigningKey::from_bytes(&[22u8; 32]);
        let server_pub_bytes = server_signing.verifying_key().to_bytes().to_vec();

        let mut cfg = CoreConfig::default();
        cfg.keys.private_key = BASE64_STANDARD.encode(client_signing.to_bytes());
        cfg.keys.server_pub_key = BASE64_STANDARD.encode(&server_pub_bytes);

        let handler = AuthHandler::new(&cfg, None).expect("Failed to create AuthHandler");
        (handler, server_signing, server_pub_bytes)
    }

    fn encrypt_handshake_msg(server_pub_bytes: &[u8], msg: &AnetMessage) -> Bytes {
        let mut raw = Vec::new();
        msg.encode(&mut raw).unwrap();
        let cipher = crypto_utils::create_handshake_cipher(server_pub_bytes);
        let nonce = [7u8; NONCE_LEN];
        let ct = cipher.encrypt(&nonce, Bytes::from(raw)).unwrap();
        let mut out = BytesMut::with_capacity(NONCE_LEN + ct.len());
        out.put_slice(&nonce);
        out.put(ct);
        out.freeze()
    }

    #[test]
    fn test_auth_deny_error_classification() {
        let session_limit = AuthDenyError::new("Достигнут лимит одновременных подключений");
        assert!(!session_limit.is_node_transient());

        let banned = AuthDenyError::new("Учетная запись заблокирована");
        assert!(!banned.is_node_transient());

        let expired = AuthDenyError::new("Время действия подписки истекло");
        assert!(!expired.is_node_transient());

        let traffic = AuthDenyError::new("Лимит трафика на этот период исчерпан");
        assert!(!traffic.is_node_transient());

        let not_found = AuthDenyError::new("Not found");
        assert!(!not_found.is_node_transient());

        let draining = AuthDenyError::new("Node is not accepting new connections");
        assert!(draining.is_node_transient());

        let backends_down = AuthDenyError::new("Все сервера авторизации недоступны");
        assert!(backends_down.is_node_transient());
    }

    #[tokio::test]
    async fn test_phase_ii_auth_error_stops_immediately_without_retries() {
        let (handler, _server_signing, server_pub_bytes) = make_test_handler_and_server_key();
        let deny_msg = AnetMessage {
            content: Some(Content::AuthError(AuthDenyNotification {
                message: "Достигнут лимит одновременных подключений".to_string(),
            })),
            padding: vec![],
        };
        let pkt = encrypt_handshake_msg(&server_pub_bytes, &deny_msg);
        let channel = MockAuthChannel::new(vec![pkt]);

        let err = handler
            .authenticate(&channel)
            .await
            .expect_err("Expected Phase II AuthError");

        // Должна быть ровно 1 отправка (Phase I) без 10 повторов MAX_RETRIES
        assert_eq!(channel.send_count.load(Ordering::SeqCst), 1);
        let auth_err = err
            .downcast_ref::<AuthDenyError>()
            .expect("Error must downcast to AuthDenyError");
        assert_eq!(
            auth_err.message,
            "Достигнут лимит одновременных подключений"
        );
        assert!(!auth_err.is_node_transient());
    }

    #[tokio::test]
    async fn test_phase_iv_auth_error_stops_immediately_without_retries() {
        let (handler, server_signing, server_pub_bytes) = make_test_handler_and_server_key();

        let server_dh_secret = StaticSecret::random_from_rng(OsRng);
        let server_dh_pub = PublicKey::from(&server_dh_secret);
        let sig = sign_data(&server_signing, server_dh_pub.as_bytes());

        let phase_ii_msg = AnetMessage {
            content: Some(Content::DhServerExchange(DhServerExchange {
                public_key: server_dh_pub.as_bytes().to_vec(),
                server_signed_dh_key: sig,
            })),
            padding: vec![],
        };
        let pkt_ii = encrypt_handshake_msg(&server_pub_bytes, &phase_ii_msg);

        let deny_msg = AnetMessage {
            content: Some(Content::AuthError(AuthDenyNotification {
                message: "Учетная запись заблокирована".to_string(),
            })),
            padding: vec![],
        };
        let pkt_iv = encrypt_handshake_msg(&server_pub_bytes, &deny_msg);

        let channel = MockAuthChannel::new(vec![pkt_ii, pkt_iv]);

        let err = handler
            .authenticate(&channel)
            .await
            .expect_err("Expected Phase IV AuthError");

        // Ровно 2 отправки (Phase I и Phase III) — цикл authenticate() не делает 10 ретраев
        assert_eq!(channel.send_count.load(Ordering::SeqCst), 2);
        let auth_err = err
            .downcast_ref::<AuthDenyError>()
            .expect("Error must downcast to AuthDenyError");
        assert_eq!(auth_err.message, "Учетная запись заблокирована");
        assert!(!auth_err.is_node_transient());
    }
}

