use crate::auth_provider::AuthProvider;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::multikey_udp_socket::TempDHInfo;
use crate::utils::{generate_seid, generate_unique_nonce_prefix};
use anet_common::consts::{NONCE_LEN, PROTO_PAD_FIELD_OVERHEAD};
use anet_common::encryption::Cipher;
use anet_common::padding_utils::{calculate_padding_needed, generate_random_padding};
use anet_common::protocol::{
    AuthResponse, DhClientExchange, DhServerExchange, EncryptedAuthRequest, EncryptedAuthResponse,
    Message as AnetMessage, message::Content,
};
use anet_common::{AuthDenyNotification, crypto_utils};
use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{info, warn};
use prost::Message;
use rand::RngCore;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub struct ServerAuthHandler {
    registry: Arc<ClientRegistry>,
    temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
    auth_provider: Arc<AuthProvider>,
    server_signing_key: SigningKey,
    handshake_cipher: Arc<Cipher>,
    quic_cert_pem: String,
    padding_step: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_provider::AuthProvider;
    use crate::ip_pool::IpPool;
    use anet_client_core::auth::{AuthChannel, AuthHandler};
    use anet_client_core::config::CoreConfig;
    use anet_common::crypto_utils::generate_key_fingerprint;
    use anet_common::handshake_fragmentation::FragmentConfig;
    use async_trait::async_trait;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use std::sync::Mutex;
    use std::time::Duration;

    struct InMemoryChannel {
        server: ServerAuthHandler,
        remote_addr: SocketAddr,
        response: Mutex<Option<Bytes>>,
        authenticated: Mutex<Option<Arc<ClientTransportInfo>>>,
    }

    #[async_trait]
    impl AuthChannel for InMemoryChannel {
        async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
            let (response, authenticated) = self
                .server
                .process_handshake_packet(data, self.remote_addr)
                .await?;
            *self.response.lock().unwrap() = response;
            if let Some((client, _)) = authenticated {
                *self.authenticated.lock().unwrap() = Some(client);
            }
            Ok(())
        }

        async fn recv(&self, _timeout: Duration) -> Result<Bytes> {
            self.response
                .lock()
                .unwrap()
                .take()
                .context("test server did not produce a response")
        }
    }

    fn channel(server: ServerAuthHandler, port: u16) -> InMemoryChannel {
        InMemoryChannel {
            server,
            remote_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            response: Mutex::new(None),
            authenticated: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn resume_keeps_logical_session_and_ip() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Info)
            .try_init();
        let client_signing = SigningKey::generate(&mut OsRng);
        let server_signing = SigningKey::generate(&mut OsRng);
        let fingerprint = generate_key_fingerprint(&client_signing.verifying_key());
        let auth_provider = Arc::new(AuthProvider::new(
            vec![fingerprint],
            vec![],
            String::new(),
        ));
        let registry = Arc::new(ClientRegistry::new(
            IpPool::new(
                "10.0.0.0".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
                1400,
            ),
            auth_provider.clone(),
        ));
        let server = ServerAuthHandler::new(
            registry.clone(),
            Arc::new(DashMap::new()),
            auth_provider,
            server_signing.clone(),
            "test-quic-cert".to_string(),
            128,
        );

        let mut config: CoreConfig = toml::from_str("").unwrap();
        config.keys.private_key = BASE64_STANDARD.encode(client_signing.to_bytes());
        config.keys.server_pub_key =
            BASE64_STANDARD.encode(server_signing.verifying_key().to_bytes());

        let first_channel = channel(server.clone(), 21001);
        let first_auth = AuthHandler::new(&config, None).unwrap();
        let (first_response, _) = tokio::time::timeout(
            Duration::from_secs(2),
            first_auth.authenticate(&first_channel),
        )
        .await
        .expect("initial authentication timed out")
        .unwrap();
        let first_info = first_channel
            .authenticated
            .lock()
            .unwrap()
            .take()
            .unwrap();
        registry.suspend_client(first_info);

        let resumed_channel = channel(server, 21002);
        let resumed_auth = AuthHandler::new_with_resume(
            &config,
            None,
            Some(first_response.session_id.clone()),
        )
        .unwrap();
        let (resumed_response, _) = tokio::time::timeout(
            Duration::from_secs(2),
            resumed_auth.authenticate(&resumed_channel),
        )
        .await
        .expect("resume authentication timed out")
        .unwrap();

        assert_eq!(resumed_response.session_id, first_response.session_id);
        assert_eq!(resumed_response.ip, first_response.ip);
        assert_eq!(resumed_response.gateway, first_response.gateway);
    }
}

impl ServerAuthHandler {
    pub fn new(
        registry: Arc<ClientRegistry>,
        temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
        auth_provider: Arc<AuthProvider>,
        server_signing_key: SigningKey,
        quic_cert_pem: String,
        padding_step: u16,
    ) -> Self {
        let pub_key_bytes = server_signing_key.verifying_key().to_bytes();
        let handshake_cipher = Arc::new(crypto_utils::create_handshake_cipher(&pub_key_bytes));

        Self {
            registry,
            temp_dh_map,
            auth_provider,
            server_signing_key,
            handshake_cipher,
            quic_cert_pem,
            padding_step,
        }
    }

    pub async fn process_handshake_packet(
        &self,
        packet: Bytes,
        remote_addr: SocketAddr,
    ) -> Result<(
        Option<Bytes>,
        Option<(Arc<ClientTransportInfo>, AuthResponse)>,
    )> {
        let message = self
            .decode_obfuscated_packet(packet)
            .context("ASTP outer handshake decryption failed")?;

        match message.content {
            Some(Content::DhClientExchange(req)) => {
                let resp_msg = self.handle_dh_exchange(req, remote_addr).await.unwrap();
                let resp_bytes = self.encode_obfuscated_packet(resp_msg)?;
                Ok((Some(resp_bytes), None))
            }
            Some(Content::EncryptedAuthRequest(enc_req)) => {
                let (resp_msg, client_info, auth_resp) = self
                    .handle_encrypted_auth(enc_req, remote_addr)
                    .await
                    .context("ASTP shared-key authentication failed")?;
                let resp_bytes = self.encode_obfuscated_packet(resp_msg)?;
                Ok((Some(resp_bytes), Some((client_info, auth_resp))))
            }
            _ => Err(anyhow!("Invalid payload message type")),
        }
    }

    fn decode_obfuscated_packet(&self, packet: Bytes) -> Result<AnetMessage> {
        if packet.len() < NONCE_LEN + 16 {
            return Err(anyhow::anyhow!("Packet too short"));
        }
        let (nonce, ciphertext) = packet.split_at(NONCE_LEN);
        let plaintext = self
            .handshake_cipher
            .decrypt(nonce, Bytes::copy_from_slice(ciphertext))?;
        Message::decode(plaintext).context("Failed to decode Protobuf")
    }

    fn encode_obfuscated_packet(&self, message: AnetMessage) -> Result<Bytes> {
        let mut data = Vec::new();
        message.encode(&mut data)?;

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = self.handshake_cipher.encrypt(&nonce, Bytes::from(data))?;
        let mut packet = BytesMut::with_capacity(NONCE_LEN + ciphertext.len());
        packet.put_slice(&nonce);
        packet.put(ciphertext);
        Ok(packet.freeze())
    }

    async fn handle_dh_exchange(
        &self,
        req: DhClientExchange,
        remote_addr: SocketAddr,
    ) -> Result<AnetMessage> {
        let client_public_key = VerifyingKey::from_bytes(
            &req.client_public_key
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
        )
        .map_err(|_| anyhow::anyhow!("Invalid verifying key"))?;

        let client_fingerprint = crypto_utils::generate_key_fingerprint(&client_public_key);

        let resume_allowed = self
            .registry
            .can_resume(&req.resume_session_id, &client_fingerprint);
        let access = if resume_allowed {
            Ok(None)
        } else {
            self.auth_provider.is_client_allowed(&client_fingerprint).await
        };

        match access {
            Ok(static_ip) => {
                // --- ЛОГИКА УСПЕХА (DH Phase 1) ---
                let mut signed_handshake = req.public_key.clone();
                if !req.resume_session_id.is_empty() {
                    signed_handshake.extend_from_slice(req.resume_session_id.as_bytes());
                }
                crypto_utils::verify_signature(
                    &client_public_key,
                    &signed_handshake,
                    &req.client_signed_dh_key,
                )?;

                info!("[AUTH] Auth Phase 1 success: {}", remote_addr);

                let server_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
                let server_pub_key = PublicKey::from(&server_ephemeral_secret);

                let client_dh_pub_array: [u8; 32] = req.public_key.as_slice().try_into().unwrap();
                let client_dh_pub = PublicKey::from(client_dh_pub_array);

                let shared_secret = server_ephemeral_secret.diffie_hellman(&client_dh_pub);
                self.temp_dh_map.insert(
                    remote_addr,
                    TempDHInfo {
                        shared_key: crypto_utils::derive_shared_key(&shared_secret),
                        client_fingerprint,
                        static_ip,
                        resume_session_id: req.resume_session_id,
                        created_at: Instant::now(),
                    },
                );

                let response_payload = DhServerExchange {
                    public_key: server_pub_key.as_bytes().to_vec(),
                    server_signed_dh_key: crypto_utils::sign_data(
                        &self.server_signing_key,
                        server_pub_key.as_bytes(),
                    ),
                };

                let mut response_message = AnetMessage {
                    content: Some(Content::DhServerExchange(response_payload)),
                    padding: vec![],
                };

                // Расчет паддинга
                let wire_len = response_message.encoded_len() + 16; // Примерный оверхед
                response_message.padding =
                    generate_random_padding(calculate_padding_needed(wire_len, self.padding_step));

                Ok(response_message)
            }
            Err(reason) => {
                // --- ЛОГИКА ОТКАЗА ---
                warn!(
                    "[AUTH] DH Exchange Phase 1 failed: {}, Reason: {}, Fingerprint: {}",
                    remote_addr, reason, client_fingerprint
                );

                // Вместо DhServerExchange пихаем AuthError (вариант 7 в oneof)
                let mut response_message = AnetMessage {
                    content: Some(Content::AuthError(AuthDenyNotification {
                        message: reason, // Тот самый текст из anet-auth
                    })),
                    padding: vec![],
                };

                // Важно: наводим маскировку даже на пакет ошибки
                let wire_len = response_message.encoded_len() + 16;
                response_message.padding =
                    generate_random_padding(calculate_padding_needed(wire_len, self.padding_step));

                Ok(response_message)
            }
        }
    }

    async fn handle_encrypted_auth(
        &self,
        enc_req: EncryptedAuthRequest,
        remote_addr: SocketAddr,
    ) -> Result<(AnetMessage, Arc<ClientTransportInfo>, AuthResponse)> {
        let temp_info = self
            .temp_dh_map
            .remove(&remote_addr)
            .map(|(_, v)| v)
            .context("DH session expired or not found")?;
        let cipher = Cipher::new(&temp_info.shared_key);
        let plaintext = cipher
            .decrypt(enc_req.nonce.as_slice(), Bytes::from(enc_req.ciphertext))
            .context("Phase III payload decryption failed")?;
        let auth_message: AnetMessage = Message::decode(plaintext)?;

        let req = match auth_message.content {
            Some(Content::AuthRequest(r)) => r,
            _ => return Err(anyhow::anyhow!("Invalid content type")),
        };
        if req.client_id != temp_info.client_fingerprint {
            return Err(anyhow::anyhow!("Client ID mismatch"));
        }
        if req.resume_session_id != temp_info.resume_session_id {
            return Err(anyhow::anyhow!("Resume session ID changed during handshake"));
        }

        let resumed = self
            .registry
            .take_suspended(&req.resume_session_id, &temp_info.client_fingerprint);
        if !req.resume_session_id.is_empty() && resumed.is_none() {
            anyhow::bail!("Requested VPN session is not available for resume");
        }
        let (assigned_ip, session_id, is_resume) = if let Some(previous) = resumed {
            info!(
                "[AUTH] Resuming logical session {} on a new transport",
                previous.session_id
            );
            (previous.assigned_ip.clone(), previous.session_id.clone(), true)
        } else {
            let assigned_ip = if let Some(static_ip) = temp_info.static_ip {
                info!(
                    "[AUTH] Assigned static IP {} to client {}",
                    static_ip, req.client_id
                );
                static_ip
            } else {
                self.registry
                    .allocate_ip()
                    .context("IP POOL FOOL")?
                    .to_string()
            };
            (assigned_ip, generate_seid(), false)
        };

        let nonce_prefix = generate_unique_nonce_prefix(self.registry.clone());

        let client_info = Arc::new(ClientTransportInfo {
            cipher: Arc::new(Cipher::new(&temp_info.shared_key)),
            sequence: Arc::new(AtomicU64::new(0)),
            assigned_ip: assigned_ip.clone(),
            session_id: session_id.clone(),
            nonce_prefix,
            remote_addr: ArcSwap::new(Arc::new(remote_addr)),
            fingerprint: temp_info.client_fingerprint.clone(),
        });

        self.registry.pre_register_client(client_info.clone());

        if !is_resume {
            let ap = self.auth_provider.clone();
            let fp = temp_info.client_fingerprint.clone();
            tokio::spawn(async move {
                ap.report_session_start(fp).await;
            });
        }

        let (netmask, gateway, mtu) = self.registry.get_network_params();
        let response_payload = AuthResponse {
            ip: assigned_ip,
            netmask: netmask.to_string(),
            gateway: gateway.to_string(),
            mtu: mtu as i32,
            session_id,
            nonce_prefix: nonce_prefix.to_vec(),
            quic_cert: self.quic_cert_pem.as_bytes().to_vec(),
        };

        let mut inner_msg = AnetMessage {
            content: Some(Content::AuthResponse(response_payload.clone())),
            padding: vec![],
        };
        inner_msg.padding = generate_random_padding(calculate_padding_needed(
            inner_msg.encoded_len() + PROTO_PAD_FIELD_OVERHEAD,
            self.padding_step,
        ));

        let mut raw_resp = Vec::new();
        inner_msg.encode(&mut raw_resp)?;

        let cipher = Cipher::new(&temp_info.shared_key);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce_bytes, Bytes::from(raw_resp))?;

        let mut outer_msg = AnetMessage {
            content: Some(Content::EncryptedAuthResponse(EncryptedAuthResponse {
                ciphertext: ciphertext.to_vec(),
                nonce: nonce_bytes.to_vec(),
            })),
            padding: vec![],
        };
        outer_msg.padding = generate_random_padding(calculate_padding_needed(
            outer_msg.encoded_len() + NONCE_LEN + PROTO_PAD_FIELD_OVERHEAD,
            self.padding_step,
        ));

        Ok((outer_msg, client_info, response_payload))
    }
}
