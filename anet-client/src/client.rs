use crate::client_udp_socket::AnetUdpSocket;
use crate::config::{Config, load};
use anet_common::atun::TunManager;
use anet_common::consts::{AUTH_PREFIX_LEN, MAX_PACKET_SIZE, NONCE_LEN};
use anet_common::crypto_utils;
use anet_common::crypto_utils::{derive_shared_key, generate_key_fingerprint, sign_data};
use anet_common::encryption::Cipher;
use anet_common::protocol::{
    AuthRequest, AuthResponse, DhClientExchange, EncryptedAuthRequest, EncryptedAuthResponse,
    Message as AnetMessage, message::Content,
};
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use base64::prelude::*;
use bytes::{BufMut, Bytes, BytesMut};
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{error, info, warn};
use prost::Message;
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint, EndpointConfig, TokioRuntime,
    crypto::rustls::QuicClientConfig,
};
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::certs;
use std::net::SocketAddr;
use std::ops::Deref;
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_RETRIES: u32 = 10;
const INITIAL_DELAY: u64 = 5;
const MAX_DELAY: u64 = 60;

pub struct DHClientState {
    ephemeral_secret: StaticSecret,
    signing_key: SigningKey,
    client_public_key: VerifyingKey,
    client_id: String,
}

pub struct ANetClient {
    server_addr: String,
    server_public_key: VerifyingKey,
    dh_state: DHClientState,
    tun_name: String,
}

impl ANetClient {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let mut rng = OsRng;
        let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);

        // Загрузка личного ключа клиента
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

        // Загрузка публичного ключа сервера (опционально)

        let server_pub_bytes = BASE64_STANDARD
            .decode(&cfg.keys.server_pub_key)
            .context("Failed to decode server public key")?;
        let server_public_key = VerifyingKey::from_bytes(
            &server_pub_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid server public key length"))?,
        )?;

        info!("ANET Client created for client ID: {}", client_id);
        Ok(Self {
            server_addr: cfg.main.address.to_string(),
            server_public_key,
            tun_name: cfg.main.tun_name.to_string(),
            dh_state: DHClientState {
                ephemeral_secret,
                signing_key,
                client_public_key,
                client_id,
            },
        })
    }

    /// Выполняет DH Exchange с аутентификацией ключами
    pub async fn authenticate(&self) -> Result<(AuthResponse, [u8; 32])> {
        let server_addr: SocketAddr = self.server_addr.parse()?;
        let local_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let client_pub_key = PublicKey::from(&self.dh_state.ephemeral_secret);

        let mut delay = INITIAL_DELAY;
        let mut attempt = 0;

        // --- ФАЗА I/II: DH Exchange Loop ---
        let shared_key = loop {
            attempt += 1;

            if attempt > MAX_RETRIES {
                return Err(anyhow::anyhow!(
                    "DH exchange failed after {} retries.",
                    MAX_RETRIES
                ));
            }

            // --- ФАЗА I: КЛИЕНТ -> СЕРВЕР (DH Public Key + Подпись) ---
            let client_signed_dh_key =
                sign_data(&self.dh_state.signing_key, client_pub_key.as_bytes());
            let client_public_key_bytes = self.dh_state.client_public_key.to_bytes().to_vec();

            let dh_init_msg = AnetMessage {
                content: Some(Content::DhClientExchange(DhClientExchange {
                    public_key: client_pub_key.as_bytes().to_vec(),
                    client_signed_dh_key,
                    client_public_key: client_public_key_bytes,
                })),
            };

            let request_packet = self.create_obf_packet(&dh_init_msg)?;

            info!(
                "Phase I (Attempt {}): Sending DH Client Public Key with signature.",
                attempt
            );

            local_socket
                .send_to(&request_packet, server_addr)
                .await
                .context("Failed Phase I send")?;

            // --- ФАЗА II: Ждем DH Server Response ---
            match self
                .wait_for_response(&local_socket, server_addr, delay)
                .await
            {
                Ok((response_buf, len)) => {
                    let response_message = self.decode_obf_response(&response_buf, len)?;

                    let (server_pub_key_bytes, server_signature) = match response_message.content {
                        Some(Content::DhServerExchange(dh_exchange)) => {
                            if dh_exchange.public_key.len() != 32 {
                                return Err(anyhow::anyhow!(
                                    "Invalid server DH key length in Phase II"
                                ));
                            }
                            (dh_exchange.public_key, dh_exchange.server_signed_dh_key)
                        }
                        _ => {
                            warn!("Unexpected response type in Phase II. Applying backoff.");
                            delay = std::cmp::min(delay * 2, MAX_DELAY);
                            sleep(Duration::from_secs(delay)).await;
                            continue;
                        }
                    };

                    // Верификация подписи сервера
                    anet_common::crypto_utils::verify_signature(
                        &self.server_public_key,
                        &server_pub_key_bytes,
                        &server_signature,
                    )
                    .context("Server signature verification failed")?;

                    info!("Server signature verified successfully");
                    // Вычисление общего секрета K_shared
                    let server_key_array: [u8; 32] = server_pub_key_bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Slice to 32 bytes conversion failed"))?;
                    let server_pub_key = PublicKey::from(server_key_array);

                    let shared_secret = self
                        .dh_state
                        .ephemeral_secret
                        .diffie_hellman(&server_pub_key);
                    let shared_key = derive_shared_key(&shared_secret);
                    info!(
                        "Phase II complete: Shared secret derived successfully. Proceeding to Auth."
                    );
                    break shared_key;
                }
                Err(_) => {
                    delay = std::cmp::min(delay * 2, MAX_DELAY);
                    error!("Phase I/II timed out. Retrying in {}s...", delay);
                    sleep(Duration::from_secs(delay)).await;
                    continue;
                }
            }
        };

        // --- ФАЗА III: КЛИЕНТ -> СЕРВЕР (Encrypted AuthRequest) ---
        let (encrypted_data_packet, cipher) = self.create_encrypted_auth_request(&shared_key)?;

        local_socket
            .send_to(&encrypted_data_packet, server_addr)
            .await
            .context("Failed Phase III send")?;
        info!(
            "Phase III: Sent Encrypted Auth Request to {}, packet size: {} bytes",
            server_addr,
            encrypted_data_packet.len()
        );
        // --- ФАЗА IV: Ждем Encrypted AuthResponse ---
        match self
            .wait_for_response(&local_socket, server_addr, delay)
            .await
        {
            Ok((final_response_buf, final_len)) => {
                let response_message = self.decode_obf_response(&final_response_buf, final_len)?;

                if let Some(Content::EncryptedAuthResponse(enc_res)) = response_message.content {
                    let auth_response = self.decrypt_auth_response(enc_res, &cipher)?;

                    info!("Phase IV complete: Auth Response decrypted successfully.");
                    Ok((auth_response, shared_key))
                } else {
                    Err(anyhow::anyhow!(
                        "Unexpected Phase IV response content (Auth Response Expected)"
                    ))
                }
            }
            Err(e) => Err(e),
        }
    }

    // Вспомогательные функции остаются в основном те же, за исключением:

    fn create_encrypted_auth_request(&self, shared_key: &[u8; 32]) -> Result<(Bytes, Cipher)> {
        let auth_payload = AnetMessage {
            content: Some(Content::AuthRequest(AuthRequest {
                client_id: self.dh_state.client_id.clone(),
            })),
        };

        let mut raw_auth_request = Vec::new();
        auth_payload.encode(&mut raw_auth_request)?;

        info!("Raw AuthRequest size: {} bytes", raw_auth_request.len());
        info!(
            "AuthRequest content: client_id = {}",
            self.dh_state.client_id
        );

        let req_cipher = Cipher::new(shared_key);
        let mut rng = OsRng;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);

        info!("Encrypting with nonce: {:?}", nonce_bytes);

        let ciphertext = req_cipher
            .encrypt(&nonce_bytes, Bytes::from(raw_auth_request))
            .map_err(|e| {
                error!("Failed to encrypt AuthRequest: {:?}", e);
                anyhow::anyhow!("Failed to encrypt AuthRequest: {:?}", e)
            })?;

        info!("Ciphertext size: {} bytes", ciphertext.len());

        let encrypted_req = EncryptedAuthRequest {
            ciphertext: ciphertext.to_vec(),
            nonce: nonce_bytes.to_vec(),
        };

        let mut final_data = Vec::new();
        let wrapped_msg = AnetMessage {
            content: Some(Content::EncryptedAuthRequest(encrypted_req)),
        };
        wrapped_msg.encode(&mut final_data)?;

        info!(
            "Final encoded message size before XOR: {} bytes",
            final_data.len()
        );

        let prefix_info = crypto_utils::generate_prefix_with_salt();
        crypto_utils::xor_bytes(&mut final_data, &prefix_info.salt);

        info!(
            "Final encoded message size after XOR: {} bytes",
            final_data.len()
        );

        let mut final_packet_obf = BytesMut::new();
        final_packet_obf.put_slice(&prefix_info.prefix);
        final_packet_obf.put_slice(&final_data);

        let packet = final_packet_obf.freeze();
        info!("Total packet size with prefix: {} bytes", packet.len());

        Ok((packet, req_cipher))
    }

    // Вспомогательные функции:
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
        local_socket: &Arc<UdpSocket>,
        server_addr: SocketAddr,
        delay: u64,
    ) -> Result<([u8; MAX_PACKET_SIZE], usize)> {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        info!(
            "Waiting for response from {} for {} seconds...",
            server_addr, delay
        );

        match tokio::time::timeout(Duration::from_secs(delay), local_socket.recv_from(&mut buf))
            .await
        {
            Ok(Ok((len, recv_addr))) => {
                info!("Received {} bytes from {}", len, recv_addr);
                if recv_addr != server_addr {
                    warn!(
                        "Received packet from unexpected address: {} (expected: {})",
                        recv_addr, server_addr
                    );
                    return Err(anyhow::anyhow!(
                        "Received packet from unexpected address during DH."
                    ));
                }
                Ok((buf, len))
            }
            Ok(Err(e)) => {
                error!("Socket receive error: {}", e);
                Err(e.into())
            }
            Err(_) => {
                error!("Timeout waiting for response from {}", server_addr);
                Err(anyhow::anyhow!("Handshake phase timed out."))
            }
        }
    }

    fn decode_obf_response(&self, response_buf: &[u8], len: usize) -> Result<AnetMessage> {
        if len <= AUTH_PREFIX_LEN {
            return Err(anyhow::anyhow!("Auth response too short"));
        }
        let prefix = &response_buf[..AUTH_PREFIX_LEN];

        if !crypto_utils::check_auth_prefix(&prefix) {
            return Err(anyhow::anyhow!(
                "Auth response RND-SALT prefix check failed."
            ));
        }

        // XOR взыд

        // 1. Извлекаем соль из префикса ответа сервера
        let salt = anet_common::crypto_utils::extract_salt_from_prefix(prefix)
            .context("Failed to extract salt from response")?;

        // 2. Копируем зашифрованную часть пакета
        let mut payload = response_buf[AUTH_PREFIX_LEN..len].to_vec();

        // 3. Применяем XOR с солью, чтобы получить чистый Protobuf
        crypto_utils::xor_bytes(&mut payload, &salt);
        // =============================================================

        // 4. Декодируем уже "чистые" данные
        Message::decode(Bytes::from(payload)).context("Failed to decode Protobuf message")
    }

    fn decrypt_auth_response(
        &self,
        enc_res: EncryptedAuthResponse,
        req_cipher: &Cipher,
    ) -> Result<AuthResponse> {
        if enc_res.nonce.len() != NONCE_LEN {
            return Err(anyhow::anyhow!(
                "Invalid nonce length in EncryptedAuthResponse"
            ));
        }

        let plaintext = req_cipher
            .decrypt(enc_res.nonce.as_slice(), Bytes::from(enc_res.ciphertext))
            .map_err(|_| anyhow::anyhow!("Failed to decrypt AuthResponse (MAC/Key mismatch)"))?;

        let response_message: AnetMessage = Message::decode(plaintext)?;

        match response_message.content {
            Some(Content::AuthResponse(auth_response)) => {
                if auth_response.quic_cert.is_empty() {
                    return Err(anyhow::anyhow!("QUIC Certificate missing in Auth Response"));
                }
                // NOTE: crypto_key больше не проверяется, т.к. он отсутствует в AuthResponse.
                Ok(auth_response)
            }
            _ => Err(anyhow::anyhow!("Unexpected decrypted content")),
        }
    }
    pub async fn run_quic_vpn(
        &self,
        auth_response: &AuthResponse,
        shared_key: [u8; 32],
    ) -> Result<Endpoint> {
        let config_result = load().await?;

        let transport_config =
            build_transport_config(&config_result.quic_transport, auth_response.mtu as u16)?;
        let transport_config_arc = Arc::new(transport_config);

        let remote_addr: SocketAddr = self.server_addr.parse()?;
        let real_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        let cipher = Arc::new(Cipher::new(&shared_key));

        let nonce_prefix: [u8; 4] = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .context("Invalid nonce_prefix length from server")?;
        info!("[ANet] Received nonce prefix for QUIC session");

        let anet_socket = Arc::new(AnetUdpSocket::new(real_socket, cipher, nonce_prefix));

        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            anet_socket,
            Arc::new(TokioRuntime),
        )?;

        let mut client_config = self.build_quinn_client_config_from_response(auth_response)?;
        client_config.transport_config(transport_config_arc);

        endpoint.set_default_client_config(client_config);

        info!(
            "Connecting to QUIC endpoint [{}] via ANET transport...",
            remote_addr
        );

        let server_name = ServerName::try_from("alco").expect("Invalid server name");

        let connection = endpoint
            .connect(remote_addr, server_name.to_str().deref())?
            .await?;
        info!(
            "QUIC connection established with {}, SEID: {}",
            connection.remote_address(),
            auth_response.session_id,
        );

        let (send_stream, recv_stream) = connection.open_bi().await?;
        info!("Opened bidirectional QUIC stream for VPN traffic.");

        // Создаем TUN интерфейс
        let tun_params = TunParams::from_auth_response(&auth_response, self.tun_name.as_str());
        let tun_manager = TunManager::new(tun_params);
        let mut tun_manager = match tun_manager {
            Ok(tun_manager) => tun_manager,
            Err(e) => {
                error!("Error creating TunManager: {}", e);
                return Err(e);
            }
        };

        let (tx_to_tun, mut rx_from_tun) = tun_manager.run().await?;

        // Задачи для обработки трафика TUN <-> QUIC
        let mut quic_sender = send_stream;
        tokio::spawn(async move {
            while let Some(packet) = rx_from_tun.recv().await {
                if packet.len() < 20 {
                    continue;
                }
                let version = packet[0] >> 4;
                if version != 4 && version != 6 {
                    continue;
                }

                let framed_packet = frame_packet(packet);

                if let Err(e) = quic_sender.write_all(&framed_packet).await {
                    error!("QUIC stream write failed. TUN->QUIC task is closing: {}", e);
                    break;
                }

                if let Err(e) = quic_sender.flush().await {
                    error!("QUIC stream flush failed: {}", e);
                    break;
                }
            }

            if let Err(e) = quic_sender.finish() {
                error!("Error finishing QUIC stream: {}", e);
            }
            info!("TUN->QUIC task finished");
        });

        let mut quic_receiver = recv_stream;
        let tx_to_tun_clone = tx_to_tun.clone();
        tokio::spawn(async move {
            loop {
                match read_next_packet(&mut quic_receiver).await {
                    Ok(Some(packet)) => {
                        if let Err(e) = tx_to_tun_clone.send(packet).await {
                            error!("TUN channel write failed. QUIC->TUN task is closing: {}", e);
                            break;
                        }
                    }
                    Ok(None) => {
                        info!("QUIC receive stream closed gracefully.");
                        break;
                    }
                    Err(e) => {
                        error!("Error reading and deframing QUIC stream: {}", e);
                        break;
                    }
                }
            }
            info!("QUIC->TUN task finished");
        });

        Ok(endpoint)
    }

    /// Строит Quinn Client Config, используя QUIC-сертификат, полученный в AuthResponse
    fn build_quinn_client_config_from_response(
        &self,
        auth_response: &AuthResponse,
    ) -> Result<QuinnClientConfig> {
        let mut root_store = RootCertStore::empty();
        let certs_result = certs(&mut auth_response.quic_cert.as_slice())
            .collect::<Result<Vec<CertificateDer>, std::io::Error>>();

        let certs = match certs_result {
            Ok(c) => c,
            Err(e) => {
                error!("Error parsing QUIC certificate from AuthResponse: {}", e);
                return Err(anyhow::anyhow!("Certificate parsing failed"));
            }
        };

        for cert in certs {
            root_store
                .add(cert)
                .context("Failed to add QUIC certificate to root store")?;
        }

        let client_crypto = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let quic_config = QuicClientConfig::try_from(client_crypto)?;

        Ok(QuinnClientConfig::new(Arc::new(quic_config)))
    }
}
