use crate::config::WrtcConfig;
use crate::http_help::BrowserProfile;
use crate::wrtc::providers::{ProviderKind, RoomBootstrapInfo};
use crate::wrtc::stealth::generate_random_guest_name;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizeSessionRequest {
    pub name: String,
    #[serde(rename = "anonymousSecret")]
    pub anonymous_secret: String,
    #[serde(rename = "consentOnCreate")]
    pub consent_on_create: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeSessionResponse {
    pub token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "expiresIn")]
    pub expires_in: Option<u64>,
    #[serde(rename = "anonymousId")]
    pub anonymous_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoomInfoResponse {
    #[serde(rename = "roomName")]
    pub room_name: String,
    #[serde(rename = "conferenceId")]
    pub conference_id: String,
    #[serde(rename = "allowAnonymous")]
    pub allow_anonymous: Option<bool>,
}

pub struct KonturTalkProvider {
    http: reqwest::Client,
    pub profile: BrowserProfile,
    hop_attempts: usize,
}

impl KonturTalkProvider {
    /// Проверяет, относится ли домен к инфраструктуре Контур.Толк (`*.ktalk.ru` или `*.kontur.ru`).
    pub fn is_ktalk_domain(domain: &str) -> bool {
        let host = domain
            .trim()
            .trim_end_matches('/')
            .split(':')
            .next()
            .unwrap_or(domain)
            .to_ascii_lowercase();
        host == "ktalk.ru"
            || host.ends_with(".ktalk.ru")
            || host == "kontur.ru"
            || host.ends_with(".kontur.ru")
    }

    pub fn new(profile: BrowserProfile, wrtc_cfg: &WrtcConfig) -> anyhow::Result<Self> {
        let hop_attempts = wrtc_cfg.tcp_port_hop_attempts.clamp(1, 16);
        let connect_timeout = if hop_attempts > 1 {
            Duration::from_millis(wrtc_cfg.tcp_port_hop_timeout_ms.clamp(300, 10_000))
        } else {
            Duration::from_secs(wrtc_cfg.http_connect_timeout_secs.max(1))
        };

        let builder = profile
            .build_reqwest_builder(profile.cookie_jar.clone())
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to initialize BoringSSL TLS connector for WRTC/Ktalk: {e}"
                )
            })?
            .connect_timeout(connect_timeout)
            .timeout(Duration::from_secs(wrtc_cfg.http_request_timeout_secs.max(2)));

        let http = builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build Ktalk HTTP client: {e}"))?;

        Ok(Self {
            http,
            profile,
            hop_attempts,
        })
    }

    /// Генерирует 15-символьный алфавитно-цифровой `anonymousSecret`.
    pub fn generate_anonymous_secret() -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = rand::thread_rng();
        (0..15)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Авторизует гостевую сессию в Контур.Толк с быстрым перебором TCP-портов при L4 ECMP фильтрации.
    pub async fn authorize_session(
        &self,
        domain: &str,
        room_short_name: &str,
        client_name_opt: Option<&str>,
        anonymous_secret: &str,
    ) -> anyhow::Result<AuthorizeSessionResponse> {
        let url = format!("https://{domain}/api/authorize/session");
        let origin = format!("https://{domain}");
        let referer = format!("https://{domain}/{room_short_name}");
        let effective_name = match client_name_opt {
            Some(name) if !name.is_empty() && name != "ANet-Node" => name.to_string(),
            _ => generate_random_guest_name(),
        };

        let body = AuthorizeSessionRequest {
            name: effective_name,
            anonymous_secret: anonymous_secret.to_string(),
            consent_on_create: true,
        };

        let mut last_err = None;
        for attempt in 1..=self.hop_attempts {
            let req = self
                .http
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/plain, */*");
            let req = self
                .profile
                .apply_to_reqwest(req, Some(&origin), Some(&referer));

            match req.json(&body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let headers = resp.headers().clone();
                    if !status.is_success() {
                        let text = resp.text().await.unwrap_or_default();
                        anyhow::bail!("Ktalk authorize/session failed ({status}): {text}");
                    }

                    let bytes = resp.bytes().await.map_err(|e| {
                        anyhow::anyhow!(
                            "Ktalk read response bytes failed (status {status}, headers {headers:?}): {e}"
                        )
                    })?;

                    let auth_res: AuthorizeSessionResponse =
                        serde_json::from_slice(&bytes).map_err(|e| {
                            let body_preview = String::from_utf8_lossy(&bytes);
                            anyhow::anyhow!(
                                "Ktalk decode AuthorizeSessionResponse failed: {e}. Raw body ({len} bytes, headers {headers:?}): {body_preview}",
                                len = bytes.len()
                            )
                        })?;
                    return Ok(auth_res);
                }
                Err(e) => {
                    log::debug!(
                        "[WRTC Ktalk] authorize_session attempt {}/{} to {} failed: {}",
                        attempt,
                        self.hop_attempts,
                        domain,
                        e
                    );
                    last_err = Some(anyhow::Error::from(e));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Ktalk authorize_session failed")))
    }

    /// Резолвит `conferenceId` по короткому имени комнаты Контур.Толк.
    pub async fn resolve_room(
        &self,
        domain: &str,
        room_short_name: &str,
        session_token: &str,
    ) -> anyhow::Result<RoomInfoResponse> {
        let url = format!("https://{domain}/api/rooms/{room_short_name}");
        let origin = format!("https://{domain}");
        let referer = format!("https://{domain}/{room_short_name}");

        let mut last_err = None;
        for attempt in 1..=self.hop_attempts {
            let req = self
                .http
                .get(&url)
                .header("Authorization", format!("Session {session_token}"))
                .header("Accept", "application/json, text/plain, */*");
            let req = self
                .profile
                .apply_to_reqwest(req, Some(&origin), Some(&referer));

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let headers = resp.headers().clone();
                    if !status.is_success() {
                        let text = resp.text().await.unwrap_or_default();
                        anyhow::bail!("Ktalk resolve room failed ({status}): {text}");
                    }

                    let bytes = resp.bytes().await.map_err(|e| {
                        anyhow::anyhow!(
                            "Ktalk read room response bytes failed (status {status}, headers {headers:?}): {e}"
                        )
                    })?;

                    let room_info: RoomInfoResponse =
                        serde_json::from_slice(&bytes).map_err(|e| {
                            let body_preview = String::from_utf8_lossy(&bytes);
                            anyhow::anyhow!(
                                "Ktalk decode RoomInfoResponse failed: {e}. Raw body ({len} bytes, headers {headers:?}): {body_preview}",
                                len = bytes.len()
                            )
                        })?;
                    return Ok(room_info);
                }
                Err(e) => {
                    log::debug!(
                        "[WRTC Ktalk] resolve_room attempt {}/{} to {} failed: {}",
                        attempt,
                        self.hop_attempts,
                        domain,
                        e
                    );
                    last_err = Some(anyhow::Error::from(e));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Ktalk resolve_room failed")))
    }

    /// Выполняет полный цикл подготовки комнаты Контур.Толк и формирует `RoomBootstrapInfo`.
    pub async fn bootstrap_room(
        domain: &str,
        room_short_name: &str,
        client_name_opt: Option<&str>,
        profile: &BrowserProfile,
        wrtc_cfg: &WrtcConfig,
    ) -> anyhow::Result<RoomBootstrapInfo> {
        let client = Self::new(profile.clone(), wrtc_cfg)?;
        let secret = Self::generate_anonymous_secret();
        let auth = client
            .authorize_session(domain, room_short_name, client_name_opt, &secret)
            .await?;
        let room_info = client
            .resolve_room(domain, room_short_name, &auth.token)
            .await?;

        let conference_id = room_info.conference_id;
        let session_token = auth.token;
        let ws_urls = vec![format!(
            "wss://{domain}/xmpp-websocket?room={conference_id}&token={session_token}& Lists=true"
        )];

        Ok(RoomBootstrapInfo {
            provider_kind: ProviderKind::KonturTalk,
            domain: domain.to_string(),
            room_name: room_short_name.to_string(),
            conference_id,
            session_token,
            ws_urls,
            pre_allocate_before_muc: false,
            default_ice_servers: Vec::new(),
        })
    }
}
