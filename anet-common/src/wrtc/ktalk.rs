use rand::Rng;
use serde::{Deserialize, Serialize};

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

pub struct KtalkClient {
    http: reqwest::Client,
}

impl Default for KtalkClient {
    fn default() -> Self {
        Self::new()
    }
}

impl KtalkClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .build()
                .unwrap_or_default(),
        }
    }

    /// Generate random 15-char alphanumeric secret.
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

    /// Authorize a guest session in Ktalk.
    pub async fn authorize_session(
        &self,
        domain: &str,
        room_short_name: &str,
        client_name: &str,
        anonymous_secret: &str,
    ) -> anyhow::Result<AuthorizeSessionResponse> {
        let url = format!("https://{domain}/api/authorize/session");
        let origin = format!("https://{domain}");
        let referer = format!("https://{domain}/{room_short_name}");

        let body = AuthorizeSessionRequest {
            name: client_name.to_string(),
            anonymous_secret: anonymous_secret.to_string(),
            consent_on_create: true,
        };

        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Origin", origin)
            .header("Referer", referer)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ktalk authorize/session failed ({status}): {text}");
        }

        let auth_res: AuthorizeSessionResponse = resp.json().await?;
        Ok(auth_res)
    }

    /// Resolve conference room ID from short room name.
    pub async fn resolve_room(
        &self,
        domain: &str,
        room_short_name: &str,
        session_token: &str,
    ) -> anyhow::Result<RoomInfoResponse> {
        let url = format!("https://{domain}/api/rooms/{room_short_name}");

        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Session {session_token}"))
            .header("Accept", "application/json")
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ktalk resolve room failed ({status}): {text}");
        }

        let room_info: RoomInfoResponse = resp.json().await?;
        Ok(room_info)
    }
}
