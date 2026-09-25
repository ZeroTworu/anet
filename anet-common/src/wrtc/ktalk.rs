use crate::http_help::BrowserProfile;
use crate::wrtc::stealth::{apply_reqwest_browser_headers, generate_random_guest_name};
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
    pub profile: BrowserProfile,
}

impl Default for KtalkClient {
    fn default() -> Self {
        Self::new(BrowserProfile::random())
    }
}

impl KtalkClient {
    pub fn new(profile: BrowserProfile) -> Self {
        Self {
            http: reqwest::Client::builder()
                .build()
                .unwrap_or_default(),
            profile,
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

    /// Authorize a guest session in Ktalk with browser stealth headers and natural guest name.
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

        let req = self
            .http
            .post(&url)
            .header("Content-Type", "application/json");

        let req = apply_reqwest_browser_headers(req, &self.profile, Some(&origin), Some(&referer));

        let resp = req.json(&body).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ktalk authorize/session failed ({status}): {text}");
        }

        let auth_res: AuthorizeSessionResponse = resp.json().await?;
        Ok(auth_res)
    }

    /// Resolve conference room ID from short room name with browser stealth headers.
    pub async fn resolve_room(
        &self,
        domain: &str,
        room_short_name: &str,
        session_token: &str,
    ) -> anyhow::Result<RoomInfoResponse> {
        let url = format!("https://{domain}/api/rooms/{room_short_name}");
        let origin = format!("https://{domain}");
        let referer = format!("https://{domain}/{room_short_name}");

        let req = self
            .http
            .get(&url)
            .header("Authorization", format!("Session {session_token}"))
            .header("Accept", "application/json");

        let req = apply_reqwest_browser_headers(req, &self.profile, Some(&origin), Some(&referer));

        let resp = req.send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ktalk resolve room failed ({status}): {text}");
        }

        let room_info: RoomInfoResponse = resp.json().await?;
        Ok(room_info)
    }
}
