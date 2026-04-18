use log::{error};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize)]
struct CheckAccessRequest {
    fingerprint: String,
}

#[derive(Deserialize)]
struct CheckAccessResponse {
    message: String,
    allowed: bool,
}

#[derive(Serialize)]
struct SessionEventRequest {
    pub fingerprint: String,
}

#[derive(Clone)]
pub struct AuthProvider {
    /// Локальный "белый список" (VIP, админы, резерв)
    allowed_clients: Vec<String>,

    /// Список внешних серверов авторизации
    auth_servers: Vec<String>,

    /// Токен доступа к внешним серверам
    auth_token: String,

    /// HTTP клиент для запросов
    http_client: HttpClient,
}

pub enum AuthError {
    SessionsLimit,
    Expired,
    NotFound,
}

impl AuthProvider {
    pub fn new(
        allowed_clients: Vec<String>,
        auth_servers: Vec<String>,
        auth_token: String,
    ) -> Self {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();

        Self {
            allowed_clients,
            auth_servers,
            auth_token,
            http_client,
        }
    }

    /// Проверяет, разрешен ли доступ клиенту с данным fingerprint
    pub async fn is_client_allowed(&self, fingerprint: &str) -> Result<(), String> {
        // 1. Локальный список (VIP)
        if self.allowed_clients.iter().any(|c| c == fingerprint) {
            return Ok(());
        }

        // 2. Внешние сервера
        let req_body = CheckAccessRequest { fingerprint: fingerprint.to_string() };

        for server_url in &self.auth_servers {
            let url = format!("{}/check_access", server_url);
            let res = self.http_client.post(&url)
                .header("X-Auth-Key", &self.auth_token)
                .json(&req_body).send().await;

            match res {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<CheckAccessResponse>().await {
                        if json.allowed {
                            return Ok(());
                        } else {
                            return Err(json.message);
                        }
                    }
                }
                Err(e) => { error!("[Auth] Server {} unreachable: {}", server_url, e); continue; }
            }
        }
        Err("Все сервера авторизации недоступны".into())
    }


    pub async fn report_session_start(&self, fingerprint: String) {
        if self.auth_servers.is_empty() { return; }
        let req_body = SessionEventRequest { fingerprint };
        for server_url in &self.auth_servers {
            let url = format!("{}/session/start", server_url);
            let _ = self.http_client.post(&url).header("X-Auth-Key", &self.auth_token).json(&req_body).send().await;
        }
    }

    pub async fn report_session_stop(&self, fingerprint: String) {
        if self.auth_servers.is_empty() { return; }
        let req_body = SessionEventRequest { fingerprint };
        for server_url in &self.auth_servers {
            let url = format!("{}/session/stop", server_url);
            let _ = self.http_client.post(&url).header("X-Auth-Key", &self.auth_token).json(&req_body).send().await;
        }
    }
}
