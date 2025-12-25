use log::{error, info, warn};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize)]
struct CheckAccessRequest {
    fingerprint: String,
}

#[derive(Deserialize)]
struct CheckAccessResponse {
    allowed: bool,
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
    pub async fn is_client_allowed(&self, fingerprint: &str) -> bool {
        // 1. Сначала проверяем локальный конфиг (самое быстрое и надежное)
        if self.allowed_clients.iter().any(|c| c == fingerprint) {
            return true;
        }

        // 2. Если локально не нашли, и нет внешних серверов -> отказ
        if self.auth_servers.is_empty() {
            warn!(
                "[Auth] Client {} not found in local config and no auth servers defined",
                fingerprint
            );
            return false;
        }

        // 3. Стучимся во внешние сервера
        let req_body = CheckAccessRequest {
            fingerprint: fingerprint.to_string(),
        };

        for server_url in &self.auth_servers {
            let url = format!("{}/check_access", server_url);

            let res = self
                .http_client
                .post(&url)
                .header("X-Auth-Key", &self.auth_token)
                .json(&req_body)
                .send()
                .await;

            match res {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<CheckAccessResponse>().await {
                        if json.allowed {
                            info!(
                                "[Auth] Client {} allowed by remote server {}",
                                fingerprint, server_url
                            );
                            return true;
                        } else {
                            // Если первый сервер послал на хуй - чё дальше? пока - хз.
                            warn!(
                                "[Auth] Client {} rejected by remote server {}",
                                fingerprint, server_url
                            );
                            return false;
                        }
                    } else {
                        error!("[Auth] Failed to parse response from {}", server_url,);
                    }
                }
                Err(e) => {
                    error!(
                        "[Auth] Failed to contact {}: {}. Trying next...",
                        server_url, e
                    );
                    // Пробуем следующий сервер
                    continue;
                }
            }
        }

        warn!(
            "[Auth] Client {} access denied (all checks failed)",
            fingerprint
        );
        false
    }
}
