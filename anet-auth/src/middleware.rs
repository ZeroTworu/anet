use log::warn;
use poem::{Endpoint, Error, Middleware, Request, Result};
use std::sync::Arc;

pub struct ApiKeyMiddleware {
    pub key: String,
}

impl<E: Endpoint> Middleware<E> for ApiKeyMiddleware {
    type Output = ApiKeyEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        ApiKeyEndpoint {
            ep,
            key: Arc::new(self.key.clone()),
        }
    }
}

pub struct ApiKeyEndpoint<E> {
    ep: E,
    key: Arc<String>,
}

impl<E: Endpoint> Endpoint for ApiKeyEndpoint<E> {
    type Output = E::Output;

    async fn call(&self, req: Request) -> Result<Self::Output> {
        // Проверяем заголовок X-Auth-Key
        if let Some(auth_header) = req.headers().get("X-Auth-Key") {
            if let Ok(value) = auth_header.to_str() {
                if value == *self.key {
                    return self.ep.call(req).await;
                }
            }
        }

        // Swagger UI пускаем без пароля, чтобы видеть доку (но запросы работать не будут)
        if req.uri().path().contains("/swagger") || req.uri().path().contains("/spec") {
            return self.ep.call(req).await;
        }
        warn!("invalid auth header");
        Err(Error::from_string(
            "Invalid or missing X-Auth-Key",
            poem::http::StatusCode::UNAUTHORIZED,
        ))
    }
}
