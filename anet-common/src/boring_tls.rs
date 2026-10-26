use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode, SslVersion};

/// Базовая конфигурация BoringSSL, мимикрирующая под TLS-отпечаток Google Chrome (JA3/JA4):
/// GREASE, кривые X25519/P-256/P-384, версии TLS 1.2..=1.3, OCSP Stapling, SCT и порядок шифров.
fn build_chrome_ssl_connector_base() -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    // Включаем GREASE-расширения (ключевой маркер Chrome для обхода IDS/IPS)
    builder.set_grease_enabled(true);

    // Ограничиваем версии протокола строго TLS 1.2 .. TLS 1.3 (современный Chromium)
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Задаем точный список и порядок эллиптических кривых (Supported Groups) как в Chrome
    builder.set_curves_list("X25519:P-256:P-384")?;

    // Включаем расширения status_request (OCSP stapling) и signed_certificate_timestamp (SCT)
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();

    // Порядок шифров TLS 1.3 (Приоритет AES-GCM)
    builder.set_ciphersuites(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    )?;

    // Порядок шифров TLS 1.2
    builder.set_cipher_list(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    )?;

    // Доверие узлу ANet обеспечивается ASTP-хендшейком внутри туннеля.
    // Отключаем валидацию TLS сертификатов.
    builder.set_verify_callback(SslVerifyMode::NONE, |_preverify_ok, _x509_ctx| true);

    Ok(builder)
}

/// Создает конфигурацию BoringSSL для HTTP-клиентов (`reqwest`), идеально мимикрирующую под Google Chrome.
/// Заявляет в ALPN поддержку `h2` (HTTP/2) и `http/1.1` (в wire-формате с префиксами длины: `\x02h2\x08http/1.1`).
pub fn build_chrome_ssl_connector() -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = build_chrome_ssl_connector_base()?;
    // ALPN wire-format: [длина=2]"h2"[длина=8]"http/1.1"
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    Ok(builder)
}

/// Создает конфигурацию BoringSSL для WebSocket (`tokio-tungstenite`) и потоковых TLS-соединений (`TURNS`).
/// Заявляет в ALPN строго `http/1.1` (`\x08http/1.1`), чтобы Reverse Proxy / CDN не согласовывал HTTP/2
/// перед отправкой HTTP/1.1 заголовка `Upgrade: websocket`.
pub fn build_chrome_ws_ssl_connector() -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = build_chrome_ssl_connector_base()?;
    // ALPN wire-format: [длина=8]"http/1.1"
    builder.set_alpn_protos(b"\x08http/1.1")?;
    Ok(builder)
}

