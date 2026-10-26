use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode};

/// Создает конфигурацию BoringSSL, идеально мимикрирующую под Google Chrome.
/// Включает поддержку GREASE, строгий порядок шифров и ALPN.
pub fn build_chrome_ssl_connector() -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    // Включаем GREASE-расширения (ключевой маркер Chrome для обхода IDS/IPS)
    builder.set_grease_enabled(true);

    // ALPN: Заявляем поддержку HTTP/2 и HTTP/1.1
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;

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
