use base64::prelude::*;
use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use std::sync::{LazyLock, RwLock};

/// Режим маскировки TLS-отпечатка (ClientHello JA3 / JA4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsFingerprint {
    /// Автоматический выбор реалистичного профиля браузера под текущую ОС
    /// со 100% синхронизацией L4 (TLS ClientHello) и L7 (HTTP-заголовки).
    #[default]
    Auto,
    /// Google Chrome / Microsoft Edge / Chromium (v135–153+):
    /// GREASE включен, перестановка расширений (permute_extensions = true),
    /// кривые X25519MLKEM768/X25519:P-256:P-384, OCSP Stapling + SCT, шифры AES-128 -> AES-256 -> ChaCha20.
    Chrome,
    /// Mozilla Firefox (NSS v135+):
    /// GREASE выключен, фиксированный порядок расширений (permute_extensions = false),
    /// кривые X25519:P-256:P-384:P-521, OCSP Stapling без SCT, шифры AES-128 -> ChaCha20 -> AES-256.
    Firefox,
    /// Apple Safari / WebKit (macOS / iOS 17.4+):
    /// GREASE включен, фиксированный порядок расширений (permute_extensions = false),
    /// кривые X25519:P-256:P-384:P-521, OCSP Stapling + SCT, шифры AES-256 -> AES-128 -> ChaCha20.
    Safari,
    /// Полиморфный браузерный отпечаток:
    /// Генерирует валидный браузерный ClientHello со случайной комбинацией GREASE,
    /// перестановки расширений, набора кривых (с P-521 или без), SCT и порядка шифров TLS 1.2
    /// для обхода сигнатурных блокировок статических JA3/JA4 хешей на ТСПУ.
    Randomized,
}

impl TlsFingerprint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Randomized => "randomized",
        }
    }

    /// Разрешает `Auto` в конкретное семейство браузера с учётом целевой ОС и случайного зерна.
    pub fn resolve_for_os(self, seed: u64) -> Self {
        match self {
            Self::Auto => {
                #[cfg(target_os = "ios")]
                {
                    match seed % 3 {
                        0 | 1 => Self::Safari,
                        _ => Self::Randomized,
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    match seed % 4 {
                        0 => Self::Chrome,
                        1 => Self::Safari,
                        2 => Self::Firefox,
                        _ => Self::Randomized,
                    }
                }
                #[cfg(target_os = "android")]
                {
                    match seed % 3 {
                        0 => Self::Chrome,
                        1 => Self::Firefox,
                        _ => Self::Randomized,
                    }
                }
                #[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "android")))]
                {
                    match seed % 3 {
                        0 => Self::Chrome,
                        1 => Self::Firefox,
                        _ => Self::Randomized,
                    }
                }
            }
            concrete => concrete,
        }
    }
}

impl fmt::Display for TlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TlsFingerprint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" | "default" => Ok(Self::Auto),
            "chrome" | "chromium" | "edge" | "yabrowser" => Ok(Self::Chrome),
            "firefox" | "ff" | "mozilla" | "nss" => Ok(Self::Firefox),
            "safari" | "webkit" | "apple" | "ios" => Ok(Self::Safari),
            "randomized" | "random" | "polymorphic" | "shuffle" => Ok(Self::Randomized),
            other => anyhow::bail!(
                "Unknown tls_fingerprint '{other}' (expected: auto, chrome, firefox, safari, randomized)"
            ),
        }
    }
}

impl Serialize for TlsFingerprint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TlsFingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Конфигурация клиентского TLS-движка и защиты от активного спуфинга ТСПУ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientConfig {
    /// Выбранный профиль TLS-отпечатка (`auto`, `chrome`, `firefox`, `safari`, `randomized`).
    pub fingerprint: TlsFingerprint,
    /// Зерно для детерминированной генерации параметров в рамках одного профиля `BrowserProfile`.
    pub random_seed: u64,
    /// Защита от активного спуфинга ТСПУ (MITM / подмены сертификата на этапе TLS Handshake).
    /// По умолчанию: `true` (включено).
    pub verify_peer: bool,
    /// Опциональный SHA-256 пиннинг сертификата или публичного ключа (SPKI) сервера (Hex или Base64).
    /// Позволяет защититься от активного спуфинга ТСПУ даже при использовании самоподписанного сертификата.
    pub pin_sha256: Option<String>,
    /// Опциональный пользовательский корневой/серверный сертификат (путь к PEM-файлу или inline PEM).
    pub ca_cert: Option<String>,
}

impl Default for TlsClientConfig {
    fn default() -> Self {
        Self {
            fingerprint: TlsFingerprint::Auto,
            random_seed: rand::random(),
            verify_peer: true,
            pin_sha256: None,
            ca_cert: None,
        }
    }
}

impl TlsClientConfig {
    /// Возвращает копию конфигурации со свежим случайным зерном.
    pub fn with_fresh_seed(&self) -> Self {
        let mut cloned = self.clone();
        cloned.random_seed = rand::random();
        cloned
    }
}

/// Глобальная политика TLS по умолчанию (инициализируется из `[stealth]` и `[[servers]]` в `client.toml`).
static DEFAULT_TLS_CONFIG: LazyLock<RwLock<TlsClientConfig>> =
    LazyLock::new(|| RwLock::new(TlsClientConfig::default()));

/// Устанавливает глобальную конфигурацию TLS по умолчанию для новых профилей `BrowserProfile` и WS/TURNS коннекторов.
pub fn set_default_tls_config(config: TlsClientConfig) {
    if let Ok(mut guard) = DEFAULT_TLS_CONFIG.write() {
        *guard = config;
    }
}

/// Возвращает текущую глобальную конфигурацию TLS со свежим случайным зерном для новой сессии.
pub fn get_default_tls_config() -> TlsClientConfig {
    DEFAULT_TLS_CONFIG
        .read()
        .map(|g| g.with_fresh_seed())
        .unwrap_or_default()
}

/// Однократно загруженный кэш системных корневых сертификатов ОС (Linux, Windows, macOS, Android, iOS).
static SYSTEM_ROOT_CERTS: LazyLock<Vec<X509>> = LazyLock::new(load_platform_root_certs);

fn load_platform_root_certs() -> Vec<X509> {
    let mut certs = Vec::new();

    // 1. Нативное хранилище ОС (Windows CryptoAPI/schannel, macOS/iOS Keychain, Linux openssl-probe)
    let native_result = rustls_native_certs::load_native_certs();
    for der in native_result.certs {
        if let Ok(x509) = X509::from_der(der.as_ref()) {
            certs.push(x509);
        }
    }

    // 2. Стандартные пути к PEM-бандлам в Linux / BSD / macOS
    const BUNDLE_PATHS: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];
    if certs.is_empty() {
        for path in BUNDLE_PATHS {
            if let Ok(pem_bytes) = std::fs::read(path) {
                if let Ok(stack) = X509::stack_from_pem(&pem_bytes) {
                    certs.extend(stack);
                    if !certs.is_empty() {
                        break;
                    }
                }
            }
        }
    }

    // 3. Системные директории корневых сертификатов Android (Android 8..16+)
    for android_dir in [
        "/system/etc/security/cacerts",
        "/apex/com.android.conscrypt/cacerts",
    ] {
        if let Ok(entries) = std::fs::read_dir(android_dir) {
            for entry in entries.flatten() {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    if let Ok(stack) = X509::stack_from_pem(&bytes) {
                        certs.extend(stack);
                    } else if let Ok(x509) = X509::from_der(&bytes) {
                        certs.push(x509);
                    }
                }
            }
        }
    }

    certs
}

fn parse_custom_certs(ca_input: &str) -> anyhow::Result<Vec<X509>> {
    let trimmed = ca_input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let raw_bytes = if trimmed.contains("-----BEGIN CERTIFICATE-----") {
        trimmed.as_bytes().to_vec()
    } else {
        std::fs::read(trimmed).map_err(|e| {
            anyhow::anyhow!("Failed to read custom CA certificate file '{trimmed}': {e}")
        })?
    };

    if let Ok(stack) = X509::stack_from_pem(&raw_bytes) {
        if !stack.is_empty() {
            return Ok(stack);
        }
    }
    if let Ok(single) = X509::from_der(&raw_bytes) {
        return Ok(vec![single]);
    }
    anyhow::bail!("No valid X509 certificates found in custom CA input")
}

/// Разбирает строку SHA-256 пина в формате Hex (с двоеточиями или без, с префиксом `sha256/` или без) или Base64.
pub fn parse_sha256_pin(pin_str: &str) -> anyhow::Result<[u8; 32]> {
    let mut s = pin_str.trim();
    for prefix in ["sha256/", "sha256:", "SHA256/", "SHA256:"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.trim();
            break;
        }
    }

    let hex_candidate: String = s.chars().filter(|c| *c != ':' && *c != '-').collect();
    if hex_candidate.len() == 64 && hex_candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex_candidate[i * 2..i * 2 + 2], 16)?;
        }
        return Ok(out);
    }

    if let Ok(decoded) = BASE64_STANDARD
        .decode(s)
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(s))
    {
        if decoded.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&decoded);
            return Ok(out);
        }
    }

    anyhow::bail!(
        "Invalid tls_pin_sha256 format '{}': expected 64-char hex or 32-byte base64 SHA-256 digest",
        pin_str
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Вычисляет SHA-256 дайджест DER-представления сертификата и его SPKI (SubjectPublicKeyInfo).
pub fn cert_and_spki_sha256(cert: &boring::x509::X509Ref) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
    let cert_hash = cert.to_der().ok().map(|der| {
        let digest = Sha256::digest(&der);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        arr
    });

    let spki_hash = cert
        .public_key()
        .ok()
        .and_then(|pk| pk.public_key_to_der().ok())
        .map(|spki_der| {
            let digest = Sha256::digest(&spki_der);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&digest);
            arr
        });

    (cert_hash, spki_hash)
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

const CHROME_CIPHERS: &str = "\
    ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
    ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
    ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
    ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
    AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

const FIREFOX_CIPHERS: &str = "\
    ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
    ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
    ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
    ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:\
    ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
    AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

const SAFARI_CIPHERS: &str = "\
    ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:\
    ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:\
    ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:\
    ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:\
    ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
    ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:\
    ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA";

const CHACHA_FIRST_CIPHERS: &str = "\
    ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
    ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
    ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
    ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
    AES128-GCM-SHA256:AES256-GCM-SHA384";

const CHROME_SIGALGS: &str = "\
    ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
    ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
    rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

const FIREFOX_SIGALGS: &str = "\
    ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:\
    rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:\
    rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512";

const SAFARI_SIGALGS: &str = "\
    ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
    ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:\
    rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:\
    rsa_pkcs1_sha384:rsa_pkcs1_sha512";

fn set_chrome_curves(builder: &mut SslConnectorBuilder) -> anyhow::Result<()> {
    // Современный Chrome 131+ анонсирует гибридную постквантовую группу X25519MLKEM768.
    // Если текущая сборка BoringSSL её поддерживает — включаем, иначе используем классический набор Chrome.
    if builder
        .set_curves_list("X25519MLKEM768:X25519:P-256:P-384")
        .is_err()
    {
        builder.set_curves_list("X25519:P-256:P-384")?;
    }
    Ok(())
}

/// Создает базовый `SslConnectorBuilder` по заданной конфигурации профиля и защиты от активного спуфинга.
pub fn build_ssl_connector_base_with_config(
    cfg: &TlsClientConfig,
) -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    let concrete_fp = cfg.fingerprint.resolve_for_os(cfg.random_seed);
    match concrete_fp {
        TlsFingerprint::Chrome | TlsFingerprint::Auto => {
            builder.set_grease_enabled(true);
            builder.set_permute_extensions(true);
            set_chrome_curves(&mut builder)?;
            builder.enable_ocsp_stapling();
            builder.enable_signed_cert_timestamps();
            builder.set_cipher_list(CHROME_CIPHERS)?;
            let _ = builder.set_sigalgs_list(CHROME_SIGALGS);
        }
        TlsFingerprint::Firefox => {
            builder.set_grease_enabled(false);
            builder.set_permute_extensions(false);
            builder.set_curves_list("X25519:P-256:P-384:P-521")?;
            builder.enable_ocsp_stapling();
            builder.set_cipher_list(FIREFOX_CIPHERS)?;
            let _ = builder.set_sigalgs_list(FIREFOX_SIGALGS);
        }
        TlsFingerprint::Safari => {
            builder.set_grease_enabled(true);
            builder.set_permute_extensions(false);
            builder.set_curves_list("X25519:P-256:P-384:P-521")?;
            builder.enable_ocsp_stapling();
            builder.enable_signed_cert_timestamps();
            builder.set_cipher_list(SAFARI_CIPHERS)?;
            let _ = builder.set_sigalgs_list(SAFARI_SIGALGS);
        }
        TlsFingerprint::Randomized => {
            let h1 = splitmix64(cfg.random_seed);
            let h2 = splitmix64(h1);

            let grease = (h1 & 0b11) != 0; // 75% вероятности включения GREASE
            let permute = ((h1 >> 2) & 1) == 1;
            let enable_sct = ((h1 >> 3) & 1) == 1;

            builder.set_grease_enabled(grease);
            builder.set_permute_extensions(permute);
            builder.enable_ocsp_stapling();
            if enable_sct {
                builder.enable_signed_cert_timestamps();
            }

            match (h1 >> 4) % 4 {
                0 => set_chrome_curves(&mut builder)?,
                1 => builder.set_curves_list("X25519:P-256:P-384:P-521")?,
                2 => builder.set_curves_list("X25519:P-384:P-256")?,
                _ => builder.set_curves_list("X25519:P-256:P-384")?,
            }

            let ciphers = match h2 % 4 {
                0 => CHROME_CIPHERS,
                1 => FIREFOX_CIPHERS,
                2 => SAFARI_CIPHERS,
                _ => CHACHA_FIRST_CIPHERS,
            };
            builder.set_cipher_list(ciphers)?;

            let sigalgs = match (h2 >> 3) % 3 {
                0 => CHROME_SIGALGS,
                1 => FIREFOX_SIGALGS,
                _ => SAFARI_SIGALGS,
            };
            let _ = builder.set_sigalgs_list(sigalgs);
        }
    }

    configure_verification(&mut builder, cfg)?;

    Ok(builder)
}

fn configure_verification(
    builder: &mut SslConnectorBuilder,
    cfg: &TlsClientConfig,
) -> anyhow::Result<()> {
    if !cfg.verify_peer {
        builder.set_verify_callback(SslVerifyMode::NONE, |_preverify_ok, _x509_ctx| true);
        return Ok(());
    }

    let expected_pin = match cfg.pin_sha256.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(parse_sha256_pin(s)?),
        _ => None,
    };

    let mut store = X509StoreBuilder::new()?;
    let _ = store.set_default_paths();

    for cert in SYSTEM_ROOT_CERTS.iter() {
        let _ = store.add_cert(cert.clone());
    }

    if let Some(ref ca_str) = cfg.ca_cert {
        if !ca_str.trim().is_empty() {
            let custom_certs = parse_custom_certs(ca_str)?;
            for cert in custom_certs {
                let _ = store.add_cert(cert);
            }
        }
    }

    builder.set_cert_store_builder(store);

    builder.set_verify_callback(SslVerifyMode::PEER, move |preverify_ok, x509_ctx| {
        if let Some(ref pin) = expected_pin {
            // При заданном SHA-256 пине пропускаем промежуточные уровни цепочки и строго
            // сверяем листовой сертификат сервера (depth == 0) по DER SHA-256 или SPKI SHA-256.
            if x509_ctx.error_depth() > 0 {
                return true;
            }
            let Some(cert) = x509_ctx.current_cert() else {
                log::warn!(
                    "[TLS Anti-Spoof] Missing peer certificate at depth 0; aborting TLS handshake"
                );
                return false;
            };
            let (cert_hash, spki_hash) = cert_and_spki_sha256(cert);
            let matched = cert_hash.as_ref() == Some(pin) || spki_hash.as_ref() == Some(pin);
            if !matched {
                log::warn!(
                    "[TLS Anti-Spoof] Certificate SHA-256 pin mismatch! Expected {}, got cert={:?} spki={:?}. Aborting handshake before sending payload (possible TSPU active spoofing / MITM).",
                    hex_encode(pin),
                    cert_hash.map(|h| hex_encode(&h)),
                    spki_hash.map(|h| hex_encode(&h)),
                );
            }
            return matched;
        }

        if !preverify_ok {
            log::warn!(
                "[TLS Anti-Spoof] Peer certificate verification failed at depth {} ({:?}): aborting handshake before sending payload (possible TSPU active spoofing / MITM or untrusted certificate).",
                x509_ctx.error_depth(),
                x509_ctx.verify_result()
            );
        }
        preverify_ok
    });

    Ok(())
}

/// Создает конфигурацию BoringSSL для HTTP-клиентов (`reqwest`) с заданным профилем TLS и политикой верификации.
/// Заявляет в ALPN поддержку `h2` (HTTP/2) и `http/1.1` (`\x02h2\x08http/1.1`).
pub fn build_ssl_connector_with_config(
    cfg: &TlsClientConfig,
) -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = build_ssl_connector_base_with_config(cfg)?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    Ok(builder)
}

/// Создает конфигурацию BoringSSL для WebSocket (`tokio-tungstenite`) и потоковых TLS-соединений (`TURNS`)
/// с заданным профилем TLS и политикой верификации.
/// Заявляет в ALPN строго `http/1.1` (`\x08http/1.1`).
pub fn build_ws_ssl_connector_with_config(
    cfg: &TlsClientConfig,
) -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = build_ssl_connector_base_with_config(cfg)?;
    builder.set_alpn_protos(b"\x08http/1.1")?;
    Ok(builder)
}

/// Создает конфигурацию BoringSSL для HTTP-клиентов (`reqwest`) с текущими глобальными настройками по умолчанию.
pub fn build_chrome_ssl_connector() -> anyhow::Result<SslConnectorBuilder> {
    let cfg = get_default_tls_config();
    build_ssl_connector_with_config(&cfg)
}

/// Создает конфигурацию BoringSSL для WebSocket (`tokio-tungstenite`) и `TURNS` с текущими глобальными настройками.
pub fn build_chrome_ws_ssl_connector() -> anyhow::Result<SslConnectorBuilder> {
    let cfg = get_default_tls_config();
    build_ws_ssl_connector_with_config(&cfg)
}

/// Выполняет асинхронный клиентский TLS-хендшейк через `tokio-boring` (`ALPN: http/1.1`)
/// с явно заданной конфигурацией профиля и защиты от активного спуфинга.
pub async fn connect_ws_tls_with_config<S>(
    domain: &str,
    stream: S,
    cfg: &TlsClientConfig,
) -> anyhow::Result<tokio_boring::SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let ssl_connector = build_ws_ssl_connector_with_config(cfg)?.build();
    let mut ssl_config = ssl_connector.configure()?;
    let is_ip = domain.parse::<std::net::IpAddr>().is_ok();
    if is_ip {
        ssl_config.set_use_server_name_indication(false);
    }
    // Включаем проверку соответствия домена в сертификате (SAN/CN), если целевой хост — домен и активна WebPKI-верификация без ручного пина.
    let verify_hostname = !is_ip
        && cfg.verify_peer
        && cfg.pin_sha256.as_ref().is_none_or(|p| p.trim().is_empty());
    ssl_config.set_verify_hostname(verify_hostname);
    tokio_boring::connect(ssl_config, domain, stream)
        .await
        .map_err(|e| anyhow::anyhow!("BoringSSL TLS handshake failed: {e}"))
}

/// Выполняет асинхронный клиентский TLS-хендшейк через `tokio-boring` (`ALPN: http/1.1`)
/// с использованием глобальной конфигурации TLS.
pub async fn connect_chrome_ws_tls<S>(
    domain: &str,
    stream: S,
) -> anyhow::Result<tokio_boring::SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let cfg = get_default_tls_config();
    connect_ws_tls_with_config(domain, stream, &cfg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::asn1::Asn1Time;
    use boring::bn::{BigNum, MsbOption};
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::pkey::{PKey, Private};
    use boring::rsa::Rsa;
    use boring::ssl::{SslAcceptor, SslMethod};
    use boring::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
    use boring::x509::{X509Builder, X509NameBuilder};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[derive(Debug, Clone)]
    struct ParsedClientHello {
        cipher_suites: Vec<u16>,
        extensions: Vec<u16>,
        alpn_protocols: Vec<String>,
        supported_groups: Vec<u16>,
        sni: Option<String>,
    }

    fn is_grease_u16(val: u16) -> bool {
        let hi = (val >> 8) as u8;
        let lo = (val & 0xff) as u8;
        hi == lo && (lo & 0x0f) == 0x0a
    }

    /// Парсит сырой TLS Record с ClientHello для проверки реальных байтов на проводе.
    fn parse_client_hello_record(buf: &[u8]) -> anyhow::Result<ParsedClientHello> {
        anyhow::ensure!(buf.len() >= 9, "Buffer too short for TLS record");
        anyhow::ensure!(buf[0] == 0x16, "Not a TLS Handshake record");
        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        anyhow::ensure!(buf.len() >= 5 + record_len, "Incomplete TLS record");

        let hs = &buf[5..5 + record_len];
        anyhow::ensure!(hs[0] == 0x01, "Not a ClientHello handshake message");
        let ch_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
        anyhow::ensure!(hs.len() >= 4 + ch_len, "Incomplete ClientHello body");

        let body = &hs[4..4 + ch_len];
        // client_version (2) + random (32)
        let mut pos = 34;
        anyhow::ensure!(body.len() > pos, "Truncated at session_id");
        let session_id_len = body[pos] as usize;
        pos += 1 + session_id_len;

        anyhow::ensure!(body.len() >= pos + 2, "Truncated at cipher_suites");
        let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        anyhow::ensure!(body.len() >= pos + cs_len, "Truncated inside cipher_suites");
        let mut cipher_suites = Vec::with_capacity(cs_len / 2);
        for chunk in body[pos..pos + cs_len].chunks_exact(2) {
            cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        pos += cs_len;

        anyhow::ensure!(body.len() > pos, "Truncated at compression_methods");
        let comp_len = body[pos] as usize;
        pos += 1 + comp_len;

        let mut extensions = Vec::new();
        let mut alpn_protocols = Vec::new();
        let mut supported_groups = Vec::new();
        let mut sni = None;

        if body.len() >= pos + 2 {
            let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;
            let ext_end = (pos + ext_total_len).min(body.len());
            while pos + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
                let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
                pos += 4;
                if pos + ext_len > ext_end {
                    break;
                }
                let ext_data = &body[pos..pos + ext_len];
                extensions.push(ext_type);

                match ext_type {
                    // server_name (SNI)
                    0x0000 if ext_data.len() >= 5 => {
                        let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                        if ext_data.len() >= 5 + name_len {
                            sni = std::str::from_utf8(&ext_data[5..5 + name_len])
                                .ok()
                                .map(str::to_string);
                        }
                    }
                    // supported_groups (elliptic_curves)
                    0x000a if ext_data.len() >= 2 => {
                        let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                        let groups_raw = &ext_data[2..(2 + list_len).min(ext_data.len())];
                        for g in groups_raw.chunks_exact(2) {
                            supported_groups.push(u16::from_be_bytes([g[0], g[1]]));
                        }
                    }
                    // application_layer_protocol_negotiation (ALPN)
                    0x0010 if ext_data.len() >= 2 => {
                        let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                        let mut p = 2;
                        let end = (2 + list_len).min(ext_data.len());
                        while p < end {
                            let proto_len = ext_data[p] as usize;
                            p += 1;
                            if p + proto_len <= end {
                                if let Ok(proto) = std::str::from_utf8(&ext_data[p..p + proto_len])
                                {
                                    alpn_protocols.push(proto.to_string());
                                }
                                p += proto_len;
                            } else {
                                break;
                            }
                        }
                    }
                    _ => {}
                }

                pos += ext_len;
            }
        }

        Ok(ParsedClientHello {
            cipher_suites,
            extensions,
            alpn_protocols,
            supported_groups,
            sni,
        })
    }

    async fn capture_client_hello(
        connector_builder: SslConnectorBuilder,
        sni_domain: &str,
    ) -> ParsedClientHello {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });

        let domain = sni_domain.to_string();
        let _ = tokio::spawn(async move {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let ssl_cfg = connector_builder.build().configure().unwrap();
            let _ = tokio_boring::connect(ssl_cfg, &domain, tcp).await;
        })
        .await;

        let raw_bytes = server_task.await.unwrap();
        parse_client_hello_record(&raw_bytes).expect("Failed to parse captured ClientHello")
    }

    fn generate_test_cert(domain: &str) -> (X509, PKey<Private>, String) {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_nid(Nid::COMMONNAME, domain).unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        let serial_asn1 = serial.to_asn1_integer().unwrap();
        builder.set_serial_number(&serial_asn1).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(30).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let bc = BasicConstraints::new().critical().ca().build().unwrap();
        builder.append_extension(bc).unwrap();

        let ku = KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .key_cert_sign()
            .build()
            .unwrap();
        builder.append_extension(ku).unwrap();

        let san = SubjectAlternativeName::new()
            .dns(domain)
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();
        let pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
        (cert, pkey, pem)
    }

    #[tokio::test]
    async fn test_chrome_firefox_safari_randomized_client_hello_wire_format() {
        // 1. Профиль Chrome (HTTP/2 + HTTP/1.1): GREASE есть, SCT (0x0012) есть, AES256 (0xc02c) перед ChaCha20 (0xcca9)
        let chrome_cfg = TlsClientConfig {
            fingerprint: TlsFingerprint::Chrome,
            random_seed: 42,
            verify_peer: false,
            pin_sha256: None,
            ca_cert: None,
        };
        let ch_chrome = capture_client_hello(
            build_ssl_connector_with_config(&chrome_cfg).unwrap(),
            "cdn.example.com",
        )
        .await;

        assert_eq!(ch_chrome.sni.as_deref(), Some("cdn.example.com"));
        assert_eq!(ch_chrome.alpn_protocols, vec!["h2", "http/1.1"]);
        assert!(
            ch_chrome.cipher_suites.iter().any(|&c| is_grease_u16(c)),
            "Chrome profile must include GREASE cipher suite"
        );
        assert!(
            ch_chrome.extensions.iter().any(|&e| is_grease_u16(e)),
            "Chrome profile must include GREASE extensions"
        );
        assert!(
            ch_chrome.extensions.contains(&0x0005),
            "Chrome profile must include status_request (OCSP)"
        );
        assert!(
            ch_chrome.extensions.contains(&0x0012),
            "Chrome profile must include signed_certificate_timestamp (SCT)"
        );
        let pos_aes256_c = ch_chrome
            .cipher_suites
            .iter()
            .position(|&c| c == 0xc02c)
            .expect("Chrome must have ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        let pos_chacha_c = ch_chrome
            .cipher_suites
            .iter()
            .position(|&c| c == 0xcca9)
            .expect("Chrome must have ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        assert!(
            pos_aes256_c < pos_chacha_c,
            "Chrome must place AES_256_GCM before CHACHA20_POLY1305"
        );

        // 2. Профиль Firefox (WebSocket http/1.1): GREASE отсутствует, SCT отсутствует, P-521 (0x0019) присутствует, ChaCha20 перед AES256
        let ff_cfg = TlsClientConfig {
            fingerprint: TlsFingerprint::Firefox,
            random_seed: 42,
            verify_peer: false,
            pin_sha256: None,
            ca_cert: None,
        };
        let ch_ff = capture_client_hello(
            build_ws_ssl_connector_with_config(&ff_cfg).unwrap(),
            "ws.example.com",
        )
        .await;

        assert_eq!(ch_ff.sni.as_deref(), Some("ws.example.com"));
        assert_eq!(ch_ff.alpn_protocols, vec!["http/1.1"]);
        assert!(
            !ch_ff.cipher_suites.iter().any(|&c| is_grease_u16(c)),
            "Firefox NSS profile must NOT contain GREASE cipher suites"
        );
        assert!(
            !ch_ff.extensions.iter().any(|&e| is_grease_u16(e)),
            "Firefox NSS profile must NOT contain GREASE extensions"
        );
        assert!(
            !ch_ff.extensions.contains(&0x0012),
            "Firefox profile must NOT include SCT extension (0x0012)"
        );
        assert!(
            ch_ff.supported_groups.contains(&0x0019),
            "Firefox profile must include secp521r1 (P-521 = 0x0019) in supported_groups"
        );
        let pos_aes256_ff = ch_ff.cipher_suites.iter().position(|&c| c == 0xc02c).unwrap();
        let pos_chacha_ff = ch_ff.cipher_suites.iter().position(|&c| c == 0xcca9).unwrap();
        assert!(
            pos_chacha_ff < pos_aes256_ff,
            "Firefox must place CHACHA20_POLY1305 before AES_256_GCM"
        );

        // 3. Профиль Safari: GREASE есть, P-521 (0x0019) есть, AES256 (0xc02c) перед AES128 (0xc02b)
        let safari_cfg = TlsClientConfig {
            fingerprint: TlsFingerprint::Safari,
            random_seed: 42,
            verify_peer: false,
            pin_sha256: None,
            ca_cert: None,
        };
        let ch_safari = capture_client_hello(
            build_ssl_connector_with_config(&safari_cfg).unwrap(),
            "apple.example.com",
        )
        .await;

        assert!(
            ch_safari.cipher_suites.iter().any(|&c| is_grease_u16(c)),
            "Safari profile must include GREASE"
        );
        assert!(
            ch_safari.supported_groups.contains(&0x0019),
            "Safari profile must include P-521 (0x0019)"
        );
        let pos_aes256_saf = ch_safari
            .cipher_suites
            .iter()
            .position(|&c| c == 0xc02c)
            .unwrap();
        let pos_aes128_saf = ch_safari
            .cipher_suites
            .iter()
            .position(|&c| c == 0xc02b)
            .unwrap();
        assert!(
            pos_aes256_saf < pos_aes128_saf,
            "Safari must place ECDHE_ECDSA_AES256_GCM before ECDHE_ECDSA_AES128_GCM"
        );

        // 4. Профиль Randomized: разные seed дают валидные, но различающиеся отпечатки
        let mut distinct_signatures = std::collections::HashSet::new();
        for seed in 1..=12 {
            let rand_cfg = TlsClientConfig {
                fingerprint: TlsFingerprint::Randomized,
                random_seed: seed * 10007,
                verify_peer: false,
                pin_sha256: None,
                ca_cert: None,
            };
            let ch = capture_client_hello(
                build_ssl_connector_with_config(&rand_cfg).unwrap(),
                "poly.example.com",
            )
            .await;
            let non_grease_cs: Vec<u16> = ch
                .cipher_suites
                .into_iter()
                .filter(|&c| !is_grease_u16(c))
                .collect();
            let non_grease_groups: Vec<u16> = ch
                .supported_groups
                .into_iter()
                .filter(|&g| !is_grease_u16(g))
                .collect();
            distinct_signatures.insert((non_grease_cs, non_grease_groups));
        }
        assert!(
            distinct_signatures.len() >= 3,
            "Randomized TLS profile must produce multiple distinct cipher/curve combinations across seeds"
        );
    }

    #[tokio::test]
    async fn test_active_spoofing_protection_blocks_mitm_before_payload() {
        let (real_cert, real_key, real_pem) = generate_test_cert("secure.example.com");
        let (spoof_cert, spoof_key, _spoof_pem) = generate_test_cert("secure.example.com");

        let (real_cert_sha256, real_spki_sha256) = cert_and_spki_sha256(&real_cert);
        let real_spki_hex = hex_encode(&real_spki_sha256.unwrap());
        let real_cert_b64 = BASE64_STANDARD.encode(real_cert_sha256.unwrap());

        // Поднимаем локальный TLS-сервер, имитирующий активный спуфинг ТСПУ (поддельный сертификат)
        let spoof_payload_bytes = Arc::new(AtomicUsize::new(0));
        let spoof_bytes_clone = spoof_payload_bytes.clone();

        let mut spoof_acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        spoof_acceptor_builder.set_private_key(&spoof_key).unwrap();
        spoof_acceptor_builder.set_certificate(&spoof_cert).unwrap();
        let spoof_acceptor = Arc::new(spoof_acceptor_builder.build());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let spoof_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acc = spoof_acceptor.clone();
                let counter = spoof_bytes_clone.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = tokio_boring::accept(&acc, tcp).await {
                        let mut buf = [0u8; 1024];
                        if let Ok(n) = tls.read(&mut buf).await {
                            counter.fetch_add(n, Ordering::SeqCst);
                        }
                    }
                });
            }
        });

        // Сценарий 1: Защита по умолчанию включена (verify_peer = true) -> поддельный сертификат ТСПУ отвергается на этапе TLS Handshake, 0 байт отправлено!
        let default_cfg = TlsClientConfig {
            fingerprint: TlsFingerprint::Chrome,
            random_seed: 1,
            verify_peer: true,
            pin_sha256: None,
            ca_cert: None,
        };
        let tcp = TcpStream::connect(spoof_addr).await.unwrap();
        let res = connect_ws_tls_with_config("secure.example.com", tcp, &default_cfg).await;
        assert!(
            res.is_err(),
            "Default verify_peer=true MUST reject untrusted/spoofed certificate during handshake"
        );
        assert_eq!(
            spoof_payload_bytes.load(Ordering::SeqCst),
            0,
            "Zero application payload bytes may be transmitted to active spoofer"
        );

        // Сценарий 2: Задан SHA-256 пин настоящего сервера, но ТСПУ подсовывает свой сертификат -> отказ!
        let pinned_cfg = TlsClientConfig {
            fingerprint: TlsFingerprint::Firefox,
            random_seed: 2,
            verify_peer: true,
            pin_sha256: Some(real_spki_hex.clone()),
            ca_cert: None,
        };
        let tcp = TcpStream::connect(spoof_addr).await.unwrap();
        let res = connect_ws_tls_with_config("secure.example.com", tcp, &pinned_cfg).await;
        assert!(
            res.is_err(),
            "Pinned verify_peer=true MUST reject spoofed certificate with non-matching SPKI SHA-256"
        );
        assert_eq!(spoof_payload_bytes.load(Ordering::SeqCst), 0);

        // Сценарий 3: Настоящий сервер с валидным сертификатом: проверяем и SPKI pin, и CA + SNI hostname!
        let mut real_acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        real_acceptor_builder.set_private_key(&real_key).unwrap();
        real_acceptor_builder.set_certificate(&real_cert).unwrap();
        real_acceptor_builder.set_alpn_select_callback(|_ssl, client_protos| {
            boring::ssl::select_next_proto(b"\x08http/1.1", client_protos)
                .ok_or(boring::ssl::AlpnError::NOACK)
        });
        let real_acceptor = Arc::new(real_acceptor_builder.build());

        let real_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr = real_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = real_listener.accept().await {
                let acc = real_acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = tokio_boring::accept(&acc, tcp).await {
                        let mut buf = [0u8; 4];
                        if tls.read_exact(&mut buf).await.is_ok() && &buf == b"PING" {
                            let _ = tls.write_all(b"PONG").await;
                        }
                    }
                });
            }
        });

        // 3a. Подключение к настоящему серверу по SPKI SHA-256 пину (Hex)
        let tcp = TcpStream::connect(real_addr).await.unwrap();
        let mut tls_stream = connect_ws_tls_with_config("secure.example.com", tcp, &pinned_cfg)
            .await
            .expect("Handshake with matching SPKI SHA-256 pin must succeed");
        tls_stream.write_all(b"PING").await.unwrap();
        let mut pong = [0u8; 4];
        tls_stream.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"PONG");

        // 3b. Подключение к настоящему серверу по Cert SHA-256 пину (Base64)
        let pinned_b64_cfg = TlsClientConfig {
            pin_sha256: Some(real_cert_b64),
            ..pinned_cfg.clone()
        };
        let tcp = TcpStream::connect(real_addr).await.unwrap();
        let _ = connect_ws_tls_with_config("secure.example.com", tcp, &pinned_b64_cfg)
            .await
            .expect("Handshake with matching Base64 cert SHA-256 pin must succeed");

        // 3c. Подключение к настоящему серверу по доверенному CA и совпадающему SNI (secure.example.com)
        let ca_cfg = TlsClientConfig {
            fingerprint: TlsFingerprint::Safari,
            random_seed: 3,
            verify_peer: true,
            pin_sha256: None,
            ca_cert: Some(real_pem),
        };
        let tcp = TcpStream::connect(real_addr).await.unwrap();
        let _ = connect_ws_tls_with_config("secure.example.com", tcp, &ca_cfg)
            .await
            .expect("Handshake with trusted CA and matching SNI hostname must succeed");

        // 3d. Подключение к тому же серверу, но с чужим SNI (имитация подстановки ТСПУ чужого валидного сертификата от другого домена) -> ОТКАЗ по HOSTNAME_MISMATCH!
        let tcp = TcpStream::connect(real_addr).await.unwrap();
        let wrong_sni_res = connect_ws_tls_with_config("another-domain.example.org", tcp, &ca_cfg).await;
        assert!(
            wrong_sni_res.is_err(),
            "verify_peer=true MUST reject certificate when SNI hostname does not match SAN"
        );

        // 3e. Явное отключение проверки в конфиге (verify_peer = false) -> пропускает самоподписанный сертификат
        let disabled_verify_cfg = TlsClientConfig {
            verify_peer: false,
            pin_sha256: None,
            ca_cert: None,
            ..default_cfg
        };
        let tcp = TcpStream::connect(real_addr).await.unwrap();
        let _ = connect_ws_tls_with_config("unverified.local", tcp, &disabled_verify_cfg)
            .await
            .expect("verify_peer=false must allow self-signed certificate when explicitly disabled");
    }
}
