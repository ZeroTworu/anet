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
                    let _ = seed;
                    Self::Safari
                }
                #[cfg(target_os = "macos")]
                {
                    match seed % 2 {
                        0 => Self::Chrome,
                        _ => Self::Safari,
                    }
                }
                #[cfg(target_os = "android")]
                {
                    let _ = seed;
                    Self::Chrome
                }
                #[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "android")))]
                {
                    let _ = seed;
                    Self::Chrome
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

/// Глобальный реестр пользовательских переопределений профилей браузеров (`[[browser_profiles]]`).
static CUSTOM_BROWSER_PROFILES: LazyLock<RwLock<Vec<crate::config::BrowserProfileConfig>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));

/// Устанавливает пользовательские переопределения профилей браузеров из `client.toml` или `server.toml`.
pub fn set_browser_profiles(profiles: Vec<crate::config::BrowserProfileConfig>) {
    if let Ok(mut guard) = CUSTOM_BROWSER_PROFILES.write() {
        *guard = profiles;
    }
}

/// Возвращает пользовательское переопределение `[[browser_profiles]]` для указанного семейства браузера, если оно задано.
pub fn get_browser_profile_override(
    fp: TlsFingerprint,
) -> Option<crate::config::BrowserProfileConfig> {
    let target = match fp {
        TlsFingerprint::Chrome | TlsFingerprint::Auto => "chrome",
        TlsFingerprint::Firefox => "firefox",
        TlsFingerprint::Safari => "safari",
        TlsFingerprint::Randomized => return None,
    };
    let guard = CUSTOM_BROWSER_PROFILES.read().ok()?;
    guard
        .iter()
        .find(|p| {
            p.name.trim().eq_ignore_ascii_case(target)
                || p.name
                    .trim()
                    .parse::<TlsFingerprint>()
                    .ok()
                    .is_some_and(|parsed| parsed.as_str() == target)
        })
        .cloned()
}

/// Однократно загруженный кэш системных корневых сертификатов ОС (Linux, Windows, macOS, Android, iOS).
static SYSTEM_ROOT_CERTS: LazyLock<Vec<X509>> = LazyLock::new(load_platform_root_certs);

fn load_platform_root_certs() -> Vec<X509> {
    let mut certs = Vec::new();
    let mut seen_der = std::collections::HashSet::new();

    fn push_unique_der(
        certs: &mut Vec<X509>,
        seen_der: &mut std::collections::HashSet<Vec<u8>>,
        der_bytes: &[u8],
    ) {
        if seen_der.insert(der_bytes.to_vec()) {
            if let Ok(x509) = X509::from_der(der_bytes) {
                certs.push(x509);
            }
        }
    }

    fn push_unique_cert(
        certs: &mut Vec<X509>,
        seen_der: &mut std::collections::HashSet<Vec<u8>>,
        cert: X509,
    ) {
        if let Ok(der) = cert.to_der() {
            if seen_der.insert(der) {
                certs.push(cert);
            }
        }
    }

    // 1. Нативное хранилище ОС (Windows CryptoAPI/schannel, macOS/iOS Keychain, Linux openssl-probe)
    let native_result = rustls_native_certs::load_native_certs();
    for der in native_result.certs {
        push_unique_der(&mut certs, &mut seen_der, der.as_ref());
    }

    // 2. Встроенный бандл корневых сертификатов Mozilla WebPKI (CCADB).
    for root_der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        push_unique_der(&mut certs, &mut seen_der, root_der.as_ref());
    }

    // 3. Стандартные пути к PEM-бандлам в Linux / BSD / macOS
    const BUNDLE_PATHS: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];
    for path in BUNDLE_PATHS {
        if let Ok(pem_bytes) = std::fs::read(path) {
            if let Ok(stack) = X509::stack_from_pem(&pem_bytes) {
                for cert in stack {
                    push_unique_cert(&mut certs, &mut seen_der, cert);
                }
                break;
            }
        }
    }

    // 4. Системные директории корневых сертификатов Android (Android 8..16+)
    for android_dir in [
        "/system/etc/security/cacerts",
        "/apex/com.android.conscrypt/cacerts",
    ] {
        if let Ok(entries) = std::fs::read_dir(android_dir) {
            for entry in entries.flatten() {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    if let Ok(stack) = X509::stack_from_pem(&bytes) {
                        for cert in stack {
                            push_unique_cert(&mut certs, &mut seen_der, cert);
                        }
                    } else {
                        push_unique_der(&mut certs, &mut seen_der, &bytes);
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
    ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:\
    ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:\
    AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA:\
    ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA";

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
    rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:\
    ecdsa_sha1:rsa_pkcs1_sha1";

const SAFARI_SIGALGS: &str = "\
    ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
    ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:\
    rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:\
    rsa_pkcs1_sha384:rsa_pkcs1_sha512:\
    ecdsa_sha1:rsa_pkcs1_sha1";

fn set_chrome_curves(builder: &mut SslConnectorBuilder) -> anyhow::Result<()> {
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
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    let concrete_fp = cfg.fingerprint.resolve_for_os(cfg.random_seed);
    match concrete_fp {
        TlsFingerprint::Chrome | TlsFingerprint::Auto => {
            let ov = get_browser_profile_override(TlsFingerprint::Chrome);
            builder.set_grease_enabled(ov.as_ref().and_then(|o| o.grease).unwrap_or(true));
            builder.set_permute_extensions(
                ov.as_ref()
                    .and_then(|o| o.permute_extensions)
                    .unwrap_or(true),
            );
            if ov.as_ref().and_then(|o| o.session_ticket) == Some(false) {
                builder.set_options(boring::ssl::SslOptions::NO_TICKET);
            }
            if let Some(curves) = ov
                .as_ref()
                .and_then(|o| o.curves.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if builder.set_curves_list(curves).is_err() && curves.contains("X25519MLKEM768:") {
                    let fallback = curves.replace("X25519MLKEM768:", "");
                    builder.set_curves_list(&fallback)?;
                }
            } else {
                set_chrome_curves(&mut builder)?;
            }
            if ov.as_ref().and_then(|o| o.ocsp_stapling).unwrap_or(true) {
                builder.enable_ocsp_stapling();
            }
            if ov
                .as_ref()
                .and_then(|o| o.signed_cert_timestamps)
                .unwrap_or(true)
            {
                builder.enable_signed_cert_timestamps();
            }
            let ciphers = ov
                .as_ref()
                .and_then(|o| o.cipher_list.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(CHROME_CIPHERS);
            builder.set_cipher_list(ciphers)?;
            let sigalgs = ov
                .as_ref()
                .and_then(|o| o.sigalgs.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(CHROME_SIGALGS);
            let _ = builder.set_sigalgs_list(sigalgs);
        }
        TlsFingerprint::Firefox => {
            let ov = get_browser_profile_override(TlsFingerprint::Firefox);
            builder.set_grease_enabled(ov.as_ref().and_then(|o| o.grease).unwrap_or(false));
            builder.set_permute_extensions(
                ov.as_ref()
                    .and_then(|o| o.permute_extensions)
                    .unwrap_or(false),
            );
            if ov.as_ref().and_then(|o| o.session_ticket) == Some(false) {
                builder.set_options(boring::ssl::SslOptions::NO_TICKET);
            }
            if let Some(curves) = ov
                .as_ref()
                .and_then(|o| o.curves.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if builder.set_curves_list(curves).is_err() && curves.contains("X25519MLKEM768:") {
                    let fallback = curves.replace("X25519MLKEM768:", "");
                    builder.set_curves_list(&fallback)?;
                }
            } else {
                builder.set_curves_list("X25519:P-256:P-384:P-521")?;
            }
            if ov.as_ref().and_then(|o| o.ocsp_stapling).unwrap_or(true) {
                builder.enable_ocsp_stapling();
            }
            if ov
                .as_ref()
                .and_then(|o| o.signed_cert_timestamps)
                .unwrap_or(false)
            {
                builder.enable_signed_cert_timestamps();
            }
            let ciphers = ov
                .as_ref()
                .and_then(|o| o.cipher_list.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(FIREFOX_CIPHERS);
            builder.set_cipher_list(ciphers)?;
            let sigalgs = ov
                .as_ref()
                .and_then(|o| o.sigalgs.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(FIREFOX_SIGALGS);
            let _ = builder.set_sigalgs_list(sigalgs);
        }
        TlsFingerprint::Safari => {
            let ov = get_browser_profile_override(TlsFingerprint::Safari);
            builder.set_grease_enabled(ov.as_ref().and_then(|o| o.grease).unwrap_or(true));
            builder.set_permute_extensions(
                ov.as_ref()
                    .and_then(|o| o.permute_extensions)
                    .unwrap_or(false),
            );
            if !ov.as_ref().and_then(|o| o.session_ticket).unwrap_or(false) {
                builder.set_options(boring::ssl::SslOptions::NO_TICKET);
            }
            if let Some(curves) = ov
                .as_ref()
                .and_then(|o| o.curves.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if builder.set_curves_list(curves).is_err() && curves.contains("X25519MLKEM768:") {
                    let fallback = curves.replace("X25519MLKEM768:", "");
                    builder.set_curves_list(&fallback)?;
                }
            } else {
                builder.set_curves_list("X25519:P-256:P-384:P-521")?;
            }
            if ov.as_ref().and_then(|o| o.ocsp_stapling).unwrap_or(true) {
                builder.enable_ocsp_stapling();
            }
            if ov
                .as_ref()
                .and_then(|o| o.signed_cert_timestamps)
                .unwrap_or(true)
            {
                builder.enable_signed_cert_timestamps();
            }
            let ciphers = ov
                .as_ref()
                .and_then(|o| o.cipher_list.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(SAFARI_CIPHERS);
            builder.set_cipher_list(ciphers)?;
            let sigalgs = ov
                .as_ref()
                .and_then(|o| o.sigalgs.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(SAFARI_SIGALGS);
            let _ = builder.set_sigalgs_list(sigalgs);
        }
        TlsFingerprint::Randomized => {
            let h1 = splitmix64(cfg.random_seed);
            let h2 = splitmix64(h1);

            let enable_sct = ((h1 >> 3) & 1) == 1;

            builder.set_grease_enabled(true);
            builder.set_permute_extensions(true);
            builder.enable_ocsp_stapling();
            if enable_sct {
                builder.enable_signed_cert_timestamps();
            }

            match (h1 >> 4) % 4 {
                0 | 1 => set_chrome_curves(&mut builder)?,
                2 => builder.set_curves_list("X25519:P-256:P-384:P-521")?,
                _ => builder.set_curves_list("X25519:P-256:P-384")?,
            }

            #[cfg(target_vendor = "apple")]
            let ciphers = match h2 % 4 {
                0 => CHROME_CIPHERS,
                1 => FIREFOX_CIPHERS,
                2 => SAFARI_CIPHERS,
                _ => CHACHA_FIRST_CIPHERS,
            };
            #[cfg(not(target_vendor = "apple"))]
            let ciphers = match h2 % 3 {
                0 => CHROME_CIPHERS,
                1 => FIREFOX_CIPHERS,
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
                    "[TLS Anti-Spoof] Certificate SHA-256 pin mismatch! Expected {}, got cert={:?} spki={:?}.",
                    hex_encode(pin),
                    cert_hash.map(|h| hex_encode(&h)),
                    spki_hash.map(|h| hex_encode(&h)),
                );
            }
            return matched;
        }

        if !preverify_ok {
            log::warn!(
                "[TLS Anti-Spoof] Peer certificate verification failed at depth {} ({:?})",
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

// =========================================================================
// ЭТАЛОННЫЙ EMAIL TLS-КОННЕКТОР (IMAPS:993, KMail / OpenSSL 3.x)
// =========================================================================

/// Список шифров OpenSSL 3.x с приоритетом TLS 1.3 AES-256 для почтовых клиентов
const EMAIL_CIPHERS: &str = "\
    TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:\
    ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
    DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:\
    ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
    ECDHE-RSA-AES128-GCM-SHA256";

/// Создает конфигуратор BoringSSL с идеальной мимикрией под почтовый клиент (KMail / OpenSSL 3.x):
/// - Строго отключены GREASE и случайная перестановка расширений (Permutation);
/// - На 993 порту НЕ отправляется ALPN (никаких h2 или http/1.1);
/// - Выставлен приоритет AES-256-GCM в TLS 1.3 и поддержка X25519MLKEM768;
/// - Настроена WebPKI и анти-спуфинг валидация сертификатов.
pub fn build_email_ssl_connector_with_config(
    cfg: &TlsClientConfig,
) -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Отключаем браузерный GREASE и случайную перестановку расширений
    builder.set_grease_enabled(false);
    builder.set_permute_extensions(false);

    // ВАЖНО: На 993 порту расширение ALPN НЕ отправляется вовсе!
    // (Не вызываем builder.set_alpn_protos)

    // Приоритет AES-256 в TLS 1.3 и классический OpenSSL стек
    builder.set_cipher_list(EMAIL_CIPHERS)?;

    // Пост-квантовые группы обмена ключами
    if builder
        .set_curves_list("X25519MLKEM768:X25519:P-256:P-384")
        .is_err()
    {
        let _ = builder.set_curves_list("X25519:P-256:P-384");
    }

    configure_verification(&mut builder, cfg)?;

    Ok(builder)
}

/// Выполняет асинхронный клиентский TLS-хендшейк для IMAPS (порт 993)
/// с профилем почтового клиента (KMail / OpenSSL 3.x) через `tokio-boring`.
pub async fn connect_email_tls_with_config<S>(
    domain: &str,
    stream: S,
    cfg: &TlsClientConfig,
) -> anyhow::Result<tokio_boring::SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let ssl_connector = build_email_ssl_connector_with_config(cfg)?.build();
    let mut ssl_config = ssl_connector.configure()?;

    let is_ip = domain.parse::<std::net::IpAddr>().is_ok();
    if is_ip {
        ssl_config.set_use_server_name_indication(false);
    }

    let verify_hostname = !is_ip
        && cfg.verify_peer
        && cfg.pin_sha256.as_ref().is_none_or(|p| p.trim().is_empty());
    ssl_config.set_verify_hostname(verify_hostname);

    tokio_boring::connect(ssl_config, domain, stream)
        .await
        .map_err(|e| anyhow::anyhow!("BoringSSL Email IMAPS TLS handshake failed for {domain}: {e}"))
}
