//! Internal BoringSSL configuration shared by TCP and QUIC.
use boring::error::ErrorStack;
use boring::ssl::{
    ConnectConfiguration, SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode,
};
use boring::x509::store::X509StoreBuilder;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct Settings {
    pub roots: Vec<crate::Certificate>,
    pub roots_only: bool,
    pub identity: Option<crate::Identity>,
    pub crls: Arc<Vec<crate::tls::CertificateRevocationList>>,
    pub verify_certs: bool,
    pub verify_hostname: bool,
    pub sni: bool,
    pub min: Option<crate::tls::Version>,
    pub max: Option<crate::tls::Version>,
    pub keylog: bool,
}

impl Settings {
    pub fn builder(&self) -> crate::Result<SslConnectorBuilder> {
        let mut tls = SslConnector::builder(SslMethod::tls()).map_err(crate::error::builder)?;
        let min = self.min.unwrap_or(crate::tls::Version::TLS_1_2);
        if self.max.is_some_and(|max| min > max) {
            return Err(crate::error::builder("empty supported tls versions"));
        }
        tls.set_min_proto_version(Some(min.to_boring()))
            .map_err(crate::error::builder)?;
        tls.set_max_proto_version(self.max.map(crate::tls::Version::to_boring))
            .map_err(crate::error::builder)?;
        let mut store = X509StoreBuilder::new().map_err(crate::error::builder)?;
        #[cfg(not(target_vendor = "apple"))]
        if !self.roots_only {
            load_system_roots(&mut store).map_err(crate::error::builder)?;
        }
        for cert in self.roots.clone() {
            cert.add_to_boring(&mut store)?;
        }
        if !self.crls.is_empty() {
            if !self.roots_only {
                return Err(crate::error::builder(
                    "CRLs only allowed with tls_certs_only()",
                ));
            }
            for crl in self.crls.iter() {
                crl.add_to_boring(&mut store)?;
            }
            store.set_flags(
                boring::x509::verify::X509VerifyFlags::CRL_CHECK
                    | boring::x509::verify::X509VerifyFlags::CRL_CHECK_ALL,
            );
        }
        tls.set_cert_store_builder(store);
        if !self.verify_certs {
            tls.set_verify(SslVerifyMode::NONE);
        }
        #[cfg(target_vendor = "apple")]
        if !self.roots_only && self.verify_certs {
            let roots = self
                .roots
                .iter()
                .map(crate::Certificate::ders)
                .collect::<crate::Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            let verify_hostname = self.verify_hostname;
            let hostname_index = hostname_index().map_err(crate::error::builder)?;
            tls.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                use boring::ssl::{SslAlert, SslVerifyError};
                use security_framework::{
                    certificate::SecCertificate, policy::SecPolicy,
                    secure_transport::SslProtocolSide, trust::SecTrust,
                };
                let verify = || -> Result<(), Box<dyn std::error::Error>> {
                    let certs = ssl
                        .peer_cert_chain()
                        .ok_or("missing certificate chain")?
                        .iter()
                        .map(|cert| Ok(SecCertificate::from_der(&cert.to_der()?)?))
                        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
                    let hostname = if verify_hostname {
                        Some(
                            ssl.ex_data(hostname_index)
                                .ok_or("missing TLS hostname")?
                                .as_str(),
                        )
                    } else {
                        None
                    };
                    let policy = SecPolicy::create_ssl(SslProtocolSide::SERVER, hostname);
                    let mut trust = SecTrust::create_with_certificates(&certs, &[policy])?;
                    if !roots.is_empty() {
                        let anchors = roots
                            .iter()
                            .map(|der| SecCertificate::from_der(der))
                            .collect::<Result<Vec<_>, _>>()?;
                        trust.set_anchor_certificates(&anchors)?;
                        trust.set_trust_anchor_certificates_only(false)?;
                    }
                    trust
                        .evaluate_with_error()
                        .map_err(|e| format!("platform certificate verification failed: {e}"))?;
                    Ok(())
                };
                verify().map_err(|_| SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
            });
        }
        if let Some(id) = self.identity.clone() {
            id.add_to_boring(&mut tls)?;
        }
        if self.keylog {
            if let Some(path) = std::env::var_os("SSLKEYLOGFILE") {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(crate::error::builder)?;
                let file = std::sync::Mutex::new(file);
                tls.set_keylog_callback(move |_, line| {
                    use std::io::Write;
                    if let Ok(mut file) = file.lock() {
                        let _ = writeln!(file, "{line}");
                    }
                });
            }
        }
        Ok(tls)
    }
}

#[derive(Clone)]
pub(crate) struct Config {
    pub connector: SslConnector,
    sessions: Arc<std::sync::Mutex<std::collections::HashMap<SessionKey, boring::ssl::SslSession>>>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub enable_sni: bool,
    pub verify_hostname: bool,
    #[cfg(feature = "http3")]
    pub enable_early_data: bool,
    #[cfg(feature = "http3")]
    pub settings: Option<Settings>,
    #[cfg(feature = "http3")]
    pub quic_sessions: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
}

impl Config {
    pub fn new(settings: Settings) -> crate::Result<Self> {
        let sessions = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let mut builder = settings.builder()?;
        let cache = sessions.clone();
        let index = session_index().map_err(crate::error::builder)?;
        builder.set_session_cache_mode(boring::ssl::SslSessionCacheMode::CLIENT);
        builder.set_new_session_callback(move |ssl, session| {
            if let Some(key) = ssl.ex_data(index) {
                if let Ok(mut cache) = cache.lock() {
                    if cache.len() >= 64 {
                        cache.clear();
                    }
                    cache.insert(key.clone(), session);
                }
            }
        });
        Ok(Self {
            connector: builder.build(),
            sessions,
            alpn_protocols: Vec::new(),
            enable_sni: settings.sni,
            verify_hostname: settings.verify_hostname && settings.verify_certs,
            #[cfg(feature = "http3")]
            enable_early_data: false,
            #[cfg(feature = "http3")]
            settings: Some(settings),
            #[cfg(feature = "http3")]
            quic_sessions: Arc::default(),
        })
    }
    pub fn preconfigured(connector: SslConnector) -> Self {
        Self {
            connector,
            sessions: Arc::default(),
            alpn_protocols: Vec::new(),
            enable_sni: true,
            verify_hostname: true,
            #[cfg(feature = "http3")]
            enable_early_data: false,
            #[cfg(feature = "http3")]
            settings: None,
            #[cfg(feature = "http3")]
            quic_sessions: Arc::default(),
        }
    }
    pub fn configure(&self, host: &str, port: u16) -> Result<ConnectConfiguration, ErrorStack> {
        let mut config = self.connector.configure()?;
        #[cfg(target_vendor = "apple")]
        config.set_ex_data(hostname_index()?, host.to_owned());
        #[cfg(not(target_vendor = "apple"))]
        let _ = host;
        config.set_use_server_name_indication(self.enable_sni);
        config.set_verify_hostname(self.verify_hostname);
        let mut alpn = Vec::new();
        for protocol in &self.alpn_protocols {
            alpn.push(protocol.len() as u8);
            alpn.extend_from_slice(protocol);
        }
        if !alpn.is_empty() {
            config.set_alpn_protos(&alpn)?;
        }
        let key = (host.to_owned(), port, alpn);
        if let Ok(cache) = self.sessions.lock() {
            if let Some(session) = cache.get(&key) {
                // SAFETY: sessions are scoped to this connector, origin and ALPN.
                unsafe {
                    config.set_session(session)?;
                }
            }
        }
        config.set_ex_data(session_index()?, key);
        Ok(config)
    }
}

#[cfg(not(target_vendor = "apple"))]
fn load_system_roots(store: &mut X509StoreBuilder) -> Result<(), ErrorStack> {
    #[cfg(windows)]
    {
        let roots = schannel::cert_store::CertStore::open_current_user("ROOT")
            .map_err(|_| ErrorStack::get())?;
        for cert in roots.certs() {
            store.add_cert(boring::x509::X509::from_der(cert.to_der())?)?;
        }
    }
    #[cfg(not(any(target_vendor = "apple", windows)))]
    {
        store.set_default_paths()?;
        let probe = openssl_probe::probe();
        if let Some(path) = probe.cert_file {
            if let Ok(pem) = std::fs::read(path) {
                for cert in boring::x509::X509::stack_from_pem(&pem)? {
                    store.add_cert(cert)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_vendor = "apple")]
pub(crate) fn hostname_index(
) -> Result<boring::ex_data::Index<boring::ssl::Ssl, String>, ErrorStack> {
    static INDEX: std::sync::LazyLock<
        Result<boring::ex_data::Index<boring::ssl::Ssl, String>, ErrorStack>,
    > = std::sync::LazyLock::new(boring::ssl::Ssl::new_ex_index);
    INDEX.clone()
}

type SessionKey = (String, u16, Vec<u8>);
fn session_index() -> Result<boring::ex_data::Index<boring::ssl::Ssl, SessionKey>, ErrorStack> {
    static INDEX: std::sync::LazyLock<
        Result<boring::ex_data::Index<boring::ssl::Ssl, SessionKey>, ErrorStack>,
    > = std::sync::LazyLock::new(boring::ssl::Ssl::new_ex_index);
    INDEX.clone()
}
