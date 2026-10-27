//! TLS configuration and types
//!
//! A `Client` will use transport layer security (TLS) by default to connect to
//! HTTPS destinations.
//!
//! # Backends
//!
//! `reqwest-boring` is a fork of reqwest with BoringSSL as its default TLS
//! layer. An optional system-native backend is also available through Cargo
//! features.
//!
//! ## default-tls
//!
//! The `default-tls` feature enables BoringSSL through the `boring` and
//! `tokio-boring` crates. HTTP/3 uses Quiche with the same BoringSSL build.
//!
//! <div class="warning">This feature is enabled by default, and takes
//! precedence if any other crate enables it. This is true even if you declare
//! `features = []`. You must set `default-features = false` instead.</div>
//!
//! Since Cargo features are additive, other crates in your dependency tree can
//! cause the default backend to be enabled. If you wish to ensure your
//! `Client` uses a specific backend, call the appropriate builder methods
//! (such as [`tls_backend_rustls()`][]).
//!
//! [`tls_backend_rustls()`]: crate::ClientBuilder::tls_backend_rustls()
//!
//! ## native-tls
//!
//! This backend uses the [native-tls][] crate. That will try to use the system
//! TLS on Windows and Mac, and OpenSSL on Linux targets.
//!
//! Enabling the feature explicitly allows for `native-tls`-specific
//! configuration options.
//!
//! [native-tls]: https://crates.io/crates/native-tls
//!
//! ## boring, rustls, rustls-no-provider
//!
//! These features select BoringSSL through the `boring` crate. The legacy
//! rustls feature and builder names are retained for source compatibility.
//! No Rustls crypto provider is needed. Preconfigured TLS accepts a
//! `boring::ssl::SslConnector` instead of Rustls configuration objects (or a
//! native-tls connector when that backend is enabled). HTTP/3 is configured
//! through the standard builder methods.

use std::{
    fmt,
    io::{BufRead, BufReader},
};

/// Represents a X509 certificate revocation list.
#[cfg(feature = "__rustls")]
pub struct CertificateRevocationList {
    #[cfg(feature = "__rustls")]
    inner: Vec<u8>,
}

/// Represents a server X509 certificate.
#[derive(Clone)]
pub struct Certificate {
    #[cfg(feature = "__native-tls")]
    native: native_tls_crate::Certificate,
    #[cfg(feature = "__rustls")]
    original: Cert,
}

#[cfg(feature = "__rustls")]
#[derive(Clone)]
enum Cert {
    Der(Vec<u8>),
    Pem(Vec<u8>),
}

/// Represents a private key and X509 cert as a client certificate.
#[derive(Clone)]
pub struct Identity {
    #[cfg_attr(
        not(any(feature = "__native-tls", feature = "__rustls")),
        allow(unused)
    )]
    inner: ClientCert,
}

enum ClientCert {
    #[cfg(feature = "__native-tls")]
    Pkcs12(native_tls_crate::Identity),
    #[cfg(feature = "__native-tls")]
    Pkcs8(native_tls_crate::Identity),
    #[cfg(feature = "__rustls")]
    Pem { key: Vec<u8>, certs: Vec<Vec<u8>> },
}

impl Clone for ClientCert {
    fn clone(&self) -> Self {
        match self {
            #[cfg(feature = "__native-tls")]
            Self::Pkcs8(i) => Self::Pkcs8(i.clone()),
            #[cfg(feature = "__native-tls")]
            Self::Pkcs12(i) => Self::Pkcs12(i.clone()),
            #[cfg(feature = "__rustls")]
            ClientCert::Pem { key, certs } => ClientCert::Pem {
                key: key.clone(),
                certs: certs.clone(),
            },
            #[cfg_attr(
                any(feature = "__native-tls", feature = "__rustls"),
                allow(unreachable_patterns)
            )]
            _ => unreachable!(),
        }
    }
}

impl Certificate {
    /// Create a `Certificate` from a binary DER encoded certificate
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn cert() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("my_cert.der")?
    ///     .read_to_end(&mut buf)?;
    /// let cert = reqwest::Certificate::from_der(&buf)?;
    /// # drop(cert);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_der(der: &[u8]) -> crate::Result<Certificate> {
        Ok(Certificate {
            #[cfg(feature = "__native-tls")]
            native: native_tls_crate::Certificate::from_der(der).map_err(crate::error::builder)?,
            #[cfg(feature = "__rustls")]
            original: Cert::Der(der.to_owned()),
        })
    }

    /// Create a `Certificate` from a PEM encoded certificate
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn cert() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("my_cert.pem")?
    ///     .read_to_end(&mut buf)?;
    /// let cert = reqwest::Certificate::from_pem(&buf)?;
    /// # drop(cert);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pem(pem: &[u8]) -> crate::Result<Certificate> {
        Ok(Certificate {
            #[cfg(feature = "__native-tls")]
            native: native_tls_crate::Certificate::from_pem(pem).map_err(crate::error::builder)?,
            #[cfg(feature = "__rustls")]
            original: Cert::Pem(pem.to_owned()),
        })
    }

    /// Create a collection of `Certificate`s from a PEM encoded certificate bundle.
    /// Example byte sources may be `.crt`, `.cer` or `.pem` files.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn cert() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("ca-bundle.crt")?
    ///     .read_to_end(&mut buf)?;
    /// let certs = reqwest::Certificate::from_pem_bundle(&buf)?;
    /// # drop(certs);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pem_bundle(pem_bundle: &[u8]) -> crate::Result<Vec<Certificate>> {
        let mut reader = BufReader::new(pem_bundle);

        Self::read_pem_certs(&mut reader)?
            .iter()
            .map(|cert_vec| Certificate::from_der(cert_vec))
            .collect::<crate::Result<Vec<Certificate>>>()
    }

    #[cfg(feature = "__native-tls")]
    pub(crate) fn add_to_native_tls(self, tls: &mut native_tls_crate::TlsConnectorBuilder) {
        tls.add_root_certificate(self.native);
    }

    #[cfg(all(feature = "__rustls", target_vendor = "apple"))]
    pub(crate) fn ders(&self) -> crate::Result<Vec<Vec<u8>>> {
        match &self.original {
            Cert::Der(der) => Ok(vec![der.clone()]),
            Cert::Pem(pem) => Self::read_pem_certs(&mut &pem[..]),
        }
    }

    #[cfg(feature = "__rustls")]
    pub(crate) fn add_to_boring(
        self,
        store: &mut boring::x509::store::X509StoreBuilder,
    ) -> crate::Result<()> {
        let certs = match self.original {
            Cert::Der(der) => vec![der],
            Cert::Pem(pem) => Self::read_pem_certs(&mut &pem[..])?,
        };
        if certs.is_empty() {
            return Err(crate::error::builder("no certificates found"));
        }
        for der in certs {
            store
                .add_cert(boring::x509::X509::from_der(&der).map_err(crate::error::builder)?)
                .map_err(crate::error::builder)?;
        }
        Ok(())
    }

    fn read_pem_certs(reader: &mut impl BufRead) -> crate::Result<Vec<Vec<u8>>> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(crate::error::builder)?;
        Ok(pem::parse_many(buf)
            .map_err(crate::error::builder)?
            .into_iter()
            .filter(|p| p.tag() == "CERTIFICATE")
            .map(|p| p.into_contents())
            .collect())
    }
}

impl Identity {
    /// Parses a DER-formatted PKCS #12 archive, using the specified password to decrypt the key.
    ///
    /// The archive should contain a leaf certificate and its private key, as well any intermediate
    /// certificates that allow clients to build a chain to a trusted root.
    /// The chain certificates should be in order from the leaf certificate towards the root.
    ///
    /// PKCS #12 archives typically have the file extension `.p12` or `.pfx`, and can be created
    /// with the OpenSSL `pkcs12` tool:
    ///
    /// ```bash
    /// openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn pkcs12() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("my-ident.pfx")?
    ///     .read_to_end(&mut buf)?;
    /// let pkcs12 = reqwest::Identity::from_pkcs12_der(&buf, "my-privkey-password")?;
    /// # drop(pkcs12);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Optional
    ///
    /// This requires the `native-tls` Cargo feature enabled.
    #[cfg(feature = "__native-tls")]
    pub fn from_pkcs12_der(der: &[u8], password: &str) -> crate::Result<Identity> {
        Ok(Identity {
            inner: ClientCert::Pkcs12(
                native_tls_crate::Identity::from_pkcs12(der, password)
                    .map_err(crate::error::builder)?,
            ),
        })
    }

    /// Parses a chain of PEM encoded X509 certificates, with the leaf certificate first.
    /// `key` is a PEM encoded PKCS #8 formatted private key for the leaf certificate.
    ///
    /// The certificate chain should contain any intermediate certificates that should be sent to
    /// clients to allow them to build a chain to a trusted root.
    ///
    /// A certificate chain here means a series of PEM encoded certificates concatenated together.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # fn pkcs8() -> Result<(), Box<dyn std::error::Error>> {
    /// let cert = fs::read("client.pem")?;
    /// let key = fs::read("key.pem")?;
    /// let pkcs8 = reqwest::Identity::from_pkcs8_pem(&cert, &key)?;
    /// # drop(pkcs8);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Optional
    ///
    /// This requires the `native-tls` Cargo feature enabled.
    #[cfg(feature = "__native-tls")]
    pub fn from_pkcs8_pem(pem: &[u8], key: &[u8]) -> crate::Result<Identity> {
        Ok(Identity {
            inner: ClientCert::Pkcs8(
                native_tls_crate::Identity::from_pkcs8(pem, key).map_err(crate::error::builder)?,
            ),
        })
    }

    /// Parses PEM encoded private key and certificate.
    ///
    /// The input should contain a PEM encoded private key
    /// and at least one PEM encoded certificate.
    ///
    /// Note: The private key must be in RSA, SEC1 Elliptic Curve or PKCS#8 format.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn pem() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("my-ident.pem")?
    ///     .read_to_end(&mut buf)?;
    /// let id = reqwest::Identity::from_pem(&buf)?;
    /// # drop(id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Optional
    ///
    /// This requires the `boring` (or its legacy `rustls` aliases) Cargo feature enabled.
    #[cfg(feature = "__rustls")]
    pub fn from_pem(buf: &[u8]) -> crate::Result<Identity> {
        let blocks = pem::parse_many(buf).map_err(crate::error::builder)?;
        let mut certs = Vec::new();
        let mut key = None;
        for block in blocks {
            match block.tag() {
                "CERTIFICATE" => certs.push(block.into_contents()),
                "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                    key = Some(pem::encode(&block).into_bytes())
                }
                _ => return Err(crate::error::builder("invalid identity PEM section")),
            }
        }
        let key = key.ok_or_else(|| crate::error::builder("private key not found"))?;
        if certs.is_empty() {
            return Err(crate::error::builder("certificate not found"));
        }
        Ok(Identity {
            inner: ClientCert::Pem { key, certs },
        })
    }

    #[cfg(feature = "__native-tls")]
    pub(crate) fn add_to_native_tls(
        self,
        tls: &mut native_tls_crate::TlsConnectorBuilder,
    ) -> crate::Result<()> {
        match self.inner {
            ClientCert::Pkcs12(id) | ClientCert::Pkcs8(id) => {
                tls.identity(id);
                Ok(())
            }
            #[cfg(feature = "__rustls")]
            ClientCert::Pem { .. } => Err(crate::error::builder("incompatible TLS identity type")),
        }
    }

    #[cfg(feature = "__rustls")]
    pub(crate) fn add_to_boring(
        self,
        tls: &mut boring::ssl::SslContextBuilder,
    ) -> crate::Result<()> {
        match self.inner {
            ClientCert::Pem { key, certs } => {
                let mut certs = certs.into_iter();
                let cert = boring::x509::X509::from_der(
                    &certs
                        .next()
                        .ok_or_else(|| crate::error::builder("certificate not found"))?,
                )
                .map_err(crate::error::builder)?;
                tls.set_certificate(&cert).map_err(crate::error::builder)?;
                for cert in certs {
                    tls.add_extra_chain_cert(
                        boring::x509::X509::from_der(&cert).map_err(crate::error::builder)?,
                    )
                    .map_err(crate::error::builder)?;
                }
                let key = boring::pkey::PKey::private_key_from_pem(&key)
                    .map_err(crate::error::builder)?;
                tls.set_private_key(&key).map_err(crate::error::builder)?;
                tls.check_private_key().map_err(crate::error::builder)
            }
            #[cfg(feature = "__native-tls")]
            _ => Err(crate::error::builder("incompatible TLS identity type")),
        }
    }
}

#[cfg(feature = "__rustls")]
impl CertificateRevocationList {
    /// Parses a PEM encoded CRL.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn crl() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("my_crl.pem")?
    ///     .read_to_end(&mut buf)?;
    /// let crl = reqwest::tls::CertificateRevocationList::from_pem(&buf)?;
    /// # drop(crl);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Optional
    ///
    /// This requires the `boring` (or its legacy `rustls` aliases) Cargo feature enabled.
    #[cfg(feature = "__rustls")]
    pub fn from_pem(pem: &[u8]) -> crate::Result<CertificateRevocationList> {
        let block = pem::parse(pem).map_err(crate::error::builder)?;
        if block.tag() != "X509 CRL" {
            return Err(crate::error::builder("invalid crl encoding"));
        }
        Ok(CertificateRevocationList {
            inner: block.into_contents(),
        })
    }

    /// Creates a collection of `CertificateRevocationList`s from a PEM encoded CRL bundle.
    /// Example byte sources may be `.crl` or `.pem` files.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn crls() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("crl-bundle.crl")?
    ///     .read_to_end(&mut buf)?;
    /// let crls = reqwest::tls::CertificateRevocationList::from_pem_bundle(&buf)?;
    /// # drop(crls);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Optional
    ///
    /// This requires the `boring` (or its legacy `rustls` aliases) Cargo feature enabled.
    #[cfg(feature = "__rustls")]
    pub fn from_pem_bundle(pem_bundle: &[u8]) -> crate::Result<Vec<CertificateRevocationList>> {
        Ok(pem::parse_many(pem_bundle)
            .map_err(crate::error::builder)?
            .into_iter()
            .filter(|p| p.tag() == "X509 CRL")
            .map(|p| CertificateRevocationList {
                inner: p.into_contents(),
            })
            .collect())
    }

    pub(crate) fn add_to_boring(
        &self,
        store: &mut boring::x509::store::X509StoreBuilder,
    ) -> crate::Result<()> {
        use foreign_types::ForeignType;
        let mut input = self.inner.as_ptr();
        let len = self.inner.len().try_into().map_err(crate::error::builder)?;
        // SAFETY: DER input is valid for `len` bytes. The returned owned CRL is
        // freed after the store takes its own reference, including on failure.
        let ok = unsafe {
            let crl = boring_sys::d2i_X509_CRL(std::ptr::null_mut(), &mut input, len);
            if crl.is_null() {
                return Err(crate::error::builder(boring::error::ErrorStack::get()));
            }
            let ok = boring_sys::X509_STORE_add_crl(store.as_ptr(), crl);
            boring_sys::X509_CRL_free(crl);
            ok
        };
        if ok != 1 {
            return Err(crate::error::builder(boring::error::ErrorStack::get()));
        }
        Ok(())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Certificate").finish()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Identity").finish()
    }
}

#[cfg(feature = "__rustls")]
impl fmt::Debug for CertificateRevocationList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CertificateRevocationList").finish()
    }
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(InnerVersion);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
enum InnerVersion {
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

// These could perhaps be From/TryFrom implementations, but those would be
// part of the public API so let's be careful
impl Version {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: Version = Version(InnerVersion::Tls1_0);
    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: Version = Version(InnerVersion::Tls1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: Version = Version(InnerVersion::Tls1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: Version = Version(InnerVersion::Tls1_3);

    #[cfg(feature = "__native-tls")]
    pub(crate) fn to_native_tls(self) -> Option<native_tls_crate::Protocol> {
        match self.0 {
            InnerVersion::Tls1_0 => Some(native_tls_crate::Protocol::Tlsv10),
            InnerVersion::Tls1_1 => Some(native_tls_crate::Protocol::Tlsv11),
            InnerVersion::Tls1_2 => Some(native_tls_crate::Protocol::Tlsv12),
            InnerVersion::Tls1_3 => Some(native_tls_crate::Protocol::Tlsv13),
        }
    }

    #[cfg(feature = "__rustls")]
    pub(crate) fn to_boring(self) -> boring::ssl::SslVersion {
        use boring::ssl::SslVersion;
        match self.0 {
            InnerVersion::Tls1_0 => SslVersion::TLS1,
            InnerVersion::Tls1_1 => SslVersion::TLS1_1,
            InnerVersion::Tls1_2 => SslVersion::TLS1_2,
            InnerVersion::Tls1_3 => SslVersion::TLS1_3,
        }
    }

    #[cfg(feature = "__rustls")]
    pub(crate) fn from_boring(version: boring::ssl::SslVersion) -> Option<Self> {
        [Self::TLS_1_0, Self::TLS_1_1, Self::TLS_1_2, Self::TLS_1_3]
            .into_iter()
            .find(|v| v.to_boring() == version)
    }
}

pub(crate) enum TlsBackend {
    // This is the default and HTTP/3 feature does not use it so suppress it.
    #[allow(dead_code)]
    #[cfg(feature = "__native-tls")]
    NativeTls,
    #[cfg(feature = "__native-tls")]
    BuiltNativeTls(native_tls_crate::TlsConnector),
    #[cfg(feature = "__rustls")]
    Boring,
    #[cfg(feature = "__rustls")]
    BuiltBoring(boring::ssl::SslConnector),
    #[cfg(any(feature = "__native-tls", feature = "__rustls",))]
    UnknownPreconfigured,
}

impl fmt::Debug for TlsBackend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "__native-tls")]
            TlsBackend::NativeTls => write!(f, "NativeTls"),
            #[cfg(feature = "__native-tls")]
            TlsBackend::BuiltNativeTls(_) => write!(f, "BuiltNativeTls"),
            #[cfg(feature = "__rustls")]
            TlsBackend::Boring => write!(f, "Boring"),
            #[cfg(feature = "__rustls")]
            TlsBackend::BuiltBoring(_) => write!(f, "BuiltBoring"),
            #[cfg(any(feature = "__native-tls", feature = "__rustls",))]
            TlsBackend::UnknownPreconfigured => write!(f, "UnknownPreconfigured"),
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for TlsBackend {
    fn default() -> TlsBackend {
        #[cfg(any(
            all(feature = "__rustls", not(feature = "__native-tls")),
            feature = "http3"
        ))]
        {
            TlsBackend::Boring
        }

        #[cfg(all(feature = "__native-tls", not(feature = "http3")))]
        {
            TlsBackend::NativeTls
        }
    }
}

/// Hyper extension carrying extra TLS layer information.
/// Made available to clients on responses when `tls_info` is set.
#[derive(Clone)]
pub struct TlsInfo {
    pub(crate) peer_certificate: Option<Vec<u8>>,
    pub(crate) version: Option<Version>,
}

impl TlsInfo {
    /// Get the DER encoded leaf certificate of the peer.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_ref().map(|der| &der[..])
    }

    /// Get the TLS protocol version negotiated with the peer.
    ///
    /// Returns `None` if the TLS backend cannot report it. The `native-tls`
    /// backend never reports a version.
    pub fn version(&self) -> Option<Version> {
        self.version
    }
}

impl std::fmt::Debug for TlsInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("TlsInfo")
            .field("version", &self.version)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "__native-tls")]
    #[test]
    fn certificate_from_der_invalid() {
        Certificate::from_der(b"not der").unwrap_err();
    }

    #[cfg(feature = "__native-tls")]
    #[test]
    fn certificate_from_pem_invalid() {
        Certificate::from_pem(b"not pem").unwrap_err();
    }

    #[cfg(feature = "__native-tls")]
    #[test]
    fn identity_from_pkcs12_der_invalid() {
        Identity::from_pkcs12_der(b"not der", "nope").unwrap_err();
    }

    #[cfg(feature = "__native-tls")]
    #[test]
    fn identity_from_pkcs8_pem_invalid() {
        Identity::from_pkcs8_pem(b"not pem", b"not key").unwrap_err();
    }

    #[cfg(feature = "__rustls")]
    #[test]
    fn identity_from_pem_invalid() {
        Identity::from_pem(b"not pem").unwrap_err();
    }

    #[cfg(feature = "__rustls")]
    #[test]
    fn identity_from_pem_pkcs1_key() {
        let pem = b"-----BEGIN CERTIFICATE-----\n\
            -----END CERTIFICATE-----\n\
            -----BEGIN RSA PRIVATE KEY-----\n\
            -----END RSA PRIVATE KEY-----\n";

        Identity::from_pem(pem).unwrap();
    }

    #[test]
    fn certificates_from_pem_bundle() {
        const PEM_BUNDLE: &[u8] = b"
            -----BEGIN CERTIFICATE-----
            MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5
            MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
            Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
            A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
            Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl
            ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j
            QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr
            ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr
            BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM
            YyRIHN8wfdVoOw==
            -----END CERTIFICATE-----

            -----BEGIN CERTIFICATE-----
            MIIB8jCCAXigAwIBAgITBmyf18G7EEwpQ+Vxe3ssyBrBDjAKBggqhkjOPQQDAzA5
            MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
            Um9vdCBDQSA0MB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
            A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
            Q0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABNKrijdPo1MN/sGKe0uoe0ZLY7Bi
            9i0b2whxIdIA6GO9mif78DluXeo9pcmBqqNbIJhFXRbb/egQbeOc4OO9X4Ri83Bk
            M6DLJC9wuoihKqB1+IGuYgbEgds5bimwHvouXKNCMEAwDwYDVR0TAQH/BAUwAwEB
            /zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFNPsxzplbszh2naaVvuc84ZtV+WB
            MAoGCCqGSM49BAMDA2gAMGUCMDqLIfG9fhGt0O9Yli/W651+kI0rz2ZVwyzjKKlw
            CkcO8DdZEv8tmZQoTipPNU0zWgIxAOp1AE47xDqUEpHJWEadIRNyp4iciuRMStuW
            1KyLa2tJElMzrdfkviT8tQp21KW8EA==
            -----END CERTIFICATE-----
        ";

        assert!(Certificate::from_pem_bundle(PEM_BUNDLE).is_ok())
    }

    #[cfg(feature = "__rustls")]
    #[test]
    fn crl_from_pem() {
        let pem = b"-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n";

        CertificateRevocationList::from_pem(pem).unwrap();
    }

    #[cfg(feature = "__rustls")]
    #[test]
    fn invalid_crl_from_pem() {
        CertificateRevocationList::from_pem(b"Invalid").unwrap_err();
    }

    #[cfg(feature = "__rustls")]
    #[test]
    fn crl_from_pem_bundle() {
        let pem_bundle = std::fs::read("tests/support/crl.pem").unwrap();

        let result = CertificateRevocationList::from_pem_bundle(&pem_bundle);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
    }
}
