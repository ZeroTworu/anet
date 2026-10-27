use super::transport::{Driver, Sender};
use crate::async_impl::h3_client::dns::resolve;
use crate::dns::DynResolver;
use crate::error::BoxError;
use http::Uri;
use hyper_util::client::legacy::connect::dns::Name;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

type H3Connection = (Driver, Sender);

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

/// H3 Client Config
#[derive(Clone, Default)]
pub(crate) struct H3ClientConfig {
    /// Set the maximum HTTP/3 header size this client is willing to accept.
    ///
    /// See [header size constraints] section of the specification for details.
    ///
    /// [header size constraints]: https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints
    ///
    /// See the corresponding settings in [`quiche::h3::Config`].
    ///
    /// [`quiche::h3::Config`]: https://docs.rs/quiche/0.28.0/quiche/h3/struct.Config.html
    pub(crate) max_field_section_size: Option<u64>,

    /// Enable whether to send HTTP/3 protocol grease on the connections.
    ///
    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    ///
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    ///
    /// See the corresponding settings in [`quiche::h3::Config`].
    ///
    /// [`quiche::h3::Config`]: https://docs.rs/quiche/0.28.0/quiche/h3/struct.Config.html
    pub(crate) send_grease: Option<bool>,
}

#[derive(Clone)]
pub(crate) struct H3Connector {
    resolver: DynResolver,
    tls: crate::boring_tls::Config,
    transport_config: TransportConfig,
    client_config: H3ClientConfig,
    local_addr: Option<IpAddr>,
}

impl H3Connector {
    pub fn new(
        resolver: DynResolver,
        tls: crate::boring_tls::Config,
        local_addr: Option<IpAddr>,
        transport_config: TransportConfig,
        client_config: H3ClientConfig,
    ) -> Result<H3Connector, BoxError> {
        // Validate TLS and transport options at build time.
        make_config(&tls, &transport_config, &client_config)?;
        Ok(Self {
            resolver,
            tls,
            transport_config,
            client_config,
            local_addr,
        })
    }

    pub async fn connect(&mut self, dest: Uri) -> Result<H3Connection, BoxError> {
        let host = dest
            .host()
            .ok_or("destination must have a host")?
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port = dest.port_u16().unwrap_or(443);

        let addrs = if let Ok(addr) = IpAddr::from_str(host) {
            // If the host is already an IP address, skip resolving.
            vec![SocketAddr::new(addr, port)]
        } else {
            let addrs = resolve(&mut self.resolver, Name::from_str(host)?).await?;
            let addrs = addrs.map(|mut addr| {
                addr.set_port(port);
                addr
            });
            addrs.collect()
        };

        self.remote_connect(addrs, host).await
    }

    async fn remote_connect(
        &mut self,
        addrs: Vec<SocketAddr>,
        server_name: &str,
    ) -> Result<H3Connection, BoxError> {
        if addrs.is_empty() {
            return Err("no addresses to connect to".into());
        }

        let (mut ipv6_addrs, mut ipv4_addrs): (Vec<SocketAddr>, Vec<SocketAddr>) =
            addrs.into_iter().partition(|addr| addr.is_ipv6());

        if let Some(local_ip) = self.local_addr {
            if local_ip.is_ipv6() {
                ipv4_addrs.clear();
            } else {
                ipv6_addrs.clear();
            }
        }

        if ipv6_addrs.is_empty() {
            return Self::try_addresses_static(
                &(
                    self.tls.clone(),
                    self.transport_config.clone(),
                    self.local_addr,
                ),
                &ipv4_addrs,
                server_name,
                &self.client_config,
            )
            .await;
        }
        if ipv4_addrs.is_empty() {
            return Self::try_addresses_static(
                &(
                    self.tls.clone(),
                    self.transport_config.clone(),
                    self.local_addr,
                ),
                &ipv6_addrs,
                server_name,
                &self.client_config,
            )
            .await;
        }

        let endpoint = (
            self.tls.clone(),
            self.transport_config.clone(),
            self.local_addr,
        );
        let client_config = self.client_config.clone();

        if self.local_addr.is_some() {
            return match Self::try_addresses_static(
                &endpoint,
                &ipv6_addrs,
                server_name,
                &client_config,
            )
            .await
            {
                Ok(conn) => Ok(conn),
                Err(_) => {
                    Self::try_addresses_static(&endpoint, &ipv4_addrs, server_name, &client_config)
                        .await
                }
            };
        }

        Self::try_addresses_happy_eyeballs(
            &endpoint,
            &ipv6_addrs,
            &ipv4_addrs,
            server_name,
            &client_config,
        )
        .await
    }

    async fn try_addresses_static(
        endpoint: &(crate::boring_tls::Config, TransportConfig, Option<IpAddr>),
        addrs: &[SocketAddr],
        server_name: &str,
        client_config: &H3ClientConfig,
    ) -> Result<H3Connection, BoxError> {
        let mut last_err: Option<BoxError> = None;

        for addr in addrs {
            let local = endpoint.2.unwrap_or_else(|| {
                if addr.is_ipv6() {
                    "::".parse().unwrap()
                } else {
                    "0.0.0.0".parse().unwrap()
                }
            });
            let attempt = super::transport::connect(
                *addr,
                SocketAddr::new(local, 0),
                server_name,
                make_config(&endpoint.0, &endpoint.1, client_config)?,
                client_config.clone(),
                endpoint.1.send_window.unwrap_or(1024 * 1024),
                endpoint.0.clone(),
            )
            .await;
            match attempt {
                Ok(connection) => return Ok(connection),
                Err(error) => last_err = Some(error),
            }
        }

        Err(last_err.unwrap_or_else(|| "no addresses available".into()))
    }

    async fn try_addresses_happy_eyeballs(
        endpoint: &(crate::boring_tls::Config, TransportConfig, Option<IpAddr>),
        ipv6_addrs: &[SocketAddr],
        ipv4_addrs: &[SocketAddr],
        server_name: &str,
        client_config: &H3ClientConfig,
    ) -> Result<H3Connection, BoxError> {
        let ipv6_connect =
            Self::try_addresses_static(endpoint, ipv6_addrs, server_name, client_config);
        tokio::pin!(ipv6_connect);

        let delay = tokio::time::sleep(HAPPY_EYEBALLS_DELAY);
        tokio::pin!(delay);

        tokio::select! {
            result = &mut ipv6_connect => {
                return match result {
                    Ok(conn) => Ok(conn),
                    Err(_) => {
                        Self::try_addresses_static(endpoint, ipv4_addrs, server_name, client_config).await
                    }
                };
            }
            _ = &mut delay => {}
        }

        let ipv4_connect =
            Self::try_addresses_static(endpoint, ipv4_addrs, server_name, client_config);
        tokio::pin!(ipv4_connect);

        let wait_for_ipv6 = tokio::select! {
            result = &mut ipv6_connect => {
                match result {
                    Ok(conn) => return Ok(conn),
                    Err(_) => false,
                }
            }
            result = &mut ipv4_connect => {
                match result {
                    Ok(conn) => return Ok(conn),
                    Err(_) => true,
                }
            }
        };

        if wait_for_ipv6 {
            ipv6_connect.await
        } else {
            ipv4_connect.await
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct TransportConfig {
    idle_timeout: Option<Duration>,
    stream_window: Option<u64>,
    receive_window: Option<u64>,
    send_window: Option<u64>,
    pub bbr: bool,
}
impl TransportConfig {
    pub fn max_idle_timeout(&mut self, value: Option<Duration>) {
        self.idle_timeout = value;
    }
    pub fn stream_receive_window(&mut self, value: u64) {
        self.stream_window = Some(value);
    }
    pub fn receive_window(&mut self, value: u64) {
        self.receive_window = Some(value);
    }
    pub fn send_window(&mut self, value: u64) {
        self.send_window = Some(value);
    }
}
fn make_config(
    tls: &crate::boring_tls::Config,
    transport: &TransportConfig,
    h3: &H3ClientConfig,
) -> Result<quiche::Config, BoxError> {
    use foreign_types::ForeignType;
    let settings = tls
        .settings
        .as_ref()
        .ok_or("preconfigured TCP connector cannot configure QUIC")?;
    if settings
        .max
        .is_some_and(|max| max < crate::tls::Version::TLS_1_3)
    {
        return Err("HTTP/3 requires TLS 1.3".into());
    }
    let builder = settings.builder()?;
    // SAFETY: SslConnectorBuilder and SslContextBuilder own the same SSL_CTX;
    // transfer ownership without changing its reference count.
    let builder = unsafe {
        boring::ssl::SslContextBuilder::from_ptr(builder.build().into_context().into_ptr())
    };
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)?;
    config.set_application_protos(&[b"h3"])?;
    config.grease(h3.send_grease.unwrap_or(true));
    config.set_max_idle_timeout(
        transport
            .idle_timeout
            .unwrap_or(Duration::from_secs(30))
            .as_millis()
            .try_into()?,
    );
    config.set_initial_max_data(transport.receive_window.unwrap_or(10 * 1024 * 1024));
    let window = transport.stream_window.unwrap_or(1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(window);
    config.set_initial_max_stream_data_bidi_remote(window);
    config.set_initial_max_stream_data_uni(window);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_disable_active_migration(true);
    if transport.bbr {
        config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Bbr2Gcongestion);
    }
    if tls.enable_early_data {
        config.enable_early_data();
    }
    Ok(config)
}
