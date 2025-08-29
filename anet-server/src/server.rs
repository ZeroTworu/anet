use std::{fs::File, io::BufReader, net::SocketAddr, sync::Arc};

use anyhow::Context;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use crate::handler::handle_client;

pub async fn run_server(cert: &str, key: &str, bind: &str) -> anyhow::Result<()> {
    let tls_cfg = load_tls_config(cert, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    let listener = TcpListener::bind(bind).await?;
    println!("Listening on {}", bind);

    loop {
        let (socket, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(tls_stream) => {
                    println!("Accepted connection from {}", peer);
                    handle_client(tls_stream, peer).await;
                }
                Err(e) => eprintln!("TLS accept failed from {}: {:?}", peer, e),
            }
        });
    }
}

fn load_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<ServerConfig> {

    let cert_file = File::open(cert_path)
        .context(format!("Failed to open certificate file: {}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer>, _>>()
        .context("Failed to parse certificate")?;

    let key_file = File::open(key_path)
        .context(format!("Failed to open key file: {}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to read private key")?
        .context("No private key found")?;

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create server config")?;

    Ok(cfg)
}
