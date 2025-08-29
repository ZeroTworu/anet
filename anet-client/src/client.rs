use std::{sync::Arc, time::Duration};

use anyhow::Result;
use rustls::{ClientConfig, RootCertStore};
use rustls::pki_types::{CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;

const AUTH_KEY: &str = "supersecretkey";
const MAX_RETRIES: u32 = 5;
const READ_TIMEOUT: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AssignedIp {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    AuthRequest(AuthRequest),
    AuthResponse(AssignedIp),
    Ping,
    Pong,
}

pub async fn run_client(server_addr: &str, ca_cert_path: &str) -> Result<()> {
    //env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();


    let tls_config = load_tls_config(ca_cert_path)?;
    let connector = TlsConnector::from(Arc::new(tls_config));


    let stream = connect_with_retry(server_addr, MAX_RETRIES).await?;
    println!("Connected to server: {}", server_addr);


    let server_name = ServerName::try_from("alco").expect("Invalid server name");

    let tls_stream = connector.connect(server_name, stream).await?;
    println!("TLS connection established");

    let (reader, mut writer) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(reader);


    let auth_request = Message::AuthRequest(AuthRequest {
        key: AUTH_KEY.to_string(),
    });
    let request_data = serde_json::to_string(&auth_request)? + "\n";
    writer.write_all(request_data.as_bytes()).await?;
    println!("Authentication request sent");

    // Чтение ответа на аутентификацию
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    match serde_json::from_str::<Message>(&line) {
        Ok(Message::AuthResponse(assigned_ip)) => {
            println!("Success! Assigned IP: {}", assigned_ip.ip);

            let mut interval = tokio::time::interval(Duration::from_secs(30)); // Ping каждые 30 секундов

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let ping = serde_json::to_string(&Message::Ping)? + "\n";
                        if let Err(e) = writer.write_all(ping.as_bytes()).await {
                            eprintln!("Failed to send ping: {}", e);
                            break;
                        }
                        println!("Ping sent");

                         let mut pong_line = String::new();
                        match timeout(Duration::from_secs(5), reader.read_line(&mut pong_line)).await {
                            Ok(Ok(_)) => {
                                match serde_json::from_str::<Message>(&pong_line) {
                                    Ok(Message::Pong) => {
                                        println!("Pong received");
                                    }
                                    Ok(_) => {
                                        eprintln!("Unexpected message received: {}", pong_line);
                                        break;
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to parse pong: {}", e);
                                        break;
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                eprintln!("Read error: {}", e);
                                break;
                            }
                            Err(_) => {
                                eprintln!("Pong timeout");
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(_) => {
            eprintln!("Unexpected response type");
        }
        Err(e) => {
            eprintln!("Failed to parse response: {}", e);
        }
    }

    Ok(())
}

fn load_tls_config(ca_cert_path: &str) -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();

    let cert_file = std::fs::File::open(ca_cert_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file); // Используем std::io::BufReader вместо tokio::io::BufReader

    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer>, _>>()?;

    for cert in certs {
        let _ = root_store.add(cert);
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

async fn connect_with_retry(server_addr: &str, max_retries: u32) -> Result<TcpStream> {
    let mut retries = 0;

    loop {
        match TcpStream::connect(server_addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                retries += 1;
                if retries >= max_retries {
                    return Err(e.into());
                }

                eprintln!("Connection failed (attempt {}): {}. Retrying...", retries, e);
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}