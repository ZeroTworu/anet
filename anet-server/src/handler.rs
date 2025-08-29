use std::time::Instant;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{timeout, Duration};
use tokio_rustls::server::TlsStream;
use tokio::net::TcpStream;
use serde::{Deserialize, Serialize};

const AUTH_KEY_HARDCODED: &str = "supersecretkey";
const ASSIGNED_IP_STR: &str = "10.8.0.2";
const PING_TIMEOUT: Duration = Duration::from_secs(300); // 5 минут

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub async fn handle_client(stream: TlsStream<TcpStream>, peer: SocketAddr) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    match reader.read_line(&mut line).await {
        Ok(0) => {
            println!("[{}] Connection closed by client", peer);
            return;
        }
        Ok(_) => {
            match serde_json::from_str::<Message>(&line) {
                Ok(Message::AuthRequest(auth_request)) => {
                    if auth_request.key == AUTH_KEY_HARDCODED {
                        let response = Message::AuthResponse(AssignedIp {
                            ip: ASSIGNED_IP_STR.to_string(),
                        });

                        let response_data = serde_json::to_string(&response)
                            .expect("Failed to serialize response") + "\n";

                        if let Err(e) = writer.write_all(response_data.as_bytes()).await {
                            eprintln!("Write failed to {}: {:?}", peer, e);
                            return;
                        }

                       handle_ping_pong(reader, writer, peer).await;
                    } else {
                        eprintln!("[{}] auth failed: wrong key", peer);
                    }
                }
                Ok(_) => {
                    eprintln!("[{}] First message should be AuthRequest", peer);
                }
                Err(e) => {
                    eprintln!("[{}] failed to parse auth request: {:?}", peer, e);
                }
            }
        }
        Err(e) => {
            eprintln!("Read failed from {}: {:?}", peer, e);
        }
    }
}

async fn handle_ping_pong(
    mut reader: BufReader<tokio::io::ReadHalf<TlsStream<TcpStream>>>,
    mut writer: tokio::io::WriteHalf<TlsStream<TcpStream>>,
    peer: SocketAddr,
) {
    let mut line = String::new();
    let mut last_activity = Instant::now();

    loop {
        if last_activity.elapsed() > PING_TIMEOUT {
            eprintln!("[{}] Connection timeout - no ping received", peer);
            break;
        }

        let read_future = reader.read_line(&mut line);
        match timeout(Duration::from_secs(1), read_future).await {
            Ok(Ok(0)) => {
                println!("[{}] Connection closed by client", peer);
                break;
            }
            Ok(Ok(_)) => {
                last_activity = Instant::now();

                match serde_json::from_str::<Message>(&line) {
                    Ok(Message::Ping) => {
                        println!("[{}] Ping", peer);
                        // Отправляем pong
                        let pong = serde_json::to_string(&Message::Pong)
                            .expect("Failed to serialize pong") + "\n";

                        if let Err(e) = writer.write_all(pong.as_bytes()).await {
                            eprintln!("Write failed to {}: {:?}", peer, e);
                            break;
                        }
                        println!("[{}] Sent pong response", peer);
                    }
                    Ok(_) => {
                        eprintln!("[{}] Received unexpected message", peer);
                    }
                    Err(e) => {
                        eprintln!("[{}] Failed to parse message: {:?}", peer, e);
                    }
                }
                line.clear();
            }
            Ok(Err(e)) => {
                eprintln!("[{}] Read error: {:?}", peer, e);
                break;
            }
            Err(_) => {
                  continue;
            }
        }
    }

    let _ = writer.shutdown().await;
    println!("[{}] Connection closed", peer);
}