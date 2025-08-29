use anet_common::protocol::{AssignedIp, Message};
use log::{error, info};
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
const AUTH_KEY_HARDCODED: &str = "supersecretkey";
const ASSIGNED_IP_STR: &str = "10.8.0.3";

pub async fn handle_client(stream: TlsStream<TcpStream>, peer: SocketAddr) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    match reader.read_line(&mut line).await {
        Ok(0) => {
            info!("[{}] Connection closed by client", peer);
            return;
        }
        Ok(_) => match serde_json::from_str::<Message>(&line) {
            Ok(Message::AuthRequest(auth_request)) => {
                if auth_request.key == AUTH_KEY_HARDCODED {
                    let response = Message::AuthResponse(AssignedIp {
                        ip: ASSIGNED_IP_STR.to_string(),
                    });

                    let response_data = serde_json::to_string(&response)
                        .expect("Failed to serialize response")
                        + "\n";

                    if let Err(e) = writer.write_all(response_data.as_bytes()).await {
                        error!("Write failed to {}: {:?}", peer, e);
                        return;
                    }
                } else {
                    error!("[{}] auth failed: wrong key", peer);
                }
            }
            Ok(_) => {
                error!("[{}] First message should be AuthRequest", peer);
            }
            Err(e) => {
                error!("[{}] failed to parse auth request: {:?}", peer, e);
            }
        },
        Err(e) => {
            error!("Read failed from {}: {:?}", peer, e);
        }
    }
}
