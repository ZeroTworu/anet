use base64::prelude::*;
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "anet-keygen")]
#[command(about = "Generate cryptographic keys for ANet VPN")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate client key pair
    Client,
    /// Generate server signing key
    Server,
    /// Generate both client and server keys
    All,
}

fn generate_key_pair() -> (SigningKey, VerifyingKey, String) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let private_key_b64 = BASE64_STANDARD.encode(signing_key.to_bytes());
    let public_key_b64 = BASE64_STANDARD.encode(verifying_key.to_bytes());

    // Генерация fingerprint
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.to_bytes());
    let hash = hasher.finalize();
    let fingerprint = BASE64_STANDARD.encode(&hash[..16]);

    (signing_key, verifying_key, fingerprint)
}

fn print_client_keys(private_key: &str, public_key: &str, fingerprint: &str) {
    println!("=== ANet Client Keys ===");
    println!();
    println!("Private Key (add to client.toml):");
    println!("[keys]");
    println!("private_key = \"{}\"", private_key);
    println!();
    println!("Public Key (optional, for server verification):");
    println!("{}", public_key);
    println!();
    println!("Fingerprint (add to server.toml allowed_clients):");
    println!("{}", fingerprint);
    println!();
    println!("Example client.toml configuration:");
    println!("[keys]");
    println!("private_key = \"{}\"", private_key);
    println!();
    println!("[main]");
    println!("address = \"127.0.0.1:443\"");
    println!("tun_name = \"anet-client\"");
    println!(
        "# server_pub_key = \"{}\"  # Optional: for server verification",
        public_key
    );
}

fn print_server_key(private_key: &str, public_key: &str) {
    println!("=== ANet Server Signing Key ===");
    println!();
    println!("Private Signing Key (add to server.toml):");
    println!("[crypto]");
    println!("server_signing_key = \"{}\"", private_key);
    println!();
    println!("Public Key (for client verification, optional):");
    println!("{}", public_key);
    println!();
    println!("Example server.toml configuration:");
    println!("[crypto]");
    println!("quic_cert = \"QUIC_CERT_PEM\"");
    println!("quic_key = \"QUIC_KEY_PEM\"");
    println!("server_signing_key = \"{}\"", private_key);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Client => {
            let (signing_key, verifying_key, fingerprint) = generate_key_pair();
            let private_key_b64 = BASE64_STANDARD.encode(signing_key.to_bytes());
            let public_key_b64 = BASE64_STANDARD.encode(verifying_key.to_bytes());

            print_client_keys(&private_key_b64, &public_key_b64, &fingerprint);
        }
        Commands::Server => {
            let (signing_key, verifying_key, _) = generate_key_pair();
            let private_key_b64 = BASE64_STANDARD.encode(signing_key.to_bytes());
            let public_key_b64 = BASE64_STANDARD.encode(verifying_key.to_bytes());

            print_server_key(&private_key_b64, &public_key_b64);
        }
        Commands::All => {
            let (client_signing, client_verifying, client_fingerprint) = generate_key_pair();
            let (server_signing, server_verifying, _) = generate_key_pair();

            let client_private = BASE64_STANDARD.encode(client_signing.to_bytes());
            let client_public = BASE64_STANDARD.encode(client_verifying.to_bytes());
            let server_private = BASE64_STANDARD.encode(server_signing.to_bytes());
            let server_public = BASE64_STANDARD.encode(server_verifying.to_bytes());

            println!("=== ANet Complete Key Set ===");
            println!();

            print_client_keys(&client_private, &client_public, &client_fingerprint);
            print_server_key(&server_private, &server_public);

            println!("=== Summary ===");
            println!("Client Fingerprint: {}", client_fingerprint);
            println!("Server Public Key:  {}", server_public);
        }
    }

    println!();
    println!("Note: Keep private keys secure! Do not share them.");

    Ok(())
}
