mod ca;
mod parser;
mod proxy;

use ca::CertificationAuthority;
use proxy::handle_client;

//std
use std::sync::Arc;

// tokio
use tokio::net::{TcpListener};
use tokio_rustls::rustls::{crypto::aws_lc_rs::default_provider};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = default_provider().install_default();

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    let ca = Arc::new(CertificationAuthority::new());

    println!("Listening on 127.0.0.1:8080");

    loop {
        let (stream, _) = listener.accept().await?;
        let ca_clone = Arc::clone(&ca);

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, ca_clone).await {
                eprintln!("Error handling client: {}", e);
            }
        });
    }
}