
mod ca;

use std::sync:Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{ServerConfig, crypto::ring::default_provider};


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = default_provider().install_default();

    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    println!("Listening on 127.0.0.1:8080");

    loop {
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Error handling client: {}", e);
            }
        })
    }

}
