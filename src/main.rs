
mod ca;

use std::sync::Arc;
use ca::CertificationAuthority;

// tokio
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{ServerConfig, crypto::aws_lc_rs::default_provider};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};


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


async fn handle_client(mut client_stream: TcpStream, ca: Arc<CertificationAuthority>) -> anyhow::Result<()> {

    // 1. Read the initial Request header 
    let mut buffer = vec![0;4096];
    let n = client_stream.read(&mut buffer).await?;
    buffer.truncate(n);
    let request_str = String::from_utf8(buffer)?;


    // 2. Lifecycle check: identify if it is an HTTPS tunnel setup
    if request_str.starts_with("CONNECT") {

        // Extract host (e.g. example.com:443)
        let Some(target_address) = parse_connect_target(&request_str) else {
            anyhow::bail!("failed to parse CONNECT target");
        };
        // example.com
        let target_address = target_address.to_string();
        let target_hosts = target_address.split(':').next().unwrap_or(&target_address).to_string();
        // tell the browser 
        client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        // 3. Forge Certificate for this domain on the fly 
        let (cert_der, key_der) = ca.forge_certificate(&target_hosts);

        
        // 4. Client handshake: Spin up a local TLS server config just for this stream
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::Pkcs8(key_der.into())
            )?;

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mut tls_client_stream = acceptor.accept(client_stream).await?;

        // 5. Read the true inner decrypted payload
        let mut inner_buf = [0; 16384]; // 16KB

        let bytes_read = tls_client_stream.read(&mut inner_buf).await?;
        let inner_request = String::from_utf8_lossy(&inner_buf[..bytes_read]).into_owned();


        // Hook intercept : add your own logic here to modify the inner request
        println!("Inner Request: {}", inner_request);

        // Force Connection: close so read_to_end doesn't hang on HTTP/1.1 keep-alive
        let modified_request = inner_request
            .replace("Connection: keep-alive", "Connection: close")
            .replace("Connection: Keep-Alive", "Connection: close");
        
        let modified_request = if !modified_request.contains("Connection: close") {
            modified_request.replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1)
        } else {
            modified_request
        };

        // 6. Connect to target server via TLS 
        let server_stream = TcpStream::connect(target_address).await?;

        let root_store = tokio_rustls::rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        
        let tls_config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));
        let domain = target_hosts.try_into().unwrap_or_else(|_| "localhost".try_into().unwrap());
        let mut server_stream = connector.connect(domain, server_stream).await?;

        server_stream.write_all(modified_request.as_bytes()).await?;

        // 7. Stream response from server to client
        let bytes_copied = tokio::io::copy(&mut server_stream, &mut tls_client_stream).await?;
        println!("Response: {} bytes copied", bytes_copied);

    } else {
        // eprintln!("Non-HTTPS request received");
    }


    Ok(())
}

/// Extracts the target host:port from a CONNECT request line.
/// Returns `Some("example.com:443")` for `"CONNECT example.com:443 HTTP/1.1"`.
fn parse_connect_target(request: &str) -> Option<&str> {
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    parts.get(1).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_target() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_connect_target(req), Some("example.com:443"));
    }

    #[test]
    fn test_parse_connect_target_no_port() {
        let req = "CONNECT example.com HTTP/1.1\r\n\r\n";
        assert_eq!(parse_connect_target(req), Some("example.com"));
    }

    #[test]
    fn test_parse_connect_target_missing_field() {
        assert_eq!(parse_connect_target("CONNECT \r\n\r\n"), None);
    }

    #[test]
    fn test_parse_connect_target_empty() {
        assert_eq!(parse_connect_target(""), None);
    }
}
