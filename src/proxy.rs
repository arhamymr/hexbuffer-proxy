use crate::ca::CertificationAuthority;
use crate::parser::parse_connect_request;

// std
use std::sync::Arc;

// tokio
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer}}
};


pub async fn handle_client(mut client_stream: TcpStream, ca: Arc<CertificationAuthority>) -> anyhow::Result<()> {

    // 1. Read the initial Request header 
    let mut buffer = vec![0;4096];
    let n = client_stream.read(&mut buffer).await?;
    buffer.truncate(n);
    let request_str = String::from_utf8(buffer)?;


    // 2. Lifecycle check: identify if it is an HTTPS tunnel setup
    if request_str.starts_with("CONNECT") {
        // Extract host (e.g. example.com:443)
        let Some(target_address) = parse_connect_request(&request_str) else {
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
        let modified_request = force_connection_close(inner_request);

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


fn force_connection_close(request: String) -> String {
    let r = request
        .replace("Connection: keep-alive", "Connection: close")
        .replace("Connection: Keep-Alive", "Connection: close");
    
    if r.contains("Connection: close") {
        r
    } else {
        r.replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1)
    }
}