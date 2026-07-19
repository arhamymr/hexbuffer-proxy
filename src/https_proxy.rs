use crate::ca::CertificationAuthority;
use crate::handler::{HttpHandler, HttpContext, RequestOrResponse, Body};
use crate::proxy;

// std
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

// tokio
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer}}
};

/// Handle an HTTPS CONNECT tunnel: forge cert, TLS handshake with client,
/// decrypt inner request, forward to upstream over TLS, return response.
pub(crate) async fn handle_https(
    client_stream: TcpStream,
    ca: Arc<CertificationAuthority>,
    handler: Arc<dyn HttpHandler>,
    target: &str,       // e.g. "example.com:443"
    client_addr: SocketAddr,
    buf_size: usize,
) -> anyhow::Result<()> {
    let target_host = target
        .split(':')
        .next()
        .unwrap_or(target)
        .to_string();

    // Tell the browser the tunnel is established
    let mut client = client_stream;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    // Forge certificate for this domain on the fly
    let (cert_der, key_der) = ca.forge_certificate(&target_host);

    // Spin up a local TLS server config just for this stream
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(key_der.into()),
        )?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let mut tls_client = acceptor.accept(client).await?;

    // Read the true inner decrypted payload
    let mut inner_buf = vec![0; buf_size];
    let bytes_read = tls_client.read(&mut inner_buf).await?;
    inner_buf.truncate(bytes_read);

    // ── handler: request ────────────────────────────────────────────
    let req_id = proxy::REQUEST_ID.fetch_add(1, Ordering::SeqCst);
    let mut ctx = HttpContext {
        id: req_id,
        host: target_host.clone(),
        client_addr,
        is_https: true,
    };

    let request = proxy::parse_raw_request(&inner_buf)?;

    let modified_bytes = match handler.handle_request(&mut ctx, request).await? {
        RequestOrResponse::Request(req) => proxy::serialize_request(&req),
        RequestOrResponse::Response(res) => {
            let res_bytes = proxy::serialize_response(&res);
            tls_client.write_all(&res_bytes).await?;
            tls_client.shutdown().await?;
            return Ok(());
        }
    };

    // Connect to target server via TLS
    let server_stream = TcpStream::connect(target).await?;

    let root_store = tokio_rustls::rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));
    let domain = target_host
        .try_into()
        .unwrap_or_else(|_| "localhost".try_into().unwrap());
    let mut server_stream = connector.connect(domain, server_stream).await?;

    // Force Connection: close so read doesn't hang on keep-alive
    let forward_bytes = proxy::force_connection_close_bytes(&modified_bytes);
    server_stream.write_all(&forward_bytes).await?;

    // Read response from upstream
    let mut response_buf = vec![0; buf_size];
    let resp_bytes = server_stream.read(&mut response_buf).await?;
    response_buf.truncate(resp_bytes);

    // ── handler: response ───────────────────────────────────────────
    let response = proxy::parse_raw_response(&response_buf)?;
    let modified_response = handler.handle_response(&mut ctx, response).await?;
    let final_bytes = proxy::serialize_response(&modified_response);

    tls_client.write_all(&final_bytes).await?;
    tls_client.shutdown().await?;

    Ok(())
}
