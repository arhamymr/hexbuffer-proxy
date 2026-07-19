use crate::ca::CertificationAuthority;
use crate::handler::{HttpHandler, HttpContext, RequestOrResponse, WebSocketHandler};
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
    ws_handler: Option<Arc<dyn WebSocketHandler>>,
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

    // ── Handler decides: intercept or tunnel? ─────────────────────
    if !handler.should_intercept_tls(&target_host).await {
        let mut server = TcpStream::connect(target).await?;

        let (mut cr, mut cw) = client.split();
        let (mut sr, mut sw) = server.split();

        tokio::select! {
            r = tokio::io::copy(&mut cr, &mut sw) => { let _ = r; }
            r = tokio::io::copy(&mut sr, &mut cw) => { let _ = r; }
        }

        return Ok(());
    }

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
    let is_ws = crate::ws_proxy::is_websocket_upgrade(&request);

    match handler.handle_request(&mut ctx, request).await? {
        RequestOrResponse::Response(res) => {
            // Short-circuit
            let res_bytes = proxy::serialize_response(&res);
            tls_client.write_all(&res_bytes).await?;
            tls_client.shutdown().await?;
            return Ok(());
        }
        RequestOrResponse::Request(mut req) => {
            if is_ws {
                // ── WebSocket: raw TLS upstream relay ──────────
                let bytes = proxy::serialize_request(&req);

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

                server_stream.write_all(&bytes).await?;

                let full_response = proxy::read_full_response(&mut server_stream, buf_size).await?;
                let response = proxy::parse_raw_response(&full_response)?;
                let modified_response = handler.handle_response(&mut ctx, response).await?;
                let final_bytes = proxy::serialize_response(&modified_response);

                tls_client.write_all(&final_bytes).await?;
                if crate::ws_proxy::is_websocket_response(&modified_response) {
                    if let Some(ws) = ws_handler {
                        crate::ws_proxy::relay_framed(
                            tls_client, server_stream, ws, &mut ctx,
                        ).await?;
                    } else {
                        crate::ws_proxy::relay_websocket(
                            &mut tls_client, &mut server_stream,
                        ).await?;
                    }
                } else {
                    tls_client.shutdown().await?;
                }
            } else {
                // ── Normal HTTPS: Hyper client ────────────────
                // (connection pooling, HTTP/2, transparent decompression)

                // Hyper requires absolute URI; inner request after MITM
                // decryption has a relative path (e.g. /feed/).
                if req.uri().scheme().is_none() {
                    let uri: http::Uri = format!("https://{}{}", target_host, req.uri())
                        .parse()
                        .map_err(|e| anyhow::anyhow!("invalid absolute URI: {e}"))?;
                    *req.uri_mut() = uri;
                }

                let response = crate::upstream::send_request(req).await?;
                let modified_response = handler.handle_response(&mut ctx, response).await?;
                let final_bytes = proxy::serialize_response(&modified_response);

                tls_client.write_all(&final_bytes).await?;
                tls_client.shutdown().await?;
            }
        }
    }

    Ok(())
}

