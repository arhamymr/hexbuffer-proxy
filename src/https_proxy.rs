use crate::ca::CertificationAuthority;
use crate::handler::{HttpHandler, HttpContext, RequestOrResponse, Body, WebSocketHandler};
use crate::proxy;

// std
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

// tokio
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer}}
};

// hyper — HTTP/1.1 server on decrypted TLS stream (Hudsucker pattern)
use bytes::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use http_body_util::Full;
use hyper_util::rt::{TokioExecutor, TokioIo};

/// Handle an HTTPS CONNECT tunnel.
///
/// **Flow:**
/// 1. Respond `200 Connection Established` to the browser.
/// 2. Respect [`HttpHandler::should_intercept_tls`] — if `false`, relay
///    raw TCP (bypass for cert-pinned domains like `gemini.google.com`).
/// 3. Forge a per-domain TLS certificate.
/// 4. Perform TLS handshake with the client using the forged cert.
/// 5. Wrap the decrypted stream with Hyper's HTTP/1.1 server.
/// 6. Hyper serves every inner HTTP request (keep-alive, pipelining),
///    calling [`handle_https_request`] for each one.
pub(crate) async fn handle_https(
    client_stream: TcpStream,
    ca: Arc<CertificationAuthority>,
    handler: Arc<dyn HttpHandler>,
    ws_handler: Option<Arc<dyn WebSocketHandler>>,
    target: &str,
    client_addr: SocketAddr,
    _buf_size: usize,
) -> anyhow::Result<()> {
    let target_host = target
        .split(':')
        .next()
        .unwrap_or(target)
        .to_string();

    let mut client = client_stream;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    // ── Passthrough: raw TCP tunnel ──────────────────────────────
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

    // ── Forge certificate ────────────────────────────────────────
    let (cert_der, key_der) = ca.forge_certificate(&target_host);

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(key_der.into()),
        )?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let tls_client = acceptor.accept(client).await?;

    // ── Hyper HTTP/1.1 server on decrypted TLS stream ────────────
    let io = TokioIo::new(tls_client);
    let mut http = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    http.http1()
        .keep_alive(true)
        .serve_connection(io, service_fn({
            let handler = handler.clone();
            let host = target_host.clone();
            let ws = ws_handler.clone();
            let tgt = target.to_string();
            move |req: Request<hyper::body::Incoming>| {
                let handler = handler.clone();
                let host = host.clone();
                let ws = ws.clone();
                let tgt = tgt.clone();
                async move {
                    handle_https_request(req, handler, ws, &host, &tgt, client_addr).await
                }
            }
        }))
        .await
        .map_err(|e| anyhow::anyhow!("Hyper server: {e}"))?;

    Ok(())
}

/// Process a single HTTP request from the decrypted TLS stream.
/// Called by Hyper's server for each request (keep-alive supported).
async fn handle_https_request(
    req: Request<hyper::body::Incoming>,
    handler: Arc<dyn HttpHandler>,
    ws_handler: Option<Arc<dyn WebSocketHandler>>,
    target_host: &str,
    target: &str,
    client_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let req_id = proxy::REQUEST_ID.fetch_add(1, Ordering::SeqCst);
    let mut ctx = HttpContext {
        id: req_id,
        host: target_host.to_string(),
        client_addr,
        is_https: true,
    };

    // Convert Incoming body → our Body type
    let req = req.map(Body::from);

    // ── Handler: request ────────────────────────────────────────
    match handler.handle_request(&mut ctx, req).await {
        Ok(RequestOrResponse::Response(res)) => {
            let (parts, body) = res.into_parts();
            let bytes = body.into_bytes().await?;
            Ok(Response::from_parts(parts, Full::new(bytes)))
        }

        Ok(RequestOrResponse::Request(mut req)) => {
            // WebSocket upgrade — relay
            if crate::ws_proxy::is_websocket_upgrade(&req) {
                return handle_https_websocket(
                    req, handler, ws_handler, &mut ctx, target_host, target,
                ).await;
            }

            // Rewrite URI to absolute form for upstream
            if req.uri().scheme().is_none() {
                let uri: http::Uri = format!("https://{}{}", target_host, req.uri())
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid absolute URI: {e}"))?;
                *req.uri_mut() = uri;
            }

            // ── Upstream ──────────────────────────────────────
            let response = crate::upstream::send_request(req).await
                .map_err(|e| anyhow::anyhow!("[#{}] upstream: {e}", req_id))?;

            // ── Handler: response ─────────────────────────────
            let modified = handler.handle_response(&mut ctx, response).await
                .map_err(|e| anyhow::anyhow!("[#{}] response handler: {e}", req_id))?;

            let (parts, body) = modified.into_parts();
            let bytes = body.into_bytes().await?;
            Ok(Response::from_parts(parts, Full::new(bytes)))
        }

        Err(e) => {
            eprintln!("[#{}] request handler error: {}", req_id, e);
            Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from("Bad Gateway")))
                .unwrap())
        }
    }
}

/// Handle a WebSocket upgrade inside the TLS tunnel.
async fn handle_https_websocket(
    req: Request<Body>,
    handler: Arc<dyn HttpHandler>,
    _ws_handler: Option<Arc<dyn WebSocketHandler>>,
    ctx: &mut HttpContext,
    target_host: &str,
    target: &str,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let bytes = proxy::serialize_request(&req);

    let server_stream = TcpStream::connect(target).await?;
    let root_store = tokio_rustls::rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let host = target_host.to_string();
    let domain: tokio_rustls::rustls::pki_types::ServerName = host
        .try_into()
        .unwrap_or_else(|_| "localhost".try_into().unwrap());
    let mut server_stream = connector.connect(domain, server_stream).await?;

    server_stream.write_all(&bytes).await?;

    let full_response = proxy::read_full_response(&mut server_stream, 16384).await?;
    let response = proxy::parse_raw_response(&full_response)?;
    let modified = handler.handle_response(ctx, response).await
        .map_err(|e| anyhow::anyhow!("[ws] response handler: {e}"))?;

    let (parts, body) = modified.into_parts();
    let bytes = body.into_bytes().await?;
    Ok(Response::from_parts(parts, Full::new(bytes)))
}
