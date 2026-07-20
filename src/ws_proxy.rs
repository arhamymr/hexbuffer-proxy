// ws_proxy.rs — WebSocket upgrade detection, upgrade handshake, and bidirectional relay
use crate::handler::{Body, Direction, HttpContext, HttpHandler, WebSocketHandler};
use crate::proxy;

use anyhow;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Request, Response};
use http_body_util::Full;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Check serialized HTTP request bytes for a WebSocket upgrade.
#[allow(dead_code)]
/// Check raw bytes for a WebSocket upgrade request.
/// Looks for `Upgrade: websocket` and `Connection: upgrade` headers.
pub(crate) fn is_websocket_upgrade_bytes(raw: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(raw).to_lowercase();
    lower.contains("upgrade:") && lower.contains("websocket")
}

/// Check a parsed request for a WebSocket upgrade.
/// Check a typed request for a WebSocket upgrade.
pub(crate) fn is_websocket_upgrade(req: &Request<Body>) -> bool {
    let is_upgrade = req.headers().get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("websocket"))
        .unwrap_or(false);
    let connection_upgrade = req.headers().get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false);
    is_upgrade && connection_upgrade
}

/// Check if an HTTP response is a successful WebSocket upgrade (101).
/// Check whether a response is a successful WebSocket upgrade (status 101).
pub(crate) fn is_websocket_response(res: &Response<Body>) -> bool {
    res.status() == 101
}

/// Check request headers for a WebSocket upgrade (body-type agnostic).
/// Used before body conversion to grab `hyper::upgrade::on(&mut req)`.
pub(crate) fn is_websocket_upgrade_headers(headers: &hyper::HeaderMap) -> bool {
    let is_upgrade = headers.get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("websocket"))
        .unwrap_or(false);
    let connection_upgrade = headers.get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false);
    is_upgrade && connection_upgrade
}

/// Bidirectional relay between client and server streams.
/// Used after a successful WebSocket upgrade (101 response) to pass
/// raw frames between the client and upstream without closing either side.
/// Bidirectional raw TCP relay for WebSocket connections.
/// Copies bytes between client and server bidirectionally.
pub(crate) async fn relay_websocket<C, S>(
    client: &mut C,
    server: &mut S,
) -> anyhow::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::io::copy_bidirectional(client, server).await?;
    let _ = client.shutdown().await;
    Ok(())
}

/// Framed WebSocket relay with handler interception.
/// Takes ownership of both streams after a 101 upgrade,
/// wraps them in `WebSocketStream`, and passes each frame
/// through the handler via `on_frame` / `on_close`.
#[allow(dead_code)]
/// Bidirectional WebSocket frame relay with handler interception.
///
/// Reads/writes individual WebSocket frames (not raw bytes) and passes
/// each frame through the [`WebSocketHandler`] for inspection/modification.
pub(crate) async fn relay_framed<C, S>(
    client: C,
    server: S,
    handler: Arc<dyn WebSocketHandler>,
    ctx: &mut HttpContext,
) -> anyhow::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio_tungstenite::tungstenite::protocol::Role;

    let mut client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        client,
        Role::Server,
        None,
    ).await;
    let mut server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        server,
        Role::Client,
        None,
    ).await;

    loop {
        tokio::select! {
            msg = client_ws.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        let is_close = msg.is_close();
                        if let Some(msg) = handler.on_frame(ctx, msg, Direction::ClientToServer).await {
                            let _ = server_ws.send(msg).await;
                        }
                        if is_close { break; }
                    }
                    _ => break,
                }
            }
            msg = server_ws.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        let is_close = msg.is_close();
                        if let Some(msg) = handler.on_frame(ctx, msg, Direction::ServerToClient).await {
                            let _ = client_ws.send(msg).await;
                        }
                        if is_close { break; }
                    }
                    _ => break,
                }
            }
        }
    }

    handler.on_close(ctx).await;
    let _ = client_ws.close(None).await;
    Ok(())
}

/// Handle a WebSocket upgrade inside the TLS tunnel using Hyper's upgrade mechanism.
///
/// Forwards the upgrade request to the upstream, gets the 101 response,
/// then uses Hyper's HTTP upgrade to take over the raw client stream for
/// bidirectional WebSocket frame relay.
pub(crate) async fn handle_https_websocket(
    req: Request<Body>,
    on_upgrade: OnUpgrade,
    handler: Arc<dyn HttpHandler>,
    ws_handler: Option<Arc<dyn WebSocketHandler>>,
    ctx: &mut HttpContext,
    target_host: &str,
    target: &str,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let bytes = proxy::serialize_request(&req);

    // 1. Connect to upstream over TLS
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

    // 2. Forward the upgrade request
    server_stream.write_all(&bytes).await?;

    // 3. Read the upstream response
    let full_response = proxy::read_full_response(&mut server_stream, 16384).await?;
    let response = proxy::parse_raw_response(&full_response)?;
    let modified = handler.handle_response(ctx, response).await
        .map_err(|e| anyhow::anyhow!("[ws] response handler: {e}"))?;

    // 4. If upstream didn't upgrade, return response as-is
    if modified.status() != 101 {
        let (parts, body) = modified.into_parts();
        let bytes = body.into_bytes().await?;
        return Ok(Response::from_parts(parts, Full::new(bytes)));
    }

    // 5. Build the 101 response for the client
    let mut response_builder = Response::builder().status(101);
    for (key, value) in modified.headers() {
        response_builder = response_builder.header(key, value);
    }
    let res = response_builder.body(Full::new(Bytes::new()))?;

    // 6. Spawn the WebSocket relay task.
    //    on_upgrade resolves when Hyper hands us the raw client stream.
    let ctx_id = ctx.id;
    let ctx_host = ctx.host.clone();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                if let Some(ws) = ws_handler {
                    let mut relay_ctx = HttpContext {
                        id: ctx_id,
                        host: ctx_host,
                        client_addr: "0.0.0.0:0".parse().unwrap(),
                        is_https: true,
                    };
                    let _ = relay_framed(
                        client, server_stream, ws, &mut relay_ctx,
                    ).await;
                } else {
                    let _ = relay_websocket(
                        &mut client, &mut server_stream,
                    ).await;
                }
            }
            Err(e) => {
                eprintln!("[ws] upgrade error: {e}");
            }
        }
    });

    Ok(res)
}


// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, Response};
    use crate::handler::Body;

    fn make_upgrade_request() -> Request<Body> {
        Request::builder()
            .uri("ws://example.com/chat")
            .header("Upgrade", "websocket")
            .header("Connection", "upgrade")
            .body(Body::Full(bytes::Bytes::new()))
            .unwrap()
    }

    #[test]
    fn test_is_websocket_upgrade_true() {
        let req = make_upgrade_request();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn test_is_websocket_upgrade_missing_connection() {
        let req = Request::builder()
            .uri("ws://example.com/chat")
            .header("Upgrade", "websocket")
            .body(Body::Full(bytes::Bytes::new()))
            .unwrap();
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn test_is_websocket_upgrade_case_insensitive() {
        let req = Request::builder()
            .uri("ws://example.com/chat")
            .header("upgrade", "WebSocket")
            .header("connection", "Upgrade")
            .body(Body::Full(bytes::Bytes::new()))
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn test_is_websocket_upgrade_not_websocket() {
        let req = Request::builder()
            .uri("https://example.com/")
            .header("Host", "example.com")
            .body(Body::Full(bytes::Bytes::new()))
            .unwrap();
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn test_is_websocket_upgrade_bytes_true() {
        let raw = b"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
        assert!(is_websocket_upgrade_bytes(raw));
    }

    #[test]
    fn test_is_websocket_upgrade_bytes_false() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_websocket_upgrade_bytes(raw));
    }

    #[test]
    fn test_is_websocket_response_101() {
        let res = Response::builder()
            .status(101)
            .body(Body::Full(bytes::Bytes::new()))
            .unwrap();
        assert!(is_websocket_response(&res));
    }

    #[test]
    fn test_is_websocket_response_not_101() {
        let res200 = Response::builder()
            .status(200)
            .body(Body::Full(bytes::Bytes::new()))
            .unwrap();
        assert!(!is_websocket_response(&res200));

        let res404 = Response::builder()
            .status(404)
            .body(Body::Full(bytes::Bytes::new()))
            .unwrap();
        assert!(!is_websocket_response(&res404));
    }

    // ── is_websocket_upgrade_headers (HeaderMap-based) ─────────

    fn make_upgrade_headers() -> hyper::HeaderMap {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("connection", "upgrade".parse().unwrap());
        headers
    }

    #[test]
    fn test_is_websocket_upgrade_headers_true() {
        let headers = make_upgrade_headers();
        assert!(is_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_headers_missing_connection() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());
        assert!(!is_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_headers_case_insensitive() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("upgrade", "WebSocket".parse().unwrap());
        headers.insert("connection", "Upgrade".parse().unwrap());
        assert!(is_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_headers_not_websocket() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        assert!(!is_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_headers_empty() {
        let headers = hyper::HeaderMap::new();
        assert!(!is_websocket_upgrade_headers(&headers));
    }
}
