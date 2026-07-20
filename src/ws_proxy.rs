// ws_proxy.rs — WebSocket upgrade detection, upgrade handshake, and bidirectional relay
use crate::handler::{Body, Direction, HttpContext, HttpHandler, WebSocketHandler};

use anyhow;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Request, Response};
use http_body_util::Full;
use hyper_tungstenite;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

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

/// Handle a WebSocket upgrade inside the TLS tunnel.
///
/// Uses [`hyper_tungstenite::upgrade`] to perform the WebSocket handshake
/// within Hyper's HTTP server, then connects to the upstream via
/// [`tokio_tungstenite::connect_async_tls_with_config`] and relays frames
/// bidirectionally.
pub(crate) async fn handle_https_websocket(
    mut req: Request<Body>,
    _handler: Arc<dyn HttpHandler>,
    ws_handler: Option<Arc<dyn WebSocketHandler>>,
    ctx: &mut HttpContext,
    target_host: &str,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    // 1. Make URI absolute if needed and rewrite scheme: https → wss
    if req.uri().scheme().is_none() {
        let uri: http::Uri = format!("https://{}{}", target_host, req.uri())
            .parse()
            .map_err(|e| anyhow::anyhow!("[ws] invalid absolute URI: {e}"))?;
        *req.uri_mut() = uri;
    }
    {
        let uri = req.uri().clone();
        let mut parts = uri.into_parts();
        parts.scheme = Some(
            http::uri::Scheme::try_from("wss")
                .map_err(|e| anyhow::anyhow!("[ws] scheme error: {e}"))?,
        );
        let new_uri = http::Uri::from_parts(parts)
            .map_err(|e| anyhow::anyhow!("[ws] invalid URI: {e}"))?;
        *req.uri_mut() = new_uri;
    }

    // 2. Upgrade client side via hyper_tungstenite
    let (res, ws_fut) = hyper_tungstenite::upgrade(&mut req, None)
        .map_err(|e| anyhow::anyhow!("[ws] upgrade failed: {e}"))?;

    // 3. Build 101 response for the client (body is always empty)
    let mut response_builder = Response::builder().status(res.status());
    for (key, value) in res.headers() {
        response_builder = response_builder.header(key, value);
    }
    let client_res = response_builder.body(Full::new(Bytes::new()))?;

    // 4. Spawn relay task — connects to upstream and relays frames
    let ctx_id = ctx.id;
    let ctx_host = ctx.host.clone();
    let upgrade_req = req.map(|_| ()); // strip body for tokio_tungstenite
    tokio::spawn(async move {
        match ws_fut.await {
            Ok(client_ws) => {
                let connector = tokio_tungstenite::Connector::Rustls(Arc::new({
                    let roots = tokio_rustls::rustls::RootCertStore::from_iter(
                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                    );
                    tokio_rustls::rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth()
                }));

                match tokio_tungstenite::connect_async_tls_with_config(
                    upgrade_req, None, false, Some(connector),
                ).await {
                    Ok((server_ws, _)) => {
                        if let Some(ws) = ws_handler {
                            let mut relay_ctx = HttpContext {
                                id: ctx_id,
                                host: ctx_host,
                                client_addr: "0.0.0.0:0".parse().unwrap(),
                                is_https: true,
                            };
                            let _ = relay_upgraded(client_ws, server_ws, ws, &mut relay_ctx).await;
                        } else {
                            let _ = relay_raw_upgraded(client_ws, server_ws).await;
                        }
                    }
                    Err(e) => eprintln!("[ws] upstream connect error: {e}"),
                }
            }
            Err(e) => eprintln!("[ws] upgrade error: {e}"),
        }
    });

    Ok(client_res)
}

/// Bidirectional WebSocket frame relay for already-upgraded streams.
///
/// Splits each [`WebSocketStream`] into sink + stream halves and relays
/// frames through the handler's [`on_frame`] / [`on_close`] callbacks.
async fn relay_upgraded<A, B>(
    client: A,
    server: B,
    handler: Arc<dyn WebSocketHandler>,
    ctx: &mut HttpContext,
) -> anyhow::Result<()>
where
    A: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
    B: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let (mut client_sink, mut client_stream) = client.split();
    let (mut server_sink, mut server_stream) = server.split();

    loop {
        tokio::select! {
            msg = client_stream.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        let is_close = msg.is_close();
                        if let Some(msg) = handler.on_frame(ctx, msg, Direction::ClientToServer).await {
                            let _ = server_sink.send(msg).await;
                        }
                        if is_close { break; }
                    }
                    _ => break,
                }
            }
            msg = server_stream.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        let is_close = msg.is_close();
                        if let Some(msg) = handler.on_frame(ctx, msg, Direction::ServerToClient).await {
                            let _ = client_sink.send(msg).await;
                        }
                        if is_close { break; }
                    }
                    _ => break,
                }
            }
        }
    }

    handler.on_close(ctx).await;
    Ok(())
}

/// Raw bidirectional relay for already-upgraded WebSocket streams (no handler).
async fn relay_raw_upgraded<A, B>(client: A, server: B) -> anyhow::Result<()>
where
    A: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
    B: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let (mut client_sink, mut client_stream) = client.split();
    let (mut server_sink, mut server_stream) = server.split();

    loop {
        tokio::select! {
            msg = client_stream.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        let is_close = msg.is_close();
                        let _ = server_sink.send(msg).await;
                        if is_close { break; }
                    }
                    _ => break,
                }
            }
            msg = server_stream.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        let is_close = msg.is_close();
                        let _ = client_sink.send(msg).await;
                        if is_close { break; }
                    }
                    _ => break,
                }
            }
        }
    }

    Ok(())
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
}
