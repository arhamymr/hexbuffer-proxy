// ws_proxy.rs — WebSocket upgrade detection and bidirectional relay
use crate::handler::{Body, Direction, HttpContext, WebSocketHandler};
use futures_util::{SinkExt, StreamExt};
use http::{Request, Response};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Check serialized HTTP request bytes for a WebSocket upgrade.
#[allow(dead_code)]
pub(crate) fn is_websocket_upgrade_bytes(raw: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(raw).to_lowercase();
    lower.contains("upgrade:") && lower.contains("websocket")
}

/// Check a parsed request for a WebSocket upgrade.
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
pub(crate) fn is_websocket_response(res: &Response<Body>) -> bool {
    res.status() == 101
}

/// Bidirectional relay between client and server streams.
/// Used after a successful WebSocket upgrade (101 response) to pass
/// raw frames between the client and upstream without closing either side.
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
