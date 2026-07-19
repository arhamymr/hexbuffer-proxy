use std::net::SocketAddr;

use async_trait::async_trait;

use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use bytes::Bytes;

use crate::error::Result;

// ── Context ────────────────────────────────────────────────────────

/// Context available during request/response processing.
pub struct HttpContext {
    /// Unique request ID for tracing.
    pub id: u64,
    /// Target hostname.
    pub host: String,
    /// Client socket address.
    pub client_addr: SocketAddr,
    /// Whether this is an HTTPS (CONNECT-tunneled) request.
    pub is_https: bool,
}

// ── Body ───────────────────────────────────────────────────────────

/// An HTTP body — either streaming from the upstream or fully buffered.
pub enum Body {
    Streaming(hyper::body::Incoming),
    Full(Bytes),
}

impl Body {
    /// Collect the entire body into memory.
    pub async fn into_bytes(self) -> Result<Bytes> {
        match self {
            Body::Full(b) => Ok(b),
            Body::Streaming(incoming) => {
                let collected = incoming
                    .collect()
                    .await
                    .map_err(|e| crate::error::ProxyError::Protocol(e.to_string()))?;
                Ok(collected.to_bytes())
            }
        }
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Self {
        Body::Full(b)
    }
}

impl From<hyper::body::Incoming> for Body {
    fn from(b: hyper::body::Incoming) -> Self {
        Body::Streaming(b)
    }
}

/// Create a response body from bytes (short-circuit helpers use this).
pub fn full_body(data: impl Into<Bytes>) -> Full<Bytes> {
    Full::new(data.into())
}

// ── RequestOrResponse ──────────────────────────────────────────────

/// Returned by `handle_request`. Allows short-circuiting —
/// return a response immediately without contacting the upstream.
pub enum RequestOrResponse {
    Request(Request<Body>),
    Response(Response<Body>),
}

// ── HttpHandler trait ──────────────────────────────────────────────

/// Handler for HTTP requests and responses.
/// Called for every intercepted request/response pair.
#[async_trait]
pub trait HttpHandler: Send + Sync {
    /// Called when a request is intercepted (before forwarding to upstream).
    /// Return `RequestOrResponse::Request(modified)` to forward,
    /// or `RequestOrResponse::Response(res)` to short-circuit.
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Result<RequestOrResponse>;

    /// Called when a response is intercepted (before returning to client).
    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Result<Response<Body>>;

    /// Called before TLS interception for a CONNECT tunnel.
    /// Return `false` to skip MITM and relay raw TCP
    /// (e.g. for cert-pinned domains like `gemini.google.com`).
    /// Default: `true` (intercept all).
    async fn should_intercept_tls(&self, _host: &str) -> bool {
        true
    }
}

// ── NoopHandler ────────────────────────────────────────────────────

/// A no-op handler that passes all traffic through unchanged.
pub struct NoopHandler;

#[async_trait]
impl HttpHandler for NoopHandler {
    async fn handle_request(
        &self,
        _ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        Ok(RequestOrResponse::Request(request))
    }

    async fn handle_response(
        &self,
        _ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        Ok(response)
    }
}

// ── WebSocketHandler trait ───────────────────────────────────────

/// Direction of a WebSocket frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// Handler for WebSocket frame-level interception.
///
/// Implement this trait to inspect or modify WebSocket traffic
/// after a successful HTTP upgrade (101 Switching Protocols).
#[async_trait]
pub trait WebSocketHandler: Send + Sync {
    /// Called when a WebSocket upgrade is detected,
    /// before the request is forwarded upstream.
    async fn on_upgrade(
        &self,
        _ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Request<Body> {
        request
    }

    /// Called for each WebSocket frame passing through the proxy.
    /// Return `Some(frame)` to forward, or `None` to drop it.
    async fn on_frame(
        &self,
        _ctx: &mut HttpContext,
        frame: tokio_tungstenite::tungstenite::Message,
        _direction: Direction,
    ) -> Option<tokio_tungstenite::tungstenite::Message> {
        Some(frame)
    }

    /// Called when the WebSocket connection closes (either side).
    async fn on_close(&self, _ctx: &mut HttpContext) {}
}

/// Re-export tungstenite Message for convenience.
pub use tokio_tungstenite::tungstenite::Message as WebSocketMessage;

// ── NoopWebSocketHandler ──────────────────────────────────────────

/// A no-op WebSocket handler that passes all frames through unchanged.
pub struct NoopWebSocketHandler;

#[async_trait]
impl WebSocketHandler for NoopWebSocketHandler {}


// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_full_body_creates_correct_bytes() {
        let body = full_body("payload");
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(&collected[..], b"payload");
    }

    #[test]
    fn test_body_from_bytes() {
        let b = bytes::Bytes::from("data");
        let body: Body = b.into();
        match body {
            Body::Full(bytes) => assert_eq!(&bytes[..], b"data"),
            Body::Streaming(_) => panic!("expected Full variant"),
        }
    }

    #[tokio::test]
    async fn test_body_full_into_bytes() {
        let body = Body::Full(bytes::Bytes::from("hello"));
        let result = body.into_bytes().await.unwrap();
        assert_eq!(&result[..], b"hello");
    }
}
