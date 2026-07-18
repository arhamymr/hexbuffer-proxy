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
