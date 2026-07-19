// upstream.rs — shared Hyper client with connection pooling,
// HTTP/2 ALPN negotiation, and transparent body decompression
// via tower-http's DecompressionLayer middleware.
//
// A single LazyLock<Tower service stack> is cloned per request
// (cheap — clones share the connection pool).

use std::sync::LazyLock;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tower::{Service, ServiceExt};
use tower::Layer;
use tower_http::decompression::{Decompression, DecompressionLayer};

use crate::handler::Body;

// ── Type aliases ────────────────────────────────────────────────

type HyperClient = Client<
    HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

type DecompressionSvc = Decompression<HyperClient>;

// ── Shared service stack ────────────────────────────────────────

static SERVICE: LazyLock<DecompressionSvc> = LazyLock::new(|| {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();

    let client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(20)
        .build(https);

    DecompressionLayer::new()
        .gzip(true)
        .deflate(true)
        .br(true)
        .zstd(true)
        .layer(client)
});

// ── Public API ──────────────────────────────────────────────────

/// Send an HTTP request upstream through the pooled Hyper client.
///
/// The response body is fully buffered and transparently
/// decompressed (gzip, deflate, brotli, zstd) by tower-http's
/// `DecompressionLayer` middleware — no manual header inspection.
pub(crate) async fn send_request(req: Request<Body>) -> anyhow::Result<Response<Body>> {
    let (parts, body) = req.into_parts();

    // Collect the request body (always buffered in our proxy)
    let body_bytes = body.into_bytes().await?;
    let hyper_body = Full::new(body_bytes);
    let hyper_req = Request::from_parts(parts, hyper_body);

    // Send upstream through the Tower service stack
    // (connection pooling, HTTP/2 ALPN, transparent decompression)
    let mut svc = SERVICE.clone();
    let resp = svc.ready().await?.call(hyper_req).await?;

    // Collect the (already decompressed) response body
    let (parts, body) = resp.into_parts();
    let decoded = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("decompression failed: {e}"))?
        .to_bytes();

    Ok(Response::from_parts(parts, Body::Full(decoded)))
}
