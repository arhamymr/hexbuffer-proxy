// upstream.rs — shared Hyper client with connection pooling,
// HTTP/2 ALPN negotiation, and transparent body decompression
// via tower-http's DecompressionLayer middleware.
//
// A single LazyLock<Tower service stack> is cloned per request
// (cheap — clones share the connection pool).

use std::sync::LazyLock;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
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
    BoxBody<Bytes, hyper::Error>,
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
        .pool_idle_timeout(Duration::from_secs(90))
        .build(https);

    DecompressionLayer::new()
        .gzip(true)
        .deflate(true)
        .br(true)
        .zstd(true)
        .layer(client)
});

// ── Helper ──────────────────────────────────────────────────────

/// Convert internal `Body` into a boxed `http_body::Body` for Hyper without copying.
fn body_to_hyper(body: Body) -> BoxBody<Bytes, hyper::Error> {
    match body {
        Body::Full(b) => Full::new(b).map_err(|e| match e {}).boxed(),
        Body::Streaming(incoming) => incoming.boxed(),
    }
}

// ── Public API ──────────────────────────────────────────────────

/// Send an HTTP request upstream through the pooled Hyper client.
///
/// 1. The request body is streamed natively using Hyper's body abstractions.
/// 2. The response stream from tower-http's `DecompressionLayer` decodes
///    gzip, deflate, brotli, or zstd on the fly.
/// 3. Decompressed body frames are collected into `Bytes` and wrapped into
///    `Body::Full(decoded)` for downstream handler inspection.
pub(crate) async fn send_request(req: Request<Body>) -> anyhow::Result<Response<Body>> {
    let (parts, body) = req.into_parts();
    let hyper_req = Request::from_parts(parts, body_to_hyper(body));

    // Send upstream through the Tower service stack
    let mut svc = SERVICE.clone();
    let resp = svc.ready().await?.call(hyper_req).await?;

    // 1. Decompression & Collection: Collect decompressed body frames (gzip/deflate/br/zstd)
    let (parts, body) = resp.into_parts();
    let decoded = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("decompression failed: {e}"))?
        .to_bytes();

    // 2. Body Wrapping: Wrap decoded bytes into Body::Full for downstream handlers
    Ok(Response::from_parts(parts, Body::Full(decoded)))
}
