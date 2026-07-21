// upstream.rs — shared Hyper client with connection pooling,
// HTTP/2 ALPN negotiation, and optional transparent body
// decompression via tower-http's DecompressionLayer middleware.
//
// Two LazyLock service stacks are cloned per request
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

// ── Shared service stacks ───────────────────────────────────────

/// Decompressing service — gzip, deflate, brotli, zstd stripped transparently.
static SERVICE_DECOMPRESS: LazyLock<Decompression<HyperClient>> = LazyLock::new(|| {
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

/// Raw pass-through service — no decompression applied.
static SERVICE_RAW: LazyLock<HyperClient> = LazyLock::new(|| {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();

    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(Duration::from_secs(90))
        .build(https)
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
/// When `decompress` is true (default), gzip/deflate/brotli/zstd
/// response bodies are decoded transparently via tower-http's
/// `DecompressionLayer`.  When false, raw compressed bytes are
/// passed through untouched — useful for caching proxies.
pub(crate) async fn send_request(req: Request<Body>, decompress: bool) -> anyhow::Result<Response<Body>> {
    let (parts, body) = req.into_parts();
    let hyper_req = Request::from_parts(parts, body_to_hyper(body));

    if decompress {
        let mut svc = SERVICE_DECOMPRESS.clone();
        let resp = svc.ready().await?.call(hyper_req).await?;
        let (parts, body) = resp.into_parts();
        let bytes = body
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("decompression failed: {e}"))?
            .to_bytes();
        Ok(Response::from_parts(parts, Body::Full(bytes)))
    } else {
        let mut svc = SERVICE_RAW.clone();
        let resp = svc.ready().await?.call(hyper_req).await?;
        let (parts, body) = resp.into_parts();
        let bytes = body
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("upstream read: {e}"))?
            .to_bytes();
        Ok(Response::from_parts(parts, Body::Full(bytes)))
    }
}
