// upstream.rs — shared Hyper client with connection pooling and
// HTTP/1.1 ALPN negotiation. A single LazyLock client is cloned
// per request (cheap — clones share the connection pool).

use std::sync::LazyLock;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tower::{Service, ServiceExt};

use crate::handler::Body;

// ── Type aliases ────────────────────────────────────────────────

type HyperClient = Client<
    HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    BoxBody<Bytes, hyper::Error>,
>;

// ── Shared client ────────────────────────────────────────────────

static CLIENT: LazyLock<HyperClient> = LazyLock::new(|| {
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
    body.into_boxed()
}

// ── Public API ──────────────────────────────────────────────────

/// Send an HTTP request upstream through the pooled Hyper client.
/// Response body streams directly without buffering.
pub(crate) async fn send_request(req: Request<Body>) -> anyhow::Result<Response<Body>> {
    let (parts, body) = req.into_parts();
    let hyper_req = Request::from_parts(parts, body_to_hyper(body));

    let mut svc = CLIENT.clone();
    let resp = svc.ready().await?.call(hyper_req).await?;
    let (parts, body) = resp.into_parts();
    Ok(Response::from_parts(parts, Body::Streaming(body.boxed())))
}
