// upstream.rs — shared Hyper client with connection pooling,
// HTTP/2 ALPN negotiation, and transparent body decompression.
//
// A single LazyLock<Client> is cloned per request (cheap —
// clones share the connection pool).

use std::sync::LazyLock;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::handler::Body;

// ── Shared client ───────────────────────────────────────────────

type HyperClient = Client<
    HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

static CLIENT: LazyLock<HyperClient> = LazyLock::new(|| {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http2()
        .build();

    Client::builder(TokioExecutor::new()).build(https)
});

// ── Public API ──────────────────────────────────────────────────

/// Send an HTTP request upstream through the pooled Hyper client.
///
/// The response body is fully buffered and transparently
/// decompressed (gzip, deflate, brotli, zstd) based on the
/// `Content-Encoding` response header.
pub(crate) async fn send_request(req: Request<Body>) -> anyhow::Result<Response<Body>> {
    let (parts, body) = req.into_parts();

    // Collect the request body (always buffered in our proxy)
    let body_bytes = body.into_bytes().await?;
    let hyper_body = Full::new(body_bytes);
    let hyper_req = Request::from_parts(parts, hyper_body);

    // Send upstream — clones the client handle (connection pool is shared)
    let resp = CLIENT.request(hyper_req).await?;

    // Collect the response body into memory
    let (parts, body) = resp.into_parts();
    let raw = body.collect().await?.to_bytes();

    // Transparent decompression
    let encoding = parts
        .headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let decoded = decode_body(encoding, &raw)?;

    Ok(Response::from_parts(parts, Body::Full(Bytes::from(decoded))))
}

// ── Decompression ───────────────────────────────────────────────

fn decode_body(encoding: &str, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;

    match encoding {
        "gzip" | "x-gzip" => {
            let mut d = flate2::read::GzDecoder::new(data);
            let mut out = Vec::new();
            d.read_to_end(&mut out)?;
            Ok(out)
        }
        "deflate" => {
            let mut d = flate2::read::DeflateDecoder::new(data);
            let mut out = Vec::new();
            d.read_to_end(&mut out)?;
            Ok(out)
        }
        "br" => {
            let mut d = brotli::Decompressor::new(data, 4096);
            let mut out = Vec::new();
            d.read_to_end(&mut out)?;
            Ok(out)
        }
        "zstd" => Ok(zstd::decode_all(data)?),
        "" | "identity" => Ok(data.to_vec()),
        other => {
            eprintln!("[hexbuffer-proxy] unknown Content-Encoding: {other}, returning raw bytes");
            Ok(data.to_vec())
        }
    }
}
