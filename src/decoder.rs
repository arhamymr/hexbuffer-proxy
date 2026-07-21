//! Application-level body decoder — pluggable handler + utility functions.
//!
//! # Relationship with tower-http
//!
//! The proxy's [`crate::upstream`] module transparently decompresses
//! **response** bodies via `tower-http` (gzip/deflate/brotli/zstd).
//! This module is complementary:
//!
//! | Direction | Tower | DecodeHandler |
//! |-----------|-------|---------------|
//! | Request   | Never touches | Decodes if added to chain |
//! | Response  | Decompresses (if `decompress=true`) | Skips (header already stripped) |
//! | Response  | Passes raw (if `decompress=false`) | Decodes |
//!
//! # Usage modes
//!
//! **Tier 1 — Inspection (default):** add [`DecodeHandler`] to your chain,
//! keep tower decompression on. Request bodies are decoded for handlers;
//! response bodies are already handled by tower.
//!
//! **Tier 2 — Forensic:** disable tower (`with_decompression(false)`),
//! add [`DecodeHandler`] to the chain. Both directions decoded at the
//! application layer. Add a wire-capture handler before DecodeHandler
//! to snapshot raw bytes.
//!
//! **Tier 3 — Repeater:** call [`decode_request`] / [`decode_response`]
//! manually, modify the body, then call [`encode_body`] to re-compress
//! before forwarding.
//!
//! # Cargo feature
//!
//! Enabled by default. Opt out with:
//! ```toml
//! hexbuffer-proxy = { default-features = false }
//! ```

use std::io::{Read, Write};

use async_trait::async_trait;
use bytes::Buf;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use http::{Request, Response};
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};

use crate::error::{ProxyError, Result};
use crate::handler::{Body, HttpContext, HttpHandler, RequestOrResponse};

// ── Encoding helpers ───────────────────────────────────────────

/// Iterate `Content-Encoding` values **innermost-first**.
/// e.g. `br, gzip` → `["gzip", "br"]` (decode gzip first, then brotli).
fn encodings(map: &http::HeaderMap) -> impl Iterator<Item = &[u8]> {
    map.get_all(CONTENT_ENCODING)
        .iter()
        .rev()
        .flat_map(|val| {
            val.as_bytes()
                .rsplit(|&b| b == b',')
                .map(trim_ascii)
        })
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != b' ').unwrap_or(0);
    let end = bytes.iter().rposition(|&b| b != b' ').map(|p| p + 1).unwrap_or(bytes.len());
    &bytes[start..end]
}

fn should_decode(headers: &http::HeaderMap) -> bool {
    headers.contains_key(CONTENT_ENCODING)
        && headers
            .get(CONTENT_LENGTH)
            .map(|v| v != "0")
            .unwrap_or(true)
}

// ── Decode ─────────────────────────────────────────────────────

fn pick_decoder<R: Read + Send + 'static>(encoding: &[u8], reader: R) -> Result<Box<dyn Read + Send>> {
    Ok(match encoding {
        b"gzip" | b"x-gzip" => Box::new(GzDecoder::new(reader)),
        b"deflate" => Box::new(ZlibDecoder::new(reader)),
        b"br" => Box::new(brotli::reader::Decompressor::new(reader, 4096)),
        b"zstd" => Box::new(zstd::stream::read::Decoder::new(reader).map_err(|e| {
            ProxyError::Protocol(format!("zstd decoder init failed: {e}"))
        })?),
        other => {
            return Err(ProxyError::Protocol(format!(
                "unsupported content-encoding: {}",
                String::from_utf8_lossy(other)
            )));
        }
    })
}

async fn decode_body(encs: Vec<Vec<u8>>, body: Body) -> Result<Body> {
    let bytes = body.into_bytes().await?;

    // Decompression is CPU-bound — run on blocking thread pool.
    let decoded = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut reader: Box<dyn Read + Send> = Box::new(bytes.reader());

        for encoding in &encs {
            if encoding == b"identity" {
                continue;
            }
            reader = pick_decoder(encoding, reader)?;
        }

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).map_err(ProxyError::Io)?;
        Ok(buf)
    })
    .await
    .map_err(|e| ProxyError::Protocol(format!("decode task panicked: {e}")))?;

    let decoded = decoded?;
    Ok(Body::Full(bytes::Bytes::from(decoded)))
}

fn strip_encoding_headers_req(parts: &mut http::request::Parts) {
    parts.headers.remove(CONTENT_ENCODING);
    parts.headers.remove(CONTENT_LENGTH);
}

fn strip_encoding_headers_res(parts: &mut http::response::Parts) {
    parts.headers.remove(CONTENT_ENCODING);
    parts.headers.remove(CONTENT_LENGTH);
}

// ── Public: decode ─────────────────────────────────────────────

/// Decode a **request** body in-place.
///
/// Reads `Content-Encoding`, decompresses (gzip/deflate/brotli/zstd),
/// and strips both `Content-Encoding` and `Content-Length` headers.
/// Bodies without a `Content-Encoding` header are returned unchanged.
///
/// Use this directly in a handler when you need fine-grained control
/// over *when* decoding happens. For automatic decoding of every
/// request, prefer inserting [`DecodeHandler`] into the handler chain.
pub async fn decode_request(req: Request<Body>) -> Result<Request<Body>> {
    if !should_decode(req.headers()) {
        return Ok(req);
    }

    let (mut parts, body) = req.into_parts();
    let encs: Vec<Vec<u8>> = encodings(&parts.headers).map(|s| s.to_vec()).collect();
    let body = decode_body(encs, body).await?;

    strip_encoding_headers_req(&mut parts);
    Ok(Request::from_parts(parts, body))
}

/// Decode a **response** body in-place.
///
/// Same semantics as [`decode_request`] but for HTTP responses.
pub async fn decode_response(res: Response<Body>) -> Result<Response<Body>> {
    if !should_decode(res.headers()) {
        return Ok(res);
    }

    let (mut parts, body) = res.into_parts();
    let encs: Vec<Vec<u8>> = encodings(&parts.headers).map(|s| s.to_vec()).collect();
    let body = decode_body(encs, body).await?;

    strip_encoding_headers_res(&mut parts);
    Ok(Response::from_parts(parts, body))
}

// ── Public: encode ─────────────────────────────────────────────

/// Re-encode a body — compress with `encoding` and optionally
/// convert charset.
///
/// Used by repeater/modifier handlers that alter a decoded body and
/// need to re-apply the original wire encoding before forwarding.
///
/// # Parameters
/// - `body` — the decoded body to re-compress (must be `Body::Full`)
/// - `encoding` — one of `"gzip"`, `"deflate"`, `"br"`, `"zstd"`
/// - `_charset` — reserved for future charset conversion (currently no-op)
///
/// # Example
///
/// ```ignore
/// let decoded = decode_request(req).await?;
/// // ... modify body ...
/// let recompressed = encode_body(
///     Body::Full(modified_bytes.into()),
///     "gzip",
///     None,
/// )?;
/// ```
pub fn encode_body(
    body: Body,
    encoding: &str,
    _charset: Option<&str>,
) -> Result<Body> {
    let bytes = match body {
        Body::Full(b) => b,
        Body::Streaming(_) => {
            return Err(ProxyError::Protocol(
                "encode_body requires a buffered body (Body::Full)".into(),
            ));
        }
    };

    let mut out = Vec::with_capacity(bytes.len());

    match encoding {
        "gzip" | "x-gzip" => {
            let mut w = GzEncoder::new(&mut out, Compression::default());
            w.write_all(&bytes).map_err(ProxyError::Io)?;
            w.finish().map_err(ProxyError::Io)?;
        }
        "deflate" => {
            let mut w = ZlibEncoder::new(&mut out, Compression::default());
            w.write_all(&bytes).map_err(ProxyError::Io)?;
            w.finish().map_err(ProxyError::Io)?;
        }
        "br" => {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 6, 22);
            w.write_all(&bytes).map_err(ProxyError::Io)?;
            // Compressor flushes on Drop
            drop(w);
        }
        "zstd" => {
            let mut w = zstd::stream::write::Encoder::new(&mut out, 0)
                .map_err(|e| ProxyError::Protocol(format!("zstd encoder init: {e}")))?;
            w.write_all(&bytes).map_err(ProxyError::Io)?;
            w.finish().map_err(ProxyError::Io)?;
        }
        other => {
            return Err(ProxyError::Protocol(format!(
                "unsupported encoding for re-compression: {other}"
            )));
        }
    }

    Ok(Body::Full(bytes::Bytes::from(out)))
}

// ── DecodeHandler — pluggable handler ──────────────────────────

/// A handler plugin that decodes `Content-Encoding` on every request
/// and response body passing through it.
///
/// ## Placement
///
/// Insert **before** handlers that need to inspect decoded bodies:
///
/// ```ignore
/// ProxyBuilder::new()
///     .with_http_handler(LoggingHandler::new())
///     .add_http_handler(DecodeHandler)          // ← decode first
///     .add_http_handler(MyInspectionHandler)    // ← then inspect
///     .build()?;
/// ```
///
/// Handlers placed **after** [`DecodeHandler`] in the chain receive
/// buffered, decompressed `Body::Full` — safe to inspect immediately.
///
/// ## Interaction with tower decompression
///
/// When `decompress=true` (the default), tower already strips
/// `Content-Encoding` from responses. [`DecodeHandler`] sees no
/// encoding header and passes responses through unchanged. It still
/// decodes request bodies, which tower never touches.
pub struct DecodeHandler;

#[async_trait]
impl HttpHandler for DecodeHandler {
    async fn handle_request(
        &self,
        _ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        Ok(RequestOrResponse::Request(decode_request(request).await?))
    }

    async fn handle_response(
        &self,
        _ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        decode_response(response).await
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    use bytes::Bytes;

    // ── encodings ───────────────────────────────────────────

    #[test]
    fn single_encoding() {
        let mut h = http::HeaderMap::new();
        h.insert(CONTENT_ENCODING, "gzip".parse().unwrap());
        assert_eq!(encodings(&h).collect::<Vec<_>>(), vec![b"gzip"]);
    }

    #[test]
    fn comma_separated_innermost_first() {
        let mut h = http::HeaderMap::new();
        h.insert(CONTENT_ENCODING, "gzip, deflate".parse().unwrap());
        assert_eq!(
            encodings(&h).collect::<Vec<_>>(),
            vec![&b"deflate"[..], &b"gzip"[..]]
        );
    }

    #[test]
    fn multi_header_innermost_first() {
        let mut h = http::HeaderMap::new();
        h.append(CONTENT_ENCODING, "gzip".parse().unwrap());
        h.append(CONTENT_ENCODING, "br".parse().unwrap());
        assert_eq!(
            encodings(&h).collect::<Vec<_>>(),
            vec![&b"br"[..], &b"gzip"[..]]
        );
    }

    #[test]
    fn no_headers_empty() {
        assert_eq!(encodings(&http::HeaderMap::new()).count(), 0);
    }

    // ── decode_body ─────────────────────────────────────────

    #[tokio::test]
    async fn no_encodings_passthrough() {
        let body = Body::Full(Bytes::from("hello"));
        let out = decode_body(Vec::new(), body).await.unwrap();
        assert_eq!(&out.into_bytes().await.unwrap()[..], b"hello");
    }

    #[tokio::test]
    async fn identity_passthrough() {
        let body = Body::Full(Bytes::from("world"));
        let out = decode_body(vec![b"identity".to_vec()], body).await.unwrap();
        assert_eq!(&out.into_bytes().await.unwrap()[..], b"world");
    }

    #[tokio::test]
    async fn gzip_roundtrip() {
        let plain = b"the quick brown fox jumps over the lazy dog";
        let mut buf = Vec::new();
        {
            let mut w = GzEncoder::new(&mut buf, Compression::default());
            w.write_all(plain).unwrap();
            w.finish().unwrap();
        }

        let body = Body::Full(Bytes::from(buf));
        let out = decode_body(vec![b"gzip".to_vec()], body).await.unwrap();
        assert_eq!(&out.into_bytes().await.unwrap()[..], plain);
    }

    #[tokio::test]
    async fn brotli_roundtrip() {
        let plain = b"brotli compression test payload";
        let mut buf = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut buf, 4096, 6, 22);
            w.write_all(plain).unwrap();
            drop(w);
        }

        let body = Body::Full(Bytes::from(buf));
        let out = decode_body(vec![b"br".to_vec()], body).await.unwrap();
        assert_eq!(&out.into_bytes().await.unwrap()[..], plain);
    }

    #[tokio::test]
    async fn zstd_roundtrip() {
        let plain = b"zstd compression test data here";
        let mut buf = Vec::new();
        {
            let mut w = zstd::stream::write::Encoder::new(&mut buf, 0).unwrap();
            w.write_all(plain).unwrap();
            w.finish().unwrap();
        }

        let body = Body::Full(Bytes::from(buf));
        let out = decode_body(vec![b"zstd".to_vec()], body).await.unwrap();
        assert_eq!(&out.into_bytes().await.unwrap()[..], plain);
    }

    #[tokio::test]
    async fn unsupported_encoding_errors() {
        let body = Body::Full(Bytes::from("nope"));
        assert!(decode_body(vec![b"bogus".to_vec()], body).await.is_err());
    }

    // ── decode_request ──────────────────────────────────────

    #[tokio::test]
    async fn request_no_encoding_unchanged() {
        let req = Request::builder()
            .uri("/")
            .body(Body::Full(Bytes::from("raw")))
            .unwrap();
        let out = decode_request(req).await.unwrap();
        assert_eq!(&out.into_body().into_bytes().await.unwrap()[..], b"raw");
    }

    #[tokio::test]
    async fn request_zero_length_skipped() {
        let req = Request::builder()
            .uri("/")
            .header(CONTENT_ENCODING, "gzip")
            .header(CONTENT_LENGTH, "0")
            .body(Body::Full(Bytes::new()))
            .unwrap();
        let out = decode_request(req).await.unwrap();
        assert!(out.headers().contains_key(CONTENT_ENCODING));
    }

    #[tokio::test]
    async fn request_strips_headers_after_decode() {
        let plain = b"data";
        let mut buf = Vec::new();
        {
            let mut w = GzEncoder::new(&mut buf, Compression::default());
            w.write_all(plain).unwrap();
            w.finish().unwrap();
        }

        let req = Request::builder()
            .uri("/")
            .header(CONTENT_ENCODING, "gzip")
            .header(CONTENT_LENGTH, buf.len().to_string())
            .body(Body::Full(Bytes::from(buf)))
            .unwrap();
        let out = decode_request(req).await.unwrap();

        assert!(!out.headers().contains_key(CONTENT_ENCODING));
        assert!(!out.headers().contains_key(CONTENT_LENGTH));
        assert_eq!(&out.into_body().into_bytes().await.unwrap()[..], plain);
    }

    // ── decode_response ─────────────────────────────────────

    #[tokio::test]
    async fn response_strips_headers_after_decode() {
        let plain = b"payload";
        let mut buf = Vec::new();
        {
            let mut w = GzEncoder::new(&mut buf, Compression::default());
            w.write_all(plain).unwrap();
            w.finish().unwrap();
        }

        let res = Response::builder()
            .status(200)
            .header(CONTENT_ENCODING, "gzip")
            .body(Body::Full(Bytes::from(buf)))
            .unwrap();
        let out = decode_response(res).await.unwrap();

        assert!(!out.headers().contains_key(CONTENT_ENCODING));
        assert_eq!(&out.into_body().into_bytes().await.unwrap()[..], plain);
    }

    // ── encode_body ─────────────────────────────────────────

    #[test]
    fn gzip_encode_roundtrip() {
        let plain = b"roundtrip test data for gzip";
        let body = Body::Full(Bytes::from(&plain[..]));
        let encoded = encode_body(body, "gzip", None).unwrap();
        let encoded_bytes = match encoded {
            Body::Full(b) => b,
            _ => panic!("expected Full"),
        };
        assert_ne!(&encoded_bytes[..], plain);
    }

    #[test]
    fn br_encode_roundtrip() {
        let plain = b"brotli roundtrip test";
        let body = Body::Full(Bytes::from(&plain[..]));
        let encoded = encode_body(body, "br", None).unwrap();
        let encoded_bytes = match encoded {
            Body::Full(b) => b,
            _ => panic!("expected Full"),
        };
        assert_ne!(&encoded_bytes[..], plain);
    }

    #[test]
    fn encode_unsupported_encoding_errors() {
        let body = Body::Full(Bytes::from("nope"));
        assert!(encode_body(body, "bogus", None).is_err());
    }

    // ── DecodeHandler ───────────────────────────────────────

    #[tokio::test]
    async fn handler_decodes_request() {
        let plain = b"secret";
        let mut buf = Vec::new();
        {
            let mut w = GzEncoder::new(&mut buf, Compression::default());
            w.write_all(plain).unwrap();
            w.finish().unwrap();
        }

        let req = Request::builder()
            .uri("/")
            .header(CONTENT_ENCODING, "gzip")
            .body(Body::Full(Bytes::from(buf)))
            .unwrap();

        let mut ctx = HttpContext {
            id: 0,
            host: "example.com".into(),
            client_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: true,
        };

        let handler = DecodeHandler;
        let result = handler.handle_request(&mut ctx, req).await.unwrap();

        match result {
            RequestOrResponse::Request(req) => {
                assert!(!req.headers().contains_key(CONTENT_ENCODING));
                let body = req.into_body();
                let out = body.into_bytes().await.unwrap();
                assert_eq!(&out[..], plain);
            }
            _ => panic!("expected Request"),
        }
    }
}
