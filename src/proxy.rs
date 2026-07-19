use crate::ca::CertificationAuthority;
use crate::handler::{HttpHandler, Body, WebSocketHandler};

// std
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

// tokio
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

// http
use http::{Request, Response};

/// Hook point counter for generating unique request IDs.
pub(crate) static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) async fn handle_client(
    mut client_stream: TcpStream,
    ca: Arc<CertificationAuthority>,
    handler: Arc<dyn HttpHandler>,
    ws_handler: Option<Arc<dyn WebSocketHandler>>,
    buf_size: usize,
) -> anyhow::Result<()> {

    // 1. Read the initial Request header 
    let mut buffer = vec![0;4096];
    let n = client_stream.read(&mut buffer).await?;
    buffer.truncate(n);
    let request_str = String::from_utf8(buffer)?;

    // client address for context
    let client_addr = client_stream
        .peer_addr()
        .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());

    // 2. Lifecycle check: identify if it is an HTTPS tunnel setup
    if request_str.starts_with("CONNECT") {
        // Extract host:port from CONNECT line, default port 443 if unspecified.
        let target = request_str
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| anyhow::anyhow!(
                "malformed CONNECT request: missing target host"
            ))?;

        // Ensure port is present — CONNECT always implies HTTPS (port 443).
        let target = if target.contains(':') {
            target.to_string()
        } else {
            format!("{target}:443")
        };

        return crate::https_proxy::handle_https(
            client_stream, ca, handler, ws_handler, &target, client_addr, buf_size,
        ).await;

    }

    // Plain HTTP — delegate
    crate::http_proxy::handle_http(
        client_stream, handler, ws_handler, client_addr, buf_size, request_str,
    ).await
}


// ── HTTP parse / serialize helpers ────────────────────────────────


pub(crate) fn parse_raw_request(raw: &[u8]) -> anyhow::Result<Request<Body>> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.lines();

    // request line
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let uri = parts.next().unwrap_or("/");
    let _version = parts.next().unwrap_or("HTTP/1.1");

    let mut builder = Request::builder().method(method).uri(uri);

    // headers
    for line in &mut lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            builder = builder.header(key.trim(), value.trim());
        }
    }

    // Extract body after \r\n\r\n
    let body_bytes = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| bytes::Bytes::copy_from_slice(&raw[pos + 4..]))
        .unwrap_or_default();

    Ok(builder.body(Body::Full(body_bytes)).unwrap())
}

pub(crate) fn serialize_request(req: &Request<Body>) -> Vec<u8> {
    let mut out = format!(
        "{} {} HTTP/1.1\r\n",
        req.method(),
        req.uri()
    ).into_bytes();

    for (key, value) in req.headers() {
        out.extend_from_slice(key.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");

    // Append body
    if let Body::Full(bytes) = req.body() {
        out.extend_from_slice(bytes);
    }

    out
}

pub(crate) fn parse_raw_response(raw: &[u8]) -> anyhow::Result<Response<Body>> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.lines();

    // status line
    let status_line = lines.next().unwrap_or("HTTP/1.1 200 OK");
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().unwrap_or("HTTP/1.1");
    let status: u16 = parts.next().unwrap_or("200").parse()?;

    let mut builder = Response::builder().status(status);

    // headers
    for line in &mut lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            builder = builder.header(key.trim(), value.trim());
        }
    }

    // Extract body after \r\n\r\n
    let body_bytes = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| bytes::Bytes::copy_from_slice(&raw[pos + 4..]))
        .unwrap_or_default();

    Ok(builder.body(Body::Full(body_bytes)).unwrap())
}

pub(crate) fn serialize_response(res: &Response<Body>) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {} {}\r\n",
        res.status().as_u16(),
        res.status().canonical_reason().unwrap_or("OK")
    ).into_bytes();

    for (key, value) in res.headers() {
        out.extend_from_slice(key.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");

    if let Body::Full(bytes) = res.body() {
        out.extend_from_slice(bytes);
    }

    out
}



// ── Response body reader ──────────────────────────────────────────

/// Read a complete HTTP response from a stream, handling
/// Content-Length, chunked transfer encoding, and Connection: close.
pub(crate) async fn read_full_response<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf_size: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut full = Vec::new();
    let mut chunk = vec![0; buf_size];

    // Read until we have headers (\r\n\r\n)
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        full.extend_from_slice(&chunk[..n]);
        if full.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = full
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(full.len());

    let headers = String::from_utf8_lossy(&full[..header_end]).into_owned();
    let body_tail: Vec<u8> = full[header_end..].to_vec();

    let body = read_http_body(stream, &headers, body_tail, buf_size).await?;

    let mut result = full[..header_end].to_vec();
    result.extend_from_slice(&body);
    Ok(result)
}

fn is_chunked(headers: &str) -> bool {
    headers
        .lines()
        .any(|l| {
            let lower = l.to_lowercase();
            lower.starts_with("transfer-encoding:") && lower.contains("chunked")
        })
}

fn get_content_length(headers: &str) -> Option<usize> {
    headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
}

async fn read_http_body<R: AsyncRead + Unpin>(
    stream: &mut R,
    headers: &str,
    initial: Vec<u8>,
    buf_size: usize,
) -> anyhow::Result<Vec<u8>> {
    // 101 Switching Protocols, 204 No Content, 304 Not Modified have no body
    if is_no_body_status(headers) {
        return Ok(Vec::new());
    }
    // Request with no Content-Length and no chunked → empty body.
    // (e.g. GET, HEAD, DELETE). Only responses use connection-close for body delimiting.
    if is_request(headers) && !is_chunked(headers) && get_content_length(headers).is_none() {
        return Ok(initial);
    }
    if is_chunked(headers) {
        read_chunked_body(stream, initial, buf_size).await
    } else if let Some(len) = get_content_length(headers) {
        read_exact(stream, initial, len, buf_size).await
    } else {
        read_until_close(stream, initial, buf_size).await
    }
}

fn is_no_body_status(headers: &str) -> bool {
    headers
        .lines()
        .next()
        .and_then(|status_line| status_line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .map(|code| matches!(code, 101 | 204 | 304))
        .unwrap_or(false)
}

fn is_request(headers: &str) -> bool {
    !headers.lines().next()
        .map(|l| l.starts_with("HTTP/"))
        .unwrap_or(false)
}

async fn read_chunked_body<R: AsyncRead + Unpin>(
    stream: &mut R,
    initial: Vec<u8>,
    buf_size: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut buf = initial;
    let mut chunk = vec![0; buf_size];

    loop {
        // Find end of chunk-size line
        while !buf.contains(&b'\n') {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok(body);
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        let nl = buf.iter().position(|&b| b == b'\n').unwrap();
        let size_line = String::from_utf8_lossy(&buf[..nl]);
        let hex_str = size_line.trim().split(';').next().unwrap_or("0");
        let chunk_size = usize::from_str_radix(hex_str, 16)
            .map_err(|_| anyhow::anyhow!("invalid chunk size: {}", hex_str))?;

        if chunk_size == 0 {
            break;
        }

        // Remove size line, read data + trailing \r\n
        buf.drain(..=nl);
        let needed = chunk_size + 2;

        while buf.len() < needed {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok(body);
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        body.extend_from_slice(&buf[..chunk_size]);
        buf.drain(..needed);
    }

    Ok(body)
}

async fn read_exact<R: AsyncRead + Unpin>(
    stream: &mut R,
    initial: Vec<u8>,
    content_length: usize,
    buf_size: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = initial;
    let mut chunk = vec![0; buf_size];

    while buf.len() < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    if buf.len() > content_length {
        buf.truncate(content_length);
    }

    Ok(buf)
}

async fn read_until_close<R: AsyncRead + Unpin>(
    stream: &mut R,
    initial: Vec<u8>,
    buf_size: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = initial;
    let mut chunk = vec![0; buf_size];

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    Ok(buf)
}


// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, Response};
    use crate::handler::Body;
    use bytes::Bytes;

    // ── parse_raw_request ──────────────────────────────────────

    #[test]
    fn test_parse_raw_request_basic_get() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req = parse_raw_request(raw).unwrap();
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri().path(), "/index.html");
        assert_eq!(
            req.headers().get("host").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_parse_raw_request_with_headers() {
        let raw = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\n";
        let req = parse_raw_request(raw).unwrap();
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri().path(), "/submit");
        assert_eq!(req.headers().len(), 3);
        assert_eq!(
            req.headers().get("content-length").unwrap(),
            "11"
        );
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "text/plain"
        );
    }

    #[test]
    fn test_parse_raw_request_trims_header_values() {
        let raw = b"GET / HTTP/1.1\r\nX-Custom:   padded value  \r\n\r\n";
        let req = parse_raw_request(raw).unwrap();
        assert_eq!(
            req.headers().get("x-custom").unwrap(),
            "padded value"
        );
    }

    // ── serialize_request ──────────────────────────────────────

    #[test]
    fn test_serialize_request_roundtrip() {
        let raw = b"GET /api/data HTTP/1.1\r\nhost: example.com\r\naccept: application/json\r\n\r\n";
        let req = parse_raw_request(raw).unwrap();
        let serialized = serialize_request(&req);
        let req2 = parse_raw_request(&serialized).unwrap();

        assert_eq!(req2.method(), req.method());
        assert_eq!(req2.uri().path(), req.uri().path());
        assert_eq!(
            req2.headers().get("host").unwrap(),
            req.headers().get("host").unwrap()
        );
    }

    #[test]
    fn test_serialize_request_includes_body() {
        let req = Request::builder()
            .method("POST")
            .uri("/upload")
            .header("content-type", "text/plain")
            .body(Body::Full(Bytes::from("payload")))
            .unwrap();

        let serialized = serialize_request(&req);
        let text = String::from_utf8_lossy(&serialized);

        assert!(text.contains("POST /upload HTTP/1.1"));
        assert!(text.contains("content-type: text/plain"));
        assert!(text.ends_with("payload"));
    }

    // ── parse_raw_response ─────────────────────────────────────

    #[test]
    fn test_parse_raw_response_200_ok() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\n";
        let res = parse_raw_response(raw).unwrap();
        assert_eq!(res.status().as_u16(), 200);
        assert_eq!(
            res.headers().get("content-type").unwrap(),
            "text/html"
        );
        assert_eq!(
            res.headers().get("content-length").unwrap(),
            "5"
        );
    }

    #[test]
    fn test_parse_raw_response_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let res = parse_raw_response(raw).unwrap();
        assert_eq!(res.status().as_u16(), 404);
    }

    // ── serialize_response ─────────────────────────────────────

    #[test]
    fn test_serialize_response_roundtrip() {
        let raw = b"HTTP/1.1 301 Moved Permanently\r\nLocation: /new-path\r\n\r\n";
        let res = parse_raw_response(raw).unwrap();
        let serialized = serialize_response(&res);
        let res2 = parse_raw_response(&serialized).unwrap();

        assert_eq!(res2.status(), res.status());
        assert_eq!(
            res2.headers().get("location").unwrap(),
            "/new-path"
        );
    }

    #[test]
    fn test_serialize_response_includes_body() {
        let res = Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::Full(Bytes::from("{\"ok\":true}")))
            .unwrap();

        let bytes = serialize_response(&res);
        let text = String::from_utf8_lossy(&bytes);

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("content-type: application/json"));
        assert!(text.ends_with("{\"ok\":true}"));
    }

    #[test]
    fn test_serialize_response_no_body_for_204() {
        let res = Response::builder()
            .status(204)
            .body(Body::Full(Bytes::new()))
            .unwrap();

        let bytes = serialize_response(&res);
        let text = String::from_utf8_lossy(&bytes);

        assert!(text.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }





    // ── is_no_body_status ──────────────────────────────────────

    #[test]
    fn test_is_no_body_status_true_for_101_204_304() {
        assert!(is_no_body_status("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(is_no_body_status("HTTP/1.1 204 No Content\r\n"));
        assert!(is_no_body_status("HTTP/1.1 304 Not Modified\r\n"));
    }

    #[test]
    fn test_is_no_body_status_false_for_200() {
        assert!(!is_no_body_status("HTTP/1.1 200 OK\r\n"));
    }

    // ── is_chunked ─────────────────────────────────────────────

    #[test]
    fn test_is_chunked_detects_transfer_encoding() {
        // The function uses str::lines() which handles both \n and \r\n.
        // Test with just \n to avoid platform-specific line-ending issues.
        assert!(is_chunked("Transfer-Encoding: chunked\n"));
        assert!(is_chunked("transfer-encoding: Chunked\n"));
        assert!(!is_chunked("Content-Length: 100\n"));
    }

    // ── get_content_length ─────────────────────────────────────

    #[test]
    fn test_get_content_length_parses_value() {
        assert_eq!(
            get_content_length("Content-Length: 1024\r\n"),
            Some(1024)
        );
        assert_eq!(
            get_content_length("content-length: 0\r\n"),
            Some(0)
        );
    }

    #[test]
    fn test_get_content_length_missing_returns_none() {
        assert_eq!(get_content_length("Host: example.com\r\n"), None);
    }
}
