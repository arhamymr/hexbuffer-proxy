use crate::ca::CertificationAuthority;
use crate::parser::parse_connect_request;
use crate::handler::{HttpHandler, HttpContext, RequestOrResponse, Body};

// std
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// tokio
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// http
use http::{Request, Response};

/// Hook point counter for generating unique request IDs.
pub(crate) static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) async fn handle_client(
    mut client_stream: TcpStream,
    ca: Arc<CertificationAuthority>,
    handler: Arc<dyn HttpHandler>,
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
        let Some(target) = parse_connect_request(&request_str) else {
            anyhow::bail!("failed to parse CONNECT target");
        };

        return crate::https_proxy::handle_https(
            client_stream, ca, handler, target, client_addr, buf_size,
        ).await;

    } else {
        // ── Plain HTTP (non-CONNECT) ─────────────────────────
        let request_bytes = request_str.as_bytes();
        let request = parse_raw_request(request_bytes)?;

        // Resolve target from Host header or absolute URI
        let host = extract_host(&request, &request_str)?;

        // Handler: request
        let req_id = REQUEST_ID.fetch_add(1, Ordering::SeqCst);
        let mut ctx = HttpContext {
            id: req_id,
            host: host.clone(),
            client_addr,
            is_https: false,
        };

        let is_ws = crate::ws_proxy::is_websocket_upgrade(&request);

        match handler.handle_request(&mut ctx, request).await? {
            RequestOrResponse::Response(res) => {
                // Short-circuit — respond without contacting upstream
                let res_bytes = serialize_response(&res);
                client_stream.write_all(&res_bytes).await?;
                client_stream.shutdown().await?;
                return Ok(());
            }
            RequestOrResponse::Request(req) => {
                if is_ws {
                    // ── WebSocket: raw TCP relay ──────────────
                    let bytes = serialize_request(&req);
                    let target = if host.contains(':') {
                        host.clone()
                    } else {
                        format!("{}:80", host)
                    };
                    let mut server_stream = TcpStream::connect(&target).await?;
                    server_stream.write_all(&bytes).await?;

                    let full_response = read_full_response(&mut server_stream, buf_size).await?;
                    let response = parse_raw_response(&full_response)?;
                    let modified_response = handler.handle_response(&mut ctx, response).await?;
                    let final_bytes = serialize_response(&modified_response);

                    client_stream.write_all(&final_bytes).await?;
                    if crate::ws_proxy::is_websocket_response(&modified_response) {
                        crate::ws_proxy::relay_websocket(
                            &mut client_stream, &mut server_stream,
                        ).await?;
                    } else {
                        client_stream.shutdown().await?;
                    }
                } else {
                    // ── Normal HTTP: Hyper client ─────────────
                    // (connection pooling, HTTP/2, transparent decompression)
                    let response = crate::upstream::send_request(req).await?;
                    let modified_response = handler.handle_response(&mut ctx, response).await?;
                    let final_bytes = serialize_response(&modified_response);

                    client_stream.write_all(&final_bytes).await?;
                    client_stream.shutdown().await?;
                }
            }
        }
    }

    Ok(())
}


// ── HTTP parse / serialize helpers ────────────────────────────────

/// Extract target host from Host header or absolute URI.
fn extract_host(req: &Request<Body>, raw: &str) -> anyhow::Result<String> {
    // 1. Try Host header
    if let Some(host) = req.headers().get("host").and_then(|v| v.to_str().ok()) {
        return Ok(host.to_string());
    }

    // 2. Fallback: absolute URI (e.g. proxy requests like GET http://example.com/)
    if let Some(uri) = raw.lines().next().and_then(|l| l.split_whitespace().nth(1)) {
        for prefix in &["http://", "https://"] {
            if let Some(rest) = uri.strip_prefix(prefix) {
                return Ok(rest.split('/').next().unwrap_or(rest).to_string());
            }
        }
    }

    anyhow::bail!("could not determine target host — missing Host header");
}

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

    Ok(builder.body(Body::Full(bytes::Bytes::new())).unwrap())
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

    Ok(builder.body(Body::Full(bytes::Bytes::new())).unwrap())
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

#[allow(dead_code)]
pub(crate) fn force_connection_close_bytes(raw: &[u8]) -> Vec<u8> {
    let modified = String::from_utf8_lossy(raw)
        .replace("keep-alive", "close")
        .replace("Keep-Alive", "close");

    if modified.contains("Connection: close") {
        modified.into_bytes()
    } else {
        let mut out = Vec::with_capacity(raw.len() + 24);
        // insert Connection: close before the final \r\n\r\n
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            out.extend_from_slice(&raw[..pos]);
            out.extend_from_slice(b"\r\nConnection: close");
            out.extend_from_slice(&raw[pos..]);
        } else {
            out.extend_from_slice(raw);
        }
        out
    }
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
        .any(|l| l.to_lowercase().starts_with("transfer-encoding:")
             && l.contains("chunked"))
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
