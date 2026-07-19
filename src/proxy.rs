use crate::ca::CertificationAuthority;
use crate::parser::parse_connect_request;
use crate::handler::{HttpHandler, HttpContext, RequestOrResponse, Body};

// std
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::net::SocketAddr;

// tokio
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        let target = if host.contains(':') {
            host.clone()
        } else {
            format!("{}:80", host)
        };

        // Handler: request
        let req_id = REQUEST_ID.fetch_add(1, Ordering::SeqCst);
        let mut ctx = HttpContext {
            id: req_id,
            host: host.clone(),
            client_addr,
            is_https: false,
        };

        let modified_bytes = match handler.handle_request(&mut ctx, request).await? {
            RequestOrResponse::Request(req) => serialize_request(&req),
            RequestOrResponse::Response(res) => {
                let res_bytes = serialize_response(&res);
                client_stream.write_all(&res_bytes).await?;
                client_stream.shutdown().await?;
                return Ok(());
            }
        };

        // Connect upstream (plain TCP, no TLS)
        let mut server_stream = TcpStream::connect(&target).await?;
        let forward_bytes = force_connection_close_bytes(&modified_bytes);
        server_stream.write_all(&forward_bytes).await?;

        // Read response
        let mut response_buf = vec![0; buf_size];
        let resp_bytes = server_stream.read(&mut response_buf).await?;
        response_buf.truncate(resp_bytes);

        // Handler: response
        let response = parse_raw_response(&response_buf)?;
        let modified_response = handler.handle_response(&mut ctx, response).await?;
        let final_bytes = serialize_response(&modified_response);

        client_stream.write_all(&final_bytes).await?;
        client_stream.shutdown().await?;
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

    let mut builder = Request::builder().method(method).uri(uri);

    // headers
    for line in lines.by_ref() {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((key, val)) = line.split_once(':') {
            builder = builder.header(key.trim(), val.trim());
        }
    }

    // body: everything after \r\n\r\n
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len());

    let body_bytes = bytes::Bytes::copy_from_slice(&raw[header_end..]);

    Ok(builder.body(Body::Full(body_bytes))?)
}

pub(crate) fn serialize_request(req: &Request<Body>) -> Vec<u8> {
    let mut out = Vec::new();

    // request line
    out.extend_from_slice(req.method().as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(req.uri().to_string().as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    // headers
    for (name, val) in req.headers() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(val.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");

    // body
    if let Body::Full(bytes) = req.body() {
        out.extend_from_slice(bytes);
    }

    out
}

pub(crate) fn parse_raw_response(raw: &[u8]) -> anyhow::Result<Response<Body>> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.lines();

    // status line: "HTTP/1.1 200 OK"
    let status_line = lines.next().unwrap_or("");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);

    let mut builder = Response::builder().status(code);

    // headers
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if let Some((key, val)) = line.split_once(':') {
            builder = builder.header(key.trim(), val.trim());
        }
    }

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len());

    let body_bytes = bytes::Bytes::copy_from_slice(&raw[header_end..]);

    Ok(builder.body(Body::Full(body_bytes))?)
}

pub(crate) fn serialize_response(res: &Response<Body>) -> Vec<u8> {
    let mut out = Vec::new();

    // status line
    let code = res.status();
    out.extend_from_slice(
        format!("HTTP/1.1 {} {}\r\n", code.as_u16(), code.canonical_reason().unwrap_or(""))
            .as_bytes(),
    );

    // headers
    for (name, val) in res.headers() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(val.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");

    if let Body::Full(bytes) = res.body() {
        out.extend_from_slice(bytes);
    }

    out
}

pub(crate) fn force_connection_close_bytes(raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);

    let modified = text
        .replace("Connection: keep-alive", "Connection: close")
        .replace("Connection: Keep-Alive", "Connection: close");

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