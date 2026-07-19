use crate::handler::{HttpHandler, HttpContext, RequestOrResponse, Body, WebSocketHandler};
use crate::proxy;

// std
use std::sync::Arc;
use std::sync::atomic::Ordering;

// tokio
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

// http
use http::Request;

/// Handle a plain HTTP request (non-CONNECT).
pub(crate) async fn handle_http(
    mut client_stream: TcpStream,
    handler: Arc<dyn HttpHandler>,
    ws_handler: Option<Arc<dyn WebSocketHandler>>,
    client_addr: std::net::SocketAddr,
    buf_size: usize,
    request_str: String,
) -> anyhow::Result<()> {
    let request_bytes = request_str.as_bytes();
    let request = proxy::parse_raw_request(request_bytes)?;

    // Resolve target from Host header or absolute URI
    let host = match extract_host(&request, &request_str) {
        Ok(h) => h,
        Err(_) => {
            client_stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            client_stream.shutdown().await?;
            return Ok(());
        }
    };

    // Handler: request
    let req_id = proxy::REQUEST_ID.fetch_add(1, Ordering::SeqCst);
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
            let res_bytes = proxy::serialize_response(&res);
            client_stream.write_all(&res_bytes).await?;
            client_stream.shutdown().await?;
            Ok(())
        }
        RequestOrResponse::Request(mut req) => {
            if is_ws {
                // ── WebSocket: raw TCP relay ──────────────
                let bytes = proxy::serialize_request(&req);
                let target = if host.contains(':') {
                    host.clone()
                } else {
                    format!("{}:80", host)
                };
                let mut server_stream = TcpStream::connect(&target).await?;
                server_stream.write_all(&bytes).await?;

                let full_response = proxy::read_full_response(&mut server_stream, buf_size).await?;
                let response = proxy::parse_raw_response(&full_response)?;
                let modified_response = handler.handle_response(&mut ctx, response).await?;
                let final_bytes = proxy::serialize_response(&modified_response);

                client_stream.write_all(&final_bytes).await?;
                if crate::ws_proxy::is_websocket_response(&modified_response) {
                    if let Some(ws) = ws_handler {
                        crate::ws_proxy::relay_framed(
                            client_stream, server_stream, ws, &mut ctx,
                        ).await?;
                    } else {
                        crate::ws_proxy::relay_websocket(
                            &mut client_stream, &mut server_stream,
                        ).await?;
                    }
                } else {
                    client_stream.shutdown().await?;
                }
            } else {
                // ── Normal HTTP: Hyper client ─────────────
                // (connection pooling, HTTP/2, transparent decompression)

                // Hyper requires absolute URI for forward proxy requests.
                if req.uri().scheme().is_none() {
                    let uri: http::Uri = format!("http://{}{}", host, req.uri())
                        .parse()
                        .map_err(|e| anyhow::anyhow!("invalid absolute URI: {e}"))?;
                    *req.uri_mut() = uri;
                }

                let response = crate::upstream::send_request(req).await?;
                let modified_response = handler.handle_response(&mut ctx, response).await?;
                let final_bytes = proxy::serialize_response(&modified_response);

                client_stream.write_all(&final_bytes).await?;
                client_stream.shutdown().await?;
            }
            Ok(())
        }
    }
}

// ── HTTP helpers ─────────────────────────────────────────────────

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

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_host ──────────────────────────────────────────

    #[test]
    fn test_extract_host_from_host_header() {
        let raw = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
        let req = proxy::parse_raw_request(raw).unwrap();
        let host = extract_host(&req, std::str::from_utf8(raw).unwrap()).unwrap();
        assert_eq!(host, "www.example.com");
    }

    #[test]
    fn test_extract_host_from_absolute_uri() {
        let raw = b"GET http://api.example.com/v1/data HTTP/1.1\r\n\r\n";
        let req = proxy::parse_raw_request(raw).unwrap();
        let host = extract_host(&req, std::str::from_utf8(raw).unwrap()).unwrap();
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn test_extract_host_missing_errors() {
        let raw = b"GET / HTTP/1.1\r\n\r\n";
        let req = proxy::parse_raw_request(raw).unwrap();
        let result = extract_host(&req, std::str::from_utf8(raw).unwrap());
        assert!(result.is_err());
    }

    // ── force_connection_close_bytes ──────────────────────────

    #[test]
    fn test_force_connection_close_replaces_keep_alive() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        let modified = force_connection_close_bytes(raw);
        let text = String::from_utf8_lossy(&modified);
        assert!(text.contains("Connection: close"));
        assert!(!text.contains("keep-alive"));
    }

    #[test]
    fn test_force_connection_close_inserts_when_missing() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let modified = force_connection_close_bytes(raw);
        let text = String::from_utf8_lossy(&modified);
        assert!(text.contains("Connection: close"));
    }
}
