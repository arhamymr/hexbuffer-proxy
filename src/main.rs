use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use http::{Request, Response};

use hexbuffer_proxy::{
    Body, CertificationAuthority, Direction, HttpContext, HttpHandler, ProxyBuilder,
    RequestOrResponse, WebSocketHandler, WebSocketMessage,
};

// ── TLS crypto provider (required by rustls) ──────────────────
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;

// ═══════════════════════════════════════════════════════════════════
// Custom Handlers
// ═══════════════════════════════════════════════════════════════════

// ── LoggingHandler ────────────────────────────────────────────

/// Logs every HTTP request and response with a unique request ID,
/// method, URI, status code, and body size. Runs first in the
/// handler chain so all downstream handlers see the assigned ID.
struct LoggingHandler {
    counter: AtomicU64,
}

impl LoggingHandler {
    fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl HttpHandler for LoggingHandler {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> hexbuffer_proxy::Result<RequestOrResponse> {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        ctx.id = id;

        let https_label = if ctx.is_https { "🔒" } else { "🌐" };
        eprintln!(
            "[#{id:>04}] {https_label} → {method} {uri}",
            method = request.method(),
            uri = request.uri(),
        );

        Ok(RequestOrResponse::Request(request))
    }

    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> hexbuffer_proxy::Result<Response<Body>> {
        let id = ctx.id;
        let status = response.status();

        let size = match response.body() {
            Body::Full(b) => b.len(),
            Body::Streaming(_) => 0,
        };

        let icon = if status.is_server_error() {
            "⚠️"
        } else if status.is_client_error() {
            "✗"
        } else if status.is_redirection() {
            "↪"
        } else {
            "←"
        };

        eprintln!("[#{id:>04}] {icon} {status} ({size} bytes)");

        Ok(response)
    }
}

// ── PassthroughHandler ──────────────────────────────────────

/// Lets CONNECT tunnels bypass MITM for configured domains.
/// Suffix-match: `".google.com"` covers all subdomains.
struct PassthroughHandler {
    passthrough: Vec<String>,
}

#[async_trait]
impl HttpHandler for PassthroughHandler {
    async fn handle_request(
        &self,
        _ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> hexbuffer_proxy::Result<RequestOrResponse> {
        Ok(RequestOrResponse::Request(request))
    }

    async fn handle_response(
        &self,
        _ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> hexbuffer_proxy::Result<Response<Body>> {
        Ok(response)
    }

    async fn should_intercept_tls(&self, host: &str) -> bool {
        for p in &self.passthrough {
            if host == p.as_str() || host.ends_with(&format!(".{p}")) {
                return false;
            }
        }
        true
    }
}

// ── BlocklistHandler ──────────────────────────────────────────

/// Blocks requests to configured host patterns (demo WAF rule).
/// Returns a 403 Forbidden response without contacting the upstream.
struct BlocklistHandler {
    blocked: Vec<String>,
}

#[async_trait]
impl HttpHandler for BlocklistHandler {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> hexbuffer_proxy::Result<RequestOrResponse> {
        for pattern in &self.blocked {
            if ctx.host.contains(pattern.as_str()) {
                eprintln!(
                    "[#{:>04}] 🚫 BLOCKED host=\"{host}\" matches=\"{pattern}\"",
                    ctx.id,
                    host = ctx.host,
                    pattern = pattern,
                );

                let body_text = format!(
                    "Blocked by hexbuffer-proxy\nHost \"{}\" matched blocklist pattern \"{}\"",
                    ctx.host, pattern
                );

                let res = Response::builder()
                    .status(403)
                    .header("Content-Type", "text/plain")
                    .body(Body::Full(body_text.into()))
                    .unwrap();

                return Ok(RequestOrResponse::Response(res));
            }
        }
        Ok(RequestOrResponse::Request(request))
    }

    async fn handle_response(
        &self,
        _ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> hexbuffer_proxy::Result<Response<Body>> {
        Ok(response)
    }
}

// ── WsLogger ──────────────────────────────────────────────────

/// Logs every WebSocket frame passing through the proxy.
struct WsLogger;

#[async_trait]
impl WebSocketHandler for WsLogger {
    async fn on_upgrade(
        &self,
        ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Request<Body> {
        eprintln!(
            "[#{:>04}] 🔌 WebSocket upgrade: {uri}",
            ctx.id,
            uri = request.uri(),
        );
        request
    }

    async fn on_frame(
        &self,
        ctx: &mut HttpContext,
        frame: WebSocketMessage,
        direction: Direction,
    ) -> Option<WebSocketMessage> {
        let dir = match direction {
            Direction::ClientToServer => "C→S",
            Direction::ServerToClient => "S→C",
        };

        let desc = match &frame {
            WebSocketMessage::Text(t) => format!("text({} chars)", t.len()),
            WebSocketMessage::Binary(b) => format!("binary({} bytes)", b.len()),
            WebSocketMessage::Ping(_) => "ping".into(),
            WebSocketMessage::Pong(_) => "pong".into(),
            WebSocketMessage::Close(reason) => {
                format!("close({reason:?})")
            }
            _ => "other".into(),
        };

        eprintln!("[#{:>04}] 🔄 WS {dir} {desc}", ctx.id);
        Some(frame)
    }

    async fn on_close(&self, ctx: &mut HttpContext) {
        eprintln!("[#{:>04}] 🔌 WebSocket closed", ctx.id);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Entry Point
// ═══════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Rustls crypto provider — must be installed before any TLS
    let _ = default_provider().install_default();

    // Certificate authority for on-the-fly TLS cert generation
    let ca = CertificationAuthority::new();

    // ── Build the proxy ───────────────────────────────────────
    //
    // Handler chain (runs in order for requests, reverse for responses):
    //   1. LoggingHandler — assigns request ID, logs every request/response
    //   2. BlocklistHandler — blocks matching hosts with 403
    //
    // WebSocket frames are intercepted by WsLogger.
    let proxy = ProxyBuilder::new()
        .with_ca(ca)
        .with_http_handler(LoggingHandler::new())
        .add_http_handler(PassthroughHandler {
            passthrough: vec![
                "doubleclick.net".into(),
                "google-analytics.com".into(),
                "googletagmanager.com".into(),
            ],
        })
        .add_http_handler(BlocklistHandler {
            blocked: vec![],
        })
        .with_ws_handler(WsLogger)
        .build()?;

    eprintln!("╔══════════════════════════════════════╗");
    eprintln!("║        hexbuffer-proxy v0.1          ║");
    eprintln!("╠══════════════════════════════════════╣");
    eprintln!("║ Listen:  127.0.0.1:8080              ║");
    eprintln!("║ TLS CA:  cert/ca.pem                 ║");
    eprintln!("║ Upstream: Hyper (pooled, HTTP/2)     ║");
    eprintln!("║ Decompress: tower-http (gzip/br/zstd)║");
    eprintln!("║ WAF:      blocklist active           ║");
    eprintln!("║ WS:       frame logger active        ║");
    eprintln!("╚══════════════════════════════════════╝");
    eprintln!();
    eprintln!("Configure your browser to use HTTP proxy at 127.0.0.1:8080");
    eprintln!("Trust cert/ca.pem in your system keychain for HTTPS interception.");
    eprintln!();
    eprintln!("Press Ctrl+C to stop.");

    // Graceful shutdown — proxy runs until Ctrl+C
    tokio::select! {
        result = proxy.start() => {
            if let Err(e) = result {
                eprintln!("Proxy error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!();
            eprintln!("Shutting down...");
        }
    }

    Ok(())
}
