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

// ── WsLogger ──────────────────────────────────────────────────

/// Logs every WebSocket frame passing through the proxy.
struct WsLogger;

#[async_trait]
impl WebSocketHandler for WsLogger {
    async fn on_upgrade(&self, ctx: &mut HttpContext, request: Request<Body>) -> Request<Body> {
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
    // ── Version flag & options ─────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("hexbuffer-proxy v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // ponytail: allow starting in disabled state via --disabled or --disable flag
    let enabled_by_default = !args.iter().any(|a| a == "--disabled" || a == "--disable");

    // Rustls crypto provider — must be installed before any TLS
    let _ = default_provider().install_default();

    // Certificate authority for on-the-fly TLS cert generation
    let ca = CertificationAuthority::new();

    // ── Build the proxy ───────────────────────────────────────
    //
    // Handler chain (runs in order for requests, reverse for responses):
    //   1. LoggingHandler — assigns request ID, logs every request/response
    //   2. PassthroughHandler — skips TLS decryption for ad/tracking domains
    //
    // WebSocket frames are intercepted by WsLogger.
    let proxy = ProxyBuilder::new()
        .with_ca(ca)
        .with_enabled(enabled_by_default)
        .with_http_handler(LoggingHandler::new())
        .add_http_handler(PassthroughHandler {
            passthrough: vec![
                "doubleclick.net".into(),
                "google-analytics.com".into(),
                "googletagmanager.com".into(),
            ],
        })
        .with_ws_handler(WsLogger)
        .build()?;

    let status_str = if enabled_by_default {
        "ENABLED"
    } else {
        "DISABLED"
    };
    eprintln!("╔══════════════════════════════════════╗");
    eprintln!(
        "║  hexbuffer-proxy {:<21}║",
        format!("v{}", env!("CARGO_PKG_VERSION"))
    );
    eprintln!("╠══════════════════════════════════════╣");
    eprintln!("║ Status:  {:<28}║", status_str);
    eprintln!("║ Listen:  127.0.0.1:8080              ║");
    eprintln!("║ TLS CA:  cert/ca.pem                 ║");
    eprintln!("║ Upstream: Hyper (pooled, HTTP/2)     ║");
    eprintln!("║ Decompress: tower-http (gzip/br/zstd)║");
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

// ═══════════════════════════════════════════════════════════════════
// Unit Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> HttpContext {
        HttpContext {
            id: 0,
            host: "example.com".into(),
            client_addr: "127.0.0.1:12345".parse().unwrap(),
            is_https: true,
        }
    }

    #[tokio::test]
    async fn test_logging_handler_assigns_ids_and_handles_traffic() {
        let handler = LoggingHandler::new();
        let mut ctx = make_ctx();

        let req = Request::builder()
            .uri("https://example.com/api")
            .body(Body::Full(bytes::Bytes::from("hello")))
            .unwrap();

        let res_req = handler.handle_request(&mut ctx, req).await.unwrap();
        assert_eq!(ctx.id, 0);

        match res_req {
            RequestOrResponse::Request(r) => assert_eq!(r.uri().path(), "/api"),
            _ => panic!("expected Request"),
        }

        let resp = Response::builder()
            .status(200)
            .body(Body::Full(bytes::Bytes::from("world")))
            .unwrap();

        let res_resp = handler.handle_response(&mut ctx, resp).await.unwrap();
        assert_eq!(res_resp.status(), 200);

        // Next request gets incremented ID
        let req2 = Request::builder()
            .uri("https://example.com/other")
            .body(Body::Full(bytes::Bytes::from("")))
            .unwrap();
        let _ = handler.handle_request(&mut ctx, req2).await.unwrap();
        assert_eq!(ctx.id, 1);
    }

    #[tokio::test]
    async fn test_passthrough_handler_bypasses_configured_domains() {
        let handler = PassthroughHandler {
            passthrough: vec!["doubleclick.net".into(), "google-analytics.com".into()],
        };

        // Exact host match
        assert!(!handler.should_intercept_tls("doubleclick.net").await);

        // Subdomain match
        assert!(!handler.should_intercept_tls("ad.doubleclick.net").await);
        assert!(
            !handler
                .should_intercept_tls("stats.google-analytics.com")
                .await
        );

        // Unmatched host should be intercepted
        assert!(handler.should_intercept_tls("example.com").await);
        assert!(handler.should_intercept_tls("notdoubleclick.net").await);
    }

    #[tokio::test]
    async fn test_ws_logger_frames() {
        let logger = WsLogger;
        let mut ctx = make_ctx();

        let text_frame = WebSocketMessage::Text("hello ws".into());
        let res = logger
            .on_frame(&mut ctx, text_frame.clone(), Direction::ClientToServer)
            .await;
        assert_eq!(res, Some(text_frame));

        let bin_frame = WebSocketMessage::Binary(vec![1, 2, 3].into());
        let res = logger
            .on_frame(&mut ctx, bin_frame.clone(), Direction::ServerToClient)
            .await;
        assert_eq!(res, Some(bin_frame));

        logger.on_close(&mut ctx).await;
    }
}
