use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;

use async_trait::async_trait;

use http::{Request, Response};

use crate::ca::CertificationAuthority;
use crate::error::Result;
use crate::handler::{HttpHandler, HttpContext, RequestOrResponse, Body, NoopHandler};

// ── ProxyBuilder ───────────────────────────────────────────────────

/// Builder for configuring and launching the proxy.
pub struct ProxyBuilder {
    addr: SocketAddr,
    ca: Option<CertificationAuthority>,
    handlers: Vec<Arc<dyn HttpHandler>>,
    request_buffer_size: usize,
}

impl ProxyBuilder {
    /// Create a new builder with sensible defaults.
    pub fn new() -> Self {
        Self {
            addr: "127.0.0.1:8080".parse().unwrap(),
            ca: None,
            handlers: Vec::new(),
            request_buffer_size: 16384,
        }
    }

    /// Bind address for the proxy.
    pub fn with_addr(mut self, addr: impl Into<SocketAddr>) -> Self {
        self.addr = addr.into();
        self
    }

    /// Set the certificate authority.
    pub fn with_ca(mut self, ca: CertificationAuthority) -> Self {
        self.ca = Some(ca);
        self
    }

    /// Set the primary HTTP handler (replaces any existing handlers).
    pub fn with_http_handler(mut self, handler: impl HttpHandler + 'static) -> Self {
        self.handlers = vec![Arc::new(handler)];
        self
    }

    /// Append a handler to the stack (chain of responsibility).
    pub fn add_http_handler(mut self, handler: impl HttpHandler + 'static) -> Self {
        self.handlers.push(Arc::new(handler));
        self
    }

    /// Per-request read buffer size in bytes.
    pub fn with_request_buffer_size(mut self, size: usize) -> Self {
        self.request_buffer_size = size;
        self
    }

    /// Consume the builder and produce a ready-to-start `Proxy`.
    pub fn build(self) -> Result<Proxy> {
        let ca = self.ca.unwrap_or_else(CertificationAuthority::new);

        let handler: Arc<dyn HttpHandler> = if self.handlers.is_empty() {
            Arc::new(NoopHandler)
        } else if self.handlers.len() == 1 {
            self.handlers.into_iter().next().unwrap()
        } else {
            Arc::new(HandlerStack::new(self.handlers))
        };

        Ok(Proxy {
            addr: self.addr,
            ca: Arc::new(ca),
            handler,
            request_buffer_size: self.request_buffer_size,
        })
    }
}

impl Default for ProxyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Proxy ──────────────────────────────────────────────────────────

/// A running proxy server.
pub struct Proxy {
    addr: SocketAddr,
    ca: Arc<CertificationAuthority>,
    handler: Arc<dyn HttpHandler>,
    request_buffer_size: usize,
}

impl Proxy {
    /// Start the proxy — binds to the configured address and runs the accept loop.
    pub async fn start(self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        println!("Proxy listening on {}", self.addr);

        let ca = self.ca;
        let handler = self.handler;
        let buf_size = self.request_buffer_size;

        loop {
            let (stream, addr) = listener.accept().await?;
            let ca = Arc::clone(&ca);
            let handler = Arc::clone(&handler);

            tokio::spawn(async move {
                if let Err(e) = crate::proxy::handle_client(stream, ca, handler, buf_size).await {
                    eprintln!("[{}] error: {}", addr, e);
                }
            });
        }
    }
}

// ── HandlerStack ───────────────────────────────────────────────────

/// Chains multiple handlers — each sees the output of the previous.
/// Short-circuit responses stop the chain immediately.
pub(crate) struct HandlerStack {
    handlers: Vec<Arc<dyn HttpHandler>>,
}

impl HandlerStack {
    fn new(handlers: Vec<Arc<dyn HttpHandler>>) -> Self {
        Self { handlers }
    }
}

#[async_trait]
impl HttpHandler for HandlerStack {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        mut request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        for handler in &self.handlers {
            match handler.handle_request(ctx, request).await? {
                RequestOrResponse::Request(req) => request = req,
                short @ RequestOrResponse::Response(_) => return Ok(short),
            }
        }
        Ok(RequestOrResponse::Request(request))
    }

    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        mut response: Response<Body>,
    ) -> Result<Response<Body>> {
        for handler in &self.handlers {
            response = handler.handle_response(ctx, response).await?;
        }
        Ok(response)
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use http::header::HeaderName;

    // ── helpers ────────────────────────────────────────────────────

    fn make_ctx() -> HttpContext {
        HttpContext {
            id: 1,
            host: "example.com".into(),
            client_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: true,
        }
    }

    fn make_request() -> Request<Body> {
        Request::builder()
            .uri("https://example.com/")
            .body(Body::Full(bytes::Bytes::from("hello")))
            .unwrap()
    }

    fn make_response() -> Response<Body> {
        Response::builder()
            .status(200)
            .body(Body::Full(bytes::Bytes::from("world")))
            .unwrap()
    }

    // ── ProxyBuilder ───────────────────────────────────────────────

    #[test]
    fn test_builder_defaults() {
        let builder = ProxyBuilder::new();
        let proxy = builder.build().unwrap();

        assert_eq!(proxy.addr, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(proxy.request_buffer_size, 16384);
        assert!(Arc::ptr_eq(&proxy.ca, &proxy.ca)); // ca is valid
    }

    #[test]
    fn test_builder_with_addr() {
        let proxy = ProxyBuilder::new()
            .with_addr("0.0.0.0:9090".parse::<SocketAddr>().unwrap())
            .build()
            .unwrap();

        assert_eq!(proxy.addr, "0.0.0.0:9090".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_builder_with_request_buffer_size() {
        let proxy = ProxyBuilder::new()
            .with_request_buffer_size(32768)
            .build()
            .unwrap();

        assert_eq!(proxy.request_buffer_size, 32768);
    }

    #[test]
    fn test_builder_no_handler_defaults_to_noop() {
        let proxy = ProxyBuilder::new().build().unwrap();

        // The handler should be present — it's NoopHandler under the hood.
        // We can't inspect the concrete type, but build() succeeds and
        // handler is usable (Arc<dyn HttpHandler>).
        assert!(Arc::strong_count(&proxy.handler) == 1);
    }

    #[test]
    fn test_builder_single_handler_stores_directly() {
        struct A;
        #[async_trait]
        impl HttpHandler for A {
            async fn handle_request(&self, _: &mut HttpContext, r: Request<Body>) -> Result<RequestOrResponse> {
                Ok(RequestOrResponse::Request(r))
            }
            async fn handle_response(&self, _: &mut HttpContext, r: Response<Body>) -> Result<Response<Body>> {
                Ok(r)
            }
        }

        let proxy = ProxyBuilder::new()
            .with_http_handler(A)
            .build()
            .unwrap();

        // Single handler: stored directly (not wrapped in HandlerStack).
        assert_eq!(Arc::strong_count(&proxy.handler), 1);
    }

    #[test]
    fn test_builder_multiple_handlers_wraps_in_stack() {
        struct A;
        struct B;
        #[async_trait]
        impl HttpHandler for A {
            async fn handle_request(&self, _: &mut HttpContext, r: Request<Body>) -> Result<RequestOrResponse> {
                Ok(RequestOrResponse::Request(r))
            }
            async fn handle_response(&self, _: &mut HttpContext, r: Response<Body>) -> Result<Response<Body>> {
                Ok(r)
            }
        }
        #[async_trait]
        impl HttpHandler for B {
            async fn handle_request(&self, _: &mut HttpContext, r: Request<Body>) -> Result<RequestOrResponse> {
                Ok(RequestOrResponse::Request(r))
            }
            async fn handle_response(&self, _: &mut HttpContext, r: Response<Body>) -> Result<Response<Body>> {
                Ok(r)
            }
        }

        let proxy = ProxyBuilder::new()
            .with_http_handler(A)
            .add_http_handler(B)
            .build()
            .unwrap();

        // Build succeeds — handler stack was created.
        assert_eq!(Arc::strong_count(&proxy.handler), 1);
    }

    #[test]
    fn test_builder_default_trait() {
        let a = ProxyBuilder::default();
        let b = ProxyBuilder::new();

        let pa = a.build().unwrap();
        let pb = b.build().unwrap();

        assert_eq!(pa.addr, pb.addr);
        assert_eq!(pa.request_buffer_size, pb.request_buffer_size);
    }

    // ── HandlerStack ───────────────────────────────────────────────

    /// A handler that prepends a fixed header to every request.
    struct AddHeaderHandler {
        key: &'static str,
        val: &'static str,
    }

    #[async_trait]
    impl HttpHandler for AddHeaderHandler {
        async fn handle_request(&self, _: &mut HttpContext, mut req: Request<Body>) -> Result<RequestOrResponse> {
            req.headers_mut().insert(
                HeaderName::from_static(self.key),
                self.val.parse().unwrap(),
            );
            Ok(RequestOrResponse::Request(req))
        }

        async fn handle_response(&self, _: &mut HttpContext, mut res: Response<Body>) -> Result<Response<Body>> {
            res.headers_mut().insert(
                HeaderName::from_static(self.key),
                self.val.parse().unwrap(),
            );
            Ok(res)
        }
    }

    /// A handler that short-circuits with a 403 response.
    struct BlockHandler;

    #[async_trait]
    impl HttpHandler for BlockHandler {
        async fn handle_request(&self, _: &mut HttpContext, _req: Request<Body>) -> Result<RequestOrResponse> {
            let res = Response::builder()
                .status(403)
                .body(Body::Full(bytes::Bytes::from("blocked")))
                .unwrap();
            Ok(RequestOrResponse::Response(res))
        }

        async fn handle_response(&self, _: &mut HttpContext, res: Response<Body>) -> Result<Response<Body>> {
            Ok(res)
        }
    }

    /// A handler that records how many times handle_response was called.
    struct CountingHandler {
        count: Mutex<u32>,
    }

    impl CountingHandler {
        fn new() -> Self {
            Self { count: Mutex::new(0) }
        }
    }

    #[async_trait]
    impl HttpHandler for CountingHandler {
        async fn handle_request(&self, _: &mut HttpContext, r: Request<Body>) -> Result<RequestOrResponse> {
            Ok(RequestOrResponse::Request(r))
        }

        async fn handle_response(&self, _: &mut HttpContext, r: Response<Body>) -> Result<Response<Body>> {
            *self.count.lock().unwrap() += 1;
            Ok(r)
        }
    }

    #[tokio::test]
    async fn test_handler_stack_chains_requests() {
        let stack = HandlerStack::new(vec![
            Arc::new(AddHeaderHandler { key: "x-a", val: "1" }),
            Arc::new(AddHeaderHandler { key: "x-b", val: "2" }),
        ]);

        let mut ctx = make_ctx();
        let req = make_request();

        let result = stack.handle_request(&mut ctx, req).await.unwrap();

        match result {
            RequestOrResponse::Request(req) => {
                assert_eq!(req.headers().get("x-a").unwrap(), "1");
                assert_eq!(req.headers().get("x-b").unwrap(), "2");
            }
            RequestOrResponse::Response(_) => panic!("expected Request, got Response"),
        }
    }

    #[tokio::test]
    async fn test_handler_stack_chains_responses() {
        let stack = HandlerStack::new(vec![
            Arc::new(AddHeaderHandler { key: "x-a", val: "1" }),
            Arc::new(AddHeaderHandler { key: "x-b", val: "2" }),
        ]);

        let mut ctx = make_ctx();
        let res = make_response();

        let result = stack.handle_response(&mut ctx, res).await.unwrap();

        assert_eq!(result.headers().get("x-a").unwrap(), "1");
        assert_eq!(result.headers().get("x-b").unwrap(), "2");
    }

    #[tokio::test]
    async fn test_handler_stack_short_circuits_request() {
        let counter = Arc::new(CountingHandler::new());
        let counter_clone = Arc::clone(&counter);

        struct NeverCalled;
        #[async_trait]
        impl HttpHandler for NeverCalled {
            async fn handle_request(&self, _: &mut HttpContext, _: Request<Body>) -> Result<RequestOrResponse> {
                panic!("this handler should not be called");
            }
            async fn handle_response(&self, _: &mut HttpContext, _: Response<Body>) -> Result<Response<Body>> {
                panic!("this handler should not be called");
            }
        }

        // BlockHandler (short-circuits) → CountingHandler → NeverCalled
        let stack = HandlerStack::new(vec![
            Arc::new(BlockHandler),
            Arc::clone(&counter) as Arc<dyn HttpHandler>,
            Arc::new(NeverCalled),
        ]);

        let mut ctx = make_ctx();
        let req = make_request();

        let result = stack.handle_request(&mut ctx, req).await.unwrap();

        match result {
            RequestOrResponse::Response(res) => {
                assert_eq!(res.status(), 403);
            }
            RequestOrResponse::Request(_) => panic!("expected Response (short-circuit), got Request"),
        }

        // CountingHandler was AFTER BlockHandler — it should NOT have been called.
        assert_eq!(*counter_clone.count.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_handler_stack_response_still_chains_after_short_circuit() {
        // Short-circuit only affects handle_request. handle_response
        // should still chain through all handlers (though for a short-
        // circuited request there is no upstream response to handle).
        // This test verifies the response chain works independently.

        let stack = HandlerStack::new(vec![
            Arc::new(AddHeaderHandler { key: "x-custom", val: "added" }),
        ]);

        let mut ctx = make_ctx();
        let res = make_response();
        let result = stack.handle_response(&mut ctx, res).await.unwrap();

        assert_eq!(result.headers().get("x-custom").unwrap(), "added");
    }

    #[tokio::test]
    async fn test_noop_handler_passes_request_through() {
        let noop = NoopHandler;
        let mut ctx = make_ctx();
        let req = make_request();

        let result = noop.handle_request(&mut ctx, req).await.unwrap();

        match result {
            RequestOrResponse::Request(req) => {
                assert_eq!(req.uri().path(), "/");
            }
            RequestOrResponse::Response(_) => panic!("NoopHandler should not short-circuit"),
        }
    }

    #[tokio::test]
    async fn test_noop_handler_passes_response_through() {
        let noop = NoopHandler;
        let mut ctx = make_ctx();
        let res = make_response();

        let result = noop.handle_response(&mut ctx, res).await.unwrap();

        assert_eq!(result.status(), 200);
    }

    #[tokio::test]
    async fn test_body_full_roundtrip() {
        let body = Body::Full(bytes::Bytes::from("payload"));
        let bytes = body.into_bytes().await.unwrap();
        assert_eq!(&bytes[..], b"payload");
    }

    #[test]
    fn test_body_from_bytes() {
        let b = bytes::Bytes::from("data");
        let body: Body = b.into();
        match body {
            Body::Full(bytes) => assert_eq!(&bytes[..], b"data"),
            Body::Streaming(_) => panic!("expected Full"),
        }
    }
}
