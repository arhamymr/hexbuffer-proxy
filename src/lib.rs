// hexbuffer-proxy — HTTPS MITM proxy library
//
// Core modules
pub mod ca;
pub mod error;
pub mod handler;
pub mod builder;

// Internal modules
mod proxy;
mod http_proxy;
mod https_proxy;
mod ws_proxy;
mod upstream;

// Re-export public API at crate root
pub use builder::{ProxyBuilder, Proxy};
pub use handler::{
    HttpHandler, HttpContext, Body, RequestOrResponse, NoopHandler, full_body,
    WebSocketHandler, Direction, WebSocketMessage, NoopWebSocketHandler,
};
pub use error::{ProxyError, Result};
pub use ca::CertificationAuthority;
