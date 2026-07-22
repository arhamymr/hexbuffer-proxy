// hexbuffer-proxy — HTTPS MITM proxy library
//
// Core modules
//! # hexbuffer-proxy
//!
//! A local MITM (man-in-the-middle) HTTP/HTTPS proxy
//! built on Tokio + Hyper + rustls.
//!
//! ## Architecture
//!
//! - [`ProxyBuilder`] assembles the proxy with custom handlers.
//! - [`HttpHandler`] is the core trait — implement it to inspect or
//!   mutate traffic.
//! - HTTPS is intercepted via on-the-fly TLS certificate forging
//!   (powered by [`CertificationAuthority`]).
//! - Decrypted inner traffic is served by Hyper's HTTP/1.1 server
//!   (keep-alive, body framing, pipelining).
//! - Plain HTTP requests are handled by the same handler pipeline.
//! - WebSocket connections are detected, relayed, and optionally
//!   intercepted frame-by-frame via [`WebSocketHandler`].

pub mod ca;
pub mod error;
pub mod handler;
pub mod builder;

// Optional application-level body decoder
#[cfg(feature = "decoder")]
pub mod decoder;

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
