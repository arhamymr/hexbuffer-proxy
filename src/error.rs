use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] tokio_rustls::rustls::Error),

    #[error("HTTP error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("invalid HTTP: {0}")]
    Http(#[from] http::Error),

    #[error("certificate error: {0}")]
    Cert(String),

    #[error("connection failed: {0}")]
    Connection(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, ProxyError>;
