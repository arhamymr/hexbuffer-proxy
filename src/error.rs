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


// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_error_display_io() {
        let err = ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(format!("{err}").contains("I/O error"));
        assert!(format!("{err}").contains("file not found"));
    }

    #[test]
    fn test_proxy_error_display_cert() {
        let err = ProxyError::Cert("bad certificate".into());
        assert_eq!(format!("{err}"), "certificate error: bad certificate");
    }

    #[test]
    fn test_proxy_error_display_connection() {
        let err = ProxyError::Connection("timeout".into());
        assert_eq!(format!("{err}"), "connection failed: timeout");
    }

    #[test]
    fn test_proxy_error_display_protocol() {
        let err = ProxyError::Protocol("bad frame".into());
        assert_eq!(format!("{err}"), "protocol error: bad frame");
    }

    #[test]
    fn test_io_error_auto_conversion() {
        fn io_op() -> std::result::Result<(), std::io::Error> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "fail"))
        }

        fn proxy_op() -> Result<()> {
            io_op()?; // auto-converts via From impl
            Ok(())
        }

        let result = proxy_op();
        assert!(result.is_err());
        match result {
            Err(ProxyError::Io(_)) => {} // correct conversion
            other => panic!("expected Io variant, got {other:?}"),
        }
    }

    #[test]
    fn test_result_type_alias_is_correct() {
        let r: Result<i32> = Ok(42);
        assert_eq!(r.unwrap(), 42);
    }
}
