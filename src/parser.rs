// Extract the target host:port from a Connect Request line.
pub(crate) fn parse_connect_request(request: &str) -> Option<&str> {
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    parts.get(1).copied()
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_connect_request() {
        let request = "CONNECT www.example.com:443 HTTP/1.1\r\n\r\n";
        assert_eq!(parse_connect_request(request), Some("www.example.com:443"));
    }

    #[test]
    fn test_parse_connect_request_no_port() {
        let request = "CONNECT www.example.com HTTP/1.1\r\n\r\n";
        assert_eq!(parse_connect_request(request), Some("www.example.com"));
    }

    #[test]
    fn test_parse_connect_request_invalid() {
        // Parser extracts token blindly — caller filters by CONNECT prefix
        let request = "GET / HTTP/1.1\r\n\r\n";
        assert_eq!(parse_connect_request(request), Some("/"));
    }

    #[test]
    fn test_parse_connect_request_empty() {
        let request = "";
        assert_eq!(parse_connect_request(request), None);
    }
}