use tokio_tungstenite::tungstenite::http;

/// Validates the bearer token from a WebSocket upgrade request.
///
/// If `expected_token` is `None`, all connections are allowed (open mode).
/// If `expected_token` is `Some(token)`, the request must include a matching
/// `Authorization: Bearer <token>` header.
pub fn validate_bearer_token(request: &http::Request<()>, expected_token: Option<&str>) -> bool {
    let expected = match expected_token {
        Some(t) => t,
        None => return true, // No auth configured, allow all.
    };

    let header = match request.headers().get(http::header::AUTHORIZATION) {
        Some(h) => h,
        None => return false,
    };

    let value = match header.to_str() {
        Ok(v) => v,
        Err(_) => return false,
    };

    if let Some(token) = value.strip_prefix("Bearer ") {
        constant_time_eq(token.as_bytes(), expected.as_bytes())
    } else {
        false
    }
}

/// Constant-time byte comparison to prevent timing attacks on token validation.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::http::Request;

    fn make_request(auth_header: Option<&str>) -> Request<()> {
        let mut builder = Request::builder().uri("ws://localhost/");
        if let Some(val) = auth_header {
            builder = builder.header("Authorization", val);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn no_token_configured_allows_all() {
        let req = make_request(None);
        assert!(validate_bearer_token(&req, None));
    }

    #[test]
    fn no_token_configured_allows_with_header() {
        let req = make_request(Some("Bearer something"));
        assert!(validate_bearer_token(&req, None));
    }

    #[test]
    fn valid_token_accepted() {
        let req = make_request(Some("Bearer my-secret-token"));
        assert!(validate_bearer_token(&req, Some("my-secret-token")));
    }

    #[test]
    fn wrong_token_rejected() {
        let req = make_request(Some("Bearer wrong-token"));
        assert!(!validate_bearer_token(&req, Some("correct-token")));
    }

    #[test]
    fn missing_header_rejected_when_token_required() {
        let req = make_request(None);
        assert!(!validate_bearer_token(&req, Some("my-token")));
    }

    #[test]
    fn non_bearer_scheme_rejected() {
        let req = make_request(Some("Basic dXNlcjpwYXNz"));
        assert!(!validate_bearer_token(&req, Some("my-token")));
    }

    #[test]
    fn empty_bearer_token_rejected() {
        let req = make_request(Some("Bearer "));
        assert!(!validate_bearer_token(&req, Some("my-token")));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
