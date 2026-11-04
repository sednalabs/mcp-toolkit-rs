#[cfg(feature = "actix-web")]
use actix_web::HttpRequest;

#[cfg(feature = "actix-web")]
use crate::DpopError;

#[cfg(feature = "actix-web")]
/// Return the single DPoP header as &str; error if missing or multiple.
pub fn dpop_header_str(req: &HttpRequest) -> Result<&str, DpopError> {
    // Reject more than one header field
    let mut it = req.headers().get_all("DPoP");
    let first = it.next().ok_or(DpopError::MalformedJws)?;
    if it.next().is_some() {
        return Err(DpopError::MalformedJws);
    }

    // Parse the single header field as a single token68-like value (compact JWS),
    // not a comma-separated list. Also reject padding and whitespace.
    let s = first.to_str().map_err(|_| DpopError::MalformedJws)?;
    if s.contains(',') || s.contains(' ') || s.contains('\t') || s.contains('=') {
        return Err(DpopError::MalformedJws);
    }
    Ok(s)
}

#[cfg(feature = "actix-web")]
/// Construct the expected HTU from an Actix request, considering proxy headers if trust_proxies is true.
pub fn expected_htu_from_actix(req: &actix_web::HttpRequest, trust_proxies: bool) -> String {
    let scheme = if trust_proxies {
        req.headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_ascii_lowercase())
    } else {
        None
    }
    .unwrap_or_else(|| req.connection_info().scheme().to_ascii_lowercase());

    // host (take first in X-Forwarded-Host if present)
    let host = if trust_proxies {
        req.headers()
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
    } else {
        None
    }
    .unwrap_or_else(|| req.connection_info().host().to_string());

    // optional explicit port from X-Forwarded-Port
    let port_opt = if trust_proxies {
        req.headers()
            .get("x-forwarded-port")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u16>().ok())
    } else {
        None
    };

    let path = {
        let p = req.uri().path();
        if p.is_empty() {
            "/"
        } else {
            p
        }
    };

    // Drop default ports; otherwise include
    let is_default =
        (scheme == "http" && port_opt == Some(80)) || (scheme == "https" && port_opt == Some(443));
    let host_lc = host.to_ascii_lowercase();
    if let Some(p) = port_opt {
        if !is_default {
            return format!("{scheme}://{host_lc}:{p}{path}");
        }
    }
    format!("{scheme}://{host_lc}{path}")
}

#[cfg(all(test, feature = "actix-web"))]
mod actix_helper_tests {
    use super::{dpop_header_str, expected_htu_from_actix};
    use actix_web::test;
    use actix_web::test::TestRequest;

    // ---- dpop_header_str ------------------------------------------------------

    #[actix_web::test]
    async fn dpop_header_ok() {
        let req = test::TestRequest::default()
            .insert_header(("DPoP", "abc.def.ghi"))
            .to_http_request();
        assert_eq!(dpop_header_str(&req).unwrap(), "abc.def.ghi");
    }

    #[actix_web::test]
    async fn dpop_header_missing() {
        let req = test::TestRequest::default().to_http_request();
        assert!(dpop_header_str(&req).is_err());
    }

    #[test]
    async fn dpop_header_multiple() {
        // Multiple header fields -> must be rejected
        let req = TestRequest::default()
            .append_header(("DPoP", "v1.header.payload")) // dummy token-ish
            .append_header(("DPoP", "v2.header.payload"))
            .to_http_request();
        assert!(dpop_header_str(&req).is_err());
    }

    #[test]
    async fn dpop_header_single_field_comma_list_rejected() {
        // Single field with comma-separated values -> must be rejected
        let req = TestRequest::default()
            .insert_header(("DPoP", "a.b.c,d.e.f"))
            .to_http_request();
        assert!(dpop_header_str(&req).is_err());
    }

    #[test]
    async fn dpop_header_invalid_token68_ascii() {
        // Padding '=' is not allowed in base64url(no-pad) segments, and spaces are illegal.
        let req = TestRequest::default()
            .insert_header(("DPoP", "abc==")) // ASCII, but invalid for our rules
            .to_http_request();
        assert!(dpop_header_str(&req).is_err());

        let req2 = TestRequest::default()
            .insert_header(("DPoP", "abc def")) // space
            .to_http_request();
        assert!(dpop_header_str(&req2).is_err());

        let req3 = TestRequest::default()
            .insert_header(("DPoP", "abc,def")) // comma (list)
            .to_http_request();
        assert!(dpop_header_str(&req3).is_err());
    }

    // ---- expected_htu_from_actix --------------------------------------------

    #[actix_web::test]
    async fn canonicalize_basic_no_proxy() {
        // Explicit host + non-default port to make the expectation deterministic
        let req = test::TestRequest::default()
            .insert_header(("Host", "api.example.com:8080"))
            .uri("/a")
            .to_http_request();

        let got = expected_htu_from_actix(&req, false);
        assert_eq!(got, "http://api.example.com:8080/a");
    }

    #[actix_web::test]
    async fn canonicalize_uses_x_forwarded_and_drops_default_port() {
        // With X-Forwarded headers present, helper should prefer them,
        // lowercase scheme/host, drop default 443, and ignore query/fragment.
        let req = test::TestRequest::default()
            .insert_header(("Host", "ignored.local:1234"))
            .insert_header(("X-Forwarded-Proto", "HTTPS"))
            .insert_header(("X-Forwarded-Host", "EXAMPLE.COM"))
            .insert_header(("X-Forwarded-Port", "443"))
            .uri("/a/../b?x=1#frag")
            .to_http_request();

        let got = expected_htu_from_actix(&req, true);
        // Note: actix helper does NOT resolve dot-segments (that's done later by normalize_htu).
        assert_eq!(got, "https://example.com/a/../b");
    }
}
