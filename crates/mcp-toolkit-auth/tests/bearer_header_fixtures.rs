//! Cross-language header vectors for the toolkit's strict extraction profile.
//! These tests exercise extraction, not token validity or authentication.

use std::collections::HashSet;

use http::{HeaderMap, HeaderName, HeaderValue};
use mcp_toolkit_auth::parse_strict_bearer_authorization;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema_version: u32,
    profile: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    headers: Vec<Header>,
    token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    name: String,
    value_bytes: Vec<u8>,
}

#[test]
fn strict_bearer_header_corpus_matches_public_parser() {
    let corpus: Corpus = serde_json::from_str(include_str!("fixtures/strict-bearer-v1.json"))
        .expect("valid fixture corpus");
    assert_eq!(corpus.schema_version, 1);
    assert_eq!(corpus.profile, "toolkit-strict-bearer-v1");
    assert_eq!(corpus.cases.len(), 21);
    let mut ids = HashSet::new();

    for case in corpus.cases {
        assert!(ids.insert(case.id.clone()), "duplicate fixture id");
        assert_ne!(case.token.is_some(), case.error.is_some(), "{}", case.id);
        let mut headers = HeaderMap::new();
        for header in case.headers {
            let name = HeaderName::from_bytes(header.name.as_bytes()).expect("valid header name");
            let value = HeaderValue::from_bytes(&header.value_bytes).expect("valid HTTP field bytes");
            // Append preserves repeated fields, including case-normalized names.
            // Inserting into a map would erase the ambiguity being tested.
            headers.append(name, value);
        }
        let parsed = parse_strict_bearer_authorization(&headers);
        for rendered in [format!("{parsed:?}"), format!("{parsed:#?}")] {
            assert!(!rendered.contains("fixture-secret"), "{}", case.id);
        }
        match parsed {
            Ok(token) => {
                assert_eq!(Some(token.as_str()), case.token.as_deref(), "{}", case.id);
                assert!(case.error.is_none(), "{}", case.id);
            }
            Err(error) => {
                assert_eq!(Some(format!("{error:?}")), case.error, "{}", case.id);
                assert!(case.token.is_none(), "{}", case.id);
                assert!(!error.to_string().contains("fixture-secret"), "{}", case.id);
            }
        }
    }
}
