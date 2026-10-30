//! Downstream Git consumer regression fixture, not a production replay store.
//!
//! Uses the toolkit's signer and canonical verifier; no local JOSE/crypto code.
//! Credentials and keys are synthetic and never sent to a network provider.
#![cfg(test)]

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Method};
use jsonwebtoken::{encode, EncodingKey, Header};
use mcp_toolkit_auth::dpop_verifier::{
    DpopError, DpopVerifier, HmacConfig, NonceMode, ReplayContext, ReplayStore,
};
use mcp_toolkit_auth::outbound_dpop::{DpopSigner, OutboundDpopProof};
use mcp_toolkit_auth::upstream_oauth::SecretString;
use mcp_toolkit_auth::{
    parse_strict_dpop_authorization, parse_strict_dpop_proof, AuthConfig, AuthMode, Authenticator,
    SenderConstrainedAuthError, VerifiedAuthContext,
};
use serde_json::json;

const URI: &str = "https://resource.example.test/mcp";
const SECRET: &str = "synthetic-git-consumer-test-secret";
const CLIENT: &str = "synthetic-client";

#[derive(Default)]
struct Store {
    entries: HashSet<[u8; 32]>,
    calls: usize,
    fail: bool,
}

#[async_trait::async_trait]
impl ReplayStore for Store {
    async fn insert_once(
        &mut self,
        jti_hash: [u8; 32],
        context: ReplayContext<'_>,
    ) -> Result<bool, DpopError> {
        self.calls += 1;
        assert!(context.jkt.is_some());
        assert!(context.htm.is_some());
        assert!(context.htu.is_some());
        assert!(context.iat > 0);
        if self.fail {
            return Err(DpopError::Store(Box::new(std::io::Error::other(
                "synthetic store fault",
            ))));
        }
        Ok(self.entries.insert(jti_hash))
    }
}

fn token(signer: &DpopSigner) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    encode(
        &Header::default(),
        &json!({"sub": "synthetic-subject", "iss": "synthetic-issuer",
            "aud": "synthetic-audience", "iat": now, "exp": now + 600,
            "jti": "synthetic-access-token-jti",
            "cnf": {"jkt": signer.public_jwk().thumbprint()}}),
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap()
}

fn authenticator() -> Authenticator {
    Authenticator::new(AuthConfig {
        mode: AuthMode::Delegation,
        delegation_secret: Some(SECRET.to_owned()),
        delegation_issuer: "synthetic-issuer".into(),
        delegation_audience: "synthetic-audience".into(),
        jti_enforce_bearer: false,
        required_scopes: Vec::new(),
        ..AuthConfig::default()
    })
    .unwrap()
}

fn proof(
    signer: &DpopSigner,
    token: &str,
    request: (&str, &str),
    nonce: Option<&str>,
) -> OutboundDpopProof {
    signer
        .resource_proof(
            Method::from_bytes(request.0.as_bytes()).unwrap(),
            &request.1.parse().unwrap(),
            &SecretString::new(token),
            nonce,
        )
        .unwrap()
}

async fn authenticate(
    auth: &Authenticator,
    token: &str,
    proof: &OutboundDpopProof,
    request: (&str, &str),
    verifier: &DpopVerifier,
    store: &mut Store,
) -> Result<VerifiedAuthContext, SenderConstrainedAuthError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("DPoP {token}")).unwrap(),
    );
    headers.insert(
        "dpop",
        HeaderValue::from_str(proof.expose_secret()).unwrap(),
    );
    auth.authenticate_sender_constrained_dpop(
        parse_strict_dpop_authorization(&headers).unwrap(),
        parse_strict_dpop_proof(&headers).unwrap(),
        request.1,
        request.0,
        verifier,
        store,
    )
    .await
}

#[tokio::test]
async fn public_types_support_signed_proof_replay_and_bearer_rejection() {
    let auth = authenticator();
    let signer = DpopSigner::generate().unwrap();
    let token = token(&signer);
    let proof = proof(&signer, &token, ("POST", URI), None);
    let verifier = DpopVerifier::new();
    let mut store = Store::default();
    let verified = authenticate(&auth, &token, &proof, ("POST", URI), &verifier, &mut store)
        .await
        .unwrap();
    assert!(verified.is_issued_by(&auth));
    assert_eq!(
        verified.context().subject.as_deref(),
        Some("synthetic-subject")
    );
    assert!(matches!(
        authenticate(&auth, &token, &proof, ("POST", URI), &verifier, &mut store).await,
        Err(SenderConstrainedAuthError::Dpop(DpopError::Replay))
    ));
    assert!(auth
        .authenticate_token(&HeaderMap::new(), &token)
        .await
        .is_err());
}

#[tokio::test]
async fn wrong_key_does_not_pollute_replay_and_store_failure_remains_typed() {
    let auth = authenticator();
    let signer = DpopSigner::generate().unwrap();
    let other_signer = DpopSigner::generate().unwrap();
    let token = token(&signer);
    let wrong_key = proof(&other_signer, &token, ("POST", URI), None);
    let verifier = DpopVerifier::new();
    let mut store = Store::default();
    assert!(matches!(
        authenticate(
            &auth,
            &token,
            &wrong_key,
            ("POST", URI),
            &verifier,
            &mut store
        )
        .await,
        Err(SenderConstrainedAuthError::Authentication(_))
    ));
    assert_eq!(store.calls, 0);
    store.fail = true;
    let valid = proof(&signer, &token, ("POST", URI), None);
    assert!(matches!(
        authenticate(&auth, &token, &valid, ("POST", URI), &verifier, &mut store).await,
        Err(SenderConstrainedAuthError::Dpop(DpopError::Store(_)))
    ));
    assert!(store.entries.is_empty());
}

#[tokio::test]
async fn request_and_access_token_binding_precede_replay_admission() {
    let auth = authenticator();
    let signer = DpopSigner::generate().unwrap();
    let token = token(&signer);
    let valid = proof(&signer, &token, ("POST", URI), None);
    let verifier = DpopVerifier::new();
    let mut store = Store::default();
    for request in [
        ("GET", URI),
        ("POST", "https://resource.example.test/other"),
    ] {
        assert!(
            authenticate(&auth, &token, &valid, request, &verifier, &mut store)
                .await
                .is_err()
        );
    }
    let other_token = proof(&signer, "different-synthetic-token", ("POST", URI), None);
    assert!(matches!(
        authenticate(
            &auth,
            &token,
            &other_token,
            ("POST", URI),
            &verifier,
            &mut store
        )
        .await,
        Err(SenderConstrainedAuthError::Dpop(DpopError::AthMismatch))
    ));
    assert_eq!(store.calls, 0);
}

fn hmac_verifier(client: &str) -> DpopVerifier {
    DpopVerifier::new()
        .with_max_age_seconds(300)
        .with_future_skew_seconds(5)
        .with_client_binding(client)
        .with_nonce_mode(NonceMode::Hmac(HmacConfig::new(
            b"synthetic-nonce-secret-not-production",
            300,
            true,
            true,
            true,
        )))
}

#[tokio::test]
async fn hmac_nonce_challenge_preserves_key_request_and_client_binding() {
    let auth = authenticator();
    let signer = DpopSigner::generate().unwrap();
    let token = token(&signer);
    let mut store = Store::default();
    let verifier = hmac_verifier(CLIENT);
    let missing = proof(&signer, &token, ("POST", URI), None);
    let nonce = match authenticate(
        &auth,
        &token,
        &missing,
        ("POST", URI),
        &verifier,
        &mut store,
    )
    .await
    {
        Err(SenderConstrainedAuthError::Dpop(DpopError::UseDpopNonce { nonce })) => nonce,
        _ => panic!("expected a typed nonce challenge"),
    };
    assert_eq!(store.calls, 0);

    for request in [
        ("GET", URI),
        ("POST", "https://resource.example.test/other"),
    ] {
        let changed = proof(&signer, &token, request, Some(&nonce));
        assert!(matches!(
            authenticate(&auth, &token, &changed, request, &verifier, &mut store).await,
            Err(SenderConstrainedAuthError::Dpop(
                DpopError::UseDpopNonce { .. }
            ))
        ));
    }
    let other_signer = DpopSigner::generate().unwrap();
    let other_token = self::token(&other_signer);
    let changed = proof(&other_signer, &other_token, ("POST", URI), Some(&nonce));
    assert!(matches!(
        authenticate(
            &auth,
            &other_token,
            &changed,
            ("POST", URI),
            &verifier,
            &mut store
        )
        .await,
        Err(SenderConstrainedAuthError::Dpop(
            DpopError::UseDpopNonce { .. }
        ))
    ));
    let valid = proof(&signer, &token, ("POST", URI), Some(&nonce));
    assert!(matches!(
        authenticate(
            &auth,
            &token,
            &valid,
            ("POST", URI),
            &hmac_verifier("other-client"),
            &mut store
        )
        .await,
        Err(SenderConstrainedAuthError::Dpop(
            DpopError::UseDpopNonce { .. }
        ))
    ));
    assert_eq!(store.calls, 0);
    authenticate(&auth, &token, &valid, ("POST", URI), &verifier, &mut store)
        .await
        .unwrap();
    assert_eq!(store.calls, 1);
}
