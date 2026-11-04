//! # Vendored DPoP Verifier
//!
//! Verifies DPoP proofs with upstream nonce policies and a caller-provided replay store.
//!
//! ## Rationale
//! Preserves the upstream API while using the maintained P-256 dependency line.
//! This unpublished compatibility copy is maintained within MCP Toolkit.
//!
//! ## Security Boundaries
//! Performs proof validation without network I/O. Callers supply trusted request
//! context, enforce access-token key binding, and provide atomic replay storage.
//! The cryptographic dependency port does not redesign upstream validation policy.
//!
//! ## References
//! * **SPEC**: [DPoP, RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)
//! * **DESIGN**: `docs/design/dpop-verifier-custody.md`
//! * **PROVENANCE**: `vendor/dpop-verifier/UPSTREAM.md`
//!
//! ```
//! use dpop_verifier::DpopVerifier;
//!
//! let verifier = DpopVerifier::new()
//!     .with_max_age_seconds(300)
//!     .with_future_skew_seconds(5);
//! # let _ = verifier;
//! ```

pub mod error;
pub mod jwk;
pub mod nonce;
pub mod replay;
pub mod uri;
pub mod verify;

#[cfg(feature = "actix-web")]
pub mod actix_helpers;

pub use error::DpopError;
pub use jwk::{thumbprint_ec_p256, verifying_key_from_p256_xy};
pub use nonce::IntoSecretBox;
pub use replay::{ReplayContext, ReplayStore};
// Keep the deprecated entry point available to existing downstream callers.
#[allow(
    deprecated,
    reason = "Preserve the upstream public compatibility re-export"
)]
pub use verify::verify_proof;
pub use verify::{ClientBinding, DpopVerifier, HmacConfig, NonceMode, VerifiedDpop, VerifyOptions};
