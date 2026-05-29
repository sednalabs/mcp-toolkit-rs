//! # MCP Toolkit Policy Core
//!
//! Pure, deterministic policy primitives shared across MCP services.
//!
//! ## Rationale
//! Consolidate reusable policy contracts and generic authorization helpers into
//! a toolkit-owned crate while treating `mcp-policy-kernel` as the upstream
//! authority for vectors, contracts, and proof artifacts.
//!
//! ## Security Boundaries
//! * No network I/O or database calls.
//! * Decision helpers fail closed on malformed or oversized inputs.
//! * Kernel-owned contract versions and boundary limits are consumed rather than redefined.

pub mod boundary;
pub mod break_glass;
pub mod claims;
pub mod decision;
pub mod embed;
pub mod http_headers;
pub mod http_path;
pub mod sql_read_only;

pub use boundary::{
    list_within_boundary_limits, optional_string_within_boundary_limit,
    string_within_boundary_limit, BOUNDARY_MAX_LIST_LENGTH, BOUNDARY_MAX_STRING_LENGTH,
    PK_ABI_MAJOR, PK_ABI_MINOR,
};
pub use break_glass::{validate_break_glass_allowlist_policy, BreakGlassAllowlistPolicy};
pub use claims::{
    enforce_claims, validate_bearer_header, BearerInput, ClaimsCfg, ClaimsInput,
    MALFORMED_CLAIMS_REASON,
};
pub use decision::{decision_code_catalog, Decision, DecisionCode, DecisionDenyError};
pub use embed::{
    ClaimsCfgBuilder, ClaimsShapeError, EmbeddedPolicyKernel, EmbeddedPolicyKernelBuilder,
    GenericPolicyRequest, RoutePolicy, ScopeRoute,
};
pub use http_headers::{
    is_transport_hop_header, should_forward_request_header, should_forward_response_header,
};
pub use http_path::{
    contains_encoded_delimiter, contains_matrix_params, contains_path_confusion,
    evaluate_http_path, has_path_segment, validate_http_path,
};
pub use sql_read_only::{
    classify_restricted_sql, sql_restricted_policy_decision, validate_restricted_sql,
    RestrictedSqlError, RestrictedSqlErrorCode, SqlRestrictedPolicyInput,
    SQL_POLICY_CONTRACT_VERSION, SQL_POLICY_REASON,
};
