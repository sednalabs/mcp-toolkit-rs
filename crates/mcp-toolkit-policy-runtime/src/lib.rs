//! # Policy Runtime
//!
//! Stateful runtime helpers for policy enforcement.
//!
//! ## Ownership
//! This module owns the runtime components that interface with policy authorities
//! and capability guards, enabling stateful evaluation of MCP authorization policies.
//!
//! ## Non-ownership
//! This module does not define the fundamental authorization logic or proofs;
//! it facilitates runtime execution of policy constraints.
//!
//! ## Policy & Guarantees
//! * **Stateful Enforcement**: Provides infrastructure for cached and stateful
//!   checks of authorization capabilities.
//! * **Execution Integration**: Connects the generic `mcp-toolkit-policy-core` primitives
//!   with runtime environments.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Initializing the policy authorities with appropriate configurations and scopes.
//! * Ensuring that runtime policy enforcement is integrated correctly with service
//!   startup and request lifecycle.
//!
//! ## References
//! * Policy Kernel: `mcp-policy-kernel` (upstream policy authority)

pub mod capability_guard;
#[cfg(feature = "http")]
pub mod http_policy;
pub mod policy_authority;

pub use capability_guard::{CapabilityGuard, CapabilityGuardError, CapabilityRefreshState};
#[cfg(feature = "http")]
pub use http_policy::{
    policy_authority_decision_ref_from_parts, JsonPolicyDenyHandler, PolicyAuthorityLayer,
    PolicyAuthorityService, PolicyHttpAuthContext, PolicyHttpDenyHandler, PolicyHttpRequestContext,
    PolicyHttpSurfaceContext, PolicyRequestMapper,
};
pub use policy_authority::{
    configured_das_observability_policy_authority, configured_das_query_policy_authority,
    configured_gateway_policy_authority, configured_sql_restricted_policy_authority,
    das_observability_policy_authority, das_query_policy_authority, gateway_policy_authority,
    hello_server_policy_authority, sql_restricted_policy_authority, ClosurePolicyAuthority,
    HelloPolicyRequest, HelloServerProfile, PolicyAuthority, PolicyAuthorityDecision,
    PolicyRuntimeMode, SharedPolicyAuthority,
};
