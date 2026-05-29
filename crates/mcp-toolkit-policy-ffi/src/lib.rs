//! # Policy FFI Bridge
//!
//! Foreign Function Interface (FFI) bindings for the SPARK policy kernel.
//!
//! ## Ownership
//! This module owns the dynamic loading of the verified SPARK policy kernel,
//! providing a Rust-safe interface to the FFI-exposed kernel symbols.
//!
//! ## Non-ownership
//! This module does not manage the underlying SPARK policy logic or proof
//! verification; it acts as a thin FFI shim.
//!
//! ## Policy & Guarantees
//! * **Kernel Parity**: Exposes kernel-verified logic with consistent behavior across
//!   Rust and FFI-based integration points.
//! * **Safety**: Provides managed loading and symbol resolution for kernel runtime environments.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Ensuring that the required policy binary (SO/DLL) is available in the environment.
//! * Managing the lifecycle of dynamic loading (FFI) security risks.
//!
//! ## References
//! * `mcp-policy-kernel` (Upstream policy kernel)

pub mod ffi;
mod ffi_loader;
mod ffi_sanity;

pub use ffi::*;
pub use ffi_loader::{
    das_observability_decision, das_query_decision, enforce_claims, gateway_decision, runtime_mode,
    sql_restricted_policy_decision, validate_bearer_header, SparkRuntimeMode,
};
