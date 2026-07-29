//! # Receipt Contract Assertions
//!
//! Generic test helpers for validating mutation receipt cardinality, identity,
//! and serialized size contracts.
//!
//! ## Rationale
//! A mutation result is useful to callers only when its identity can be
//! unambiguously matched to the requested target. These assertions keep that
//! check domain-neutral: applications define their own identity extraction and
//! expected identity set.
//!
//! ## Security Boundaries
//! * Test-only helpers; they do not validate or sanitize production responses.
//! * Errors produced by an identity extractor remain caller-defined and are
//!   reported only in the test process.

use serde::Serialize;
use std::collections::BTreeSet;
use std::fmt::Debug;

/// Asserts that receipts contain exactly the expected unique identities.
///
/// The identity extractor must reject malformed or contradictory identity
/// representations for its domain. Each observed identity must occur once and
/// belong to `expected_identities`; the observed receipt count must also match
/// the expected set cardinality exactly.
///
/// ```
/// use mcp_toolkit_testing::receipt_contract::assert_exact_receipt_identity_set;
/// use std::collections::BTreeSet;
///
/// let receipts = ["alpha", "beta"];
/// let expected = BTreeSet::from(["alpha", "beta"]);
/// assert_exact_receipt_identity_set(&receipts, &expected, |receipt| {
///     Ok::<_, &'static str>(*receipt)
/// });
/// ```
///
/// # Panics
/// Panics when the expected set is empty, receipt cardinality differs, the
/// extractor rejects an identity, an identity is duplicated or unexpected, or
/// an expected identity is missing.
pub fn assert_exact_receipt_identity_set<T, I, E, F>(
    receipts: &[T],
    expected_identities: &BTreeSet<I>,
    mut extract_identity: F,
) where
    I: Ord + Debug,
    E: Debug,
    F: FnMut(&T) -> Result<I, E>,
{
    assert!(
        !expected_identities.is_empty(),
        "receipt identity contract must declare at least one expected identity"
    );
    assert_eq!(
        receipts.len(),
        expected_identities.len(),
        "receipt identity cardinality differs: expected {}, observed {}",
        expected_identities.len(),
        receipts.len()
    );

    let mut observed = BTreeSet::new();
    for (index, receipt) in receipts.iter().enumerate() {
        let identity = extract_identity(receipt).unwrap_or_else(|error| {
            panic!(
                "receipt identity extractor rejected receipt at index {index}; \
                 extractors must reject malformed or contradictory identities: {error:?}"
            )
        });
        assert!(
            expected_identities.contains(&identity),
            "receipt identity contract contains unexpected identity {identity:?}; expected {expected_identities:?}"
        );
        assert!(
            !observed.contains(&identity),
            "receipt identity contract contains duplicate identity {identity:?} at index {index}"
        );
        observed.insert(identity);
    }

    let missing = expected_identities
        .difference(&observed)
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "receipt identity contract is missing expected identities {missing:?}; observed {observed:?}"
    );
}

/// Asserts that exactly one receipt resolves to the expected identity.
///
/// This convenience assertion is appropriate when a mutation contract promises
/// one receipt. For multi-receipt contracts, use
/// [`assert_exact_receipt_identity_set`].
///
/// # Panics
/// Panics when zero or multiple receipts are supplied, or when the sole receipt
/// does not satisfy the exact identity contract.
pub fn assert_exactly_one_receipt_identity<T, I, E, F>(
    receipts: &[T],
    expected_identity: I,
    extract_identity: F,
) where
    I: Ord + Debug,
    E: Debug,
    F: FnMut(&T) -> Result<I, E>,
{
    assert_eq!(
        receipts.len(),
        1,
        "receipt identity contract requires exactly one receipt, observed {}",
        receipts.len()
    );
    assert_exact_receipt_identity_set(
        receipts,
        &BTreeSet::from([expected_identity]),
        extract_identity,
    );
}

/// Serializes a payload as deterministically canonical JSON bytes.
///
/// Object keys use the same canonicalization as JSON contract snapshots, while
/// array order remains unchanged.
///
/// # Errors
/// Returns [`serde_json::Error`] when `payload` cannot be converted to JSON.
pub fn canonical_json_bytes<T>(payload: &T) -> Result<Vec<u8>, serde_json::Error>
where
    T: Serialize,
{
    let value = crate::canonicalize_json(serde_json::to_value(payload)?);
    serde_json::to_vec(&value)
}

/// Asserts that a receipt fits within its canonical JSON byte budget.
///
/// # Panics
/// Panics when serialization fails or the canonical JSON encoding exceeds
/// `max_bytes`.
pub fn assert_serialized_receipt_within_byte_budget<T>(receipt: &T, max_bytes: usize)
where
    T: Serialize,
{
    let bytes = canonical_json_bytes(receipt).unwrap_or_else(|error| {
        panic!("failed to serialize receipt for byte-budget assertion: {error}")
    });
    assert!(
        bytes.len() <= max_bytes,
        "serialized receipt is {} bytes, exceeding its {}-byte budget",
        bytes.len(),
        max_bytes
    );
}

#[cfg(test)]
mod tests {
    use super::{
        assert_exact_receipt_identity_set, assert_exactly_one_receipt_identity,
        assert_serialized_receipt_within_byte_budget, canonical_json_bytes,
    };
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[derive(Debug)]
    struct Receipt {
        identity: String,
        claimed_identity: String,
    }

    fn identity(receipt: &Receipt) -> Result<String, &'static str> {
        if receipt.identity == receipt.claimed_identity {
            Ok(receipt.identity.clone())
        } else {
            Err("receipt exposes contradictory identity values")
        }
    }

    fn receipt(identity: &str) -> Receipt {
        Receipt {
            identity: identity.to_string(),
            claimed_identity: identity.to_string(),
        }
    }

    #[test]
    fn accepts_exact_identity_set_and_canonical_compact_receipt() {
        let receipts = [receipt("alpha"), receipt("beta")];
        let expected = BTreeSet::from(["alpha".to_string(), "beta".to_string()]);
        assert_exact_receipt_identity_set(&receipts, &expected, identity);

        let payload = json!({"z": {"b": 2, "a": 1}, "a": ["receipt"]});
        let bytes = canonical_json_bytes(&payload).expect("canonical JSON");
        assert_eq!(bytes, br#"{"a":["receipt"],"z":{"a":1,"b":2}}"#.to_vec());
        assert_serialized_receipt_within_byte_budget(&payload, bytes.len());
    }

    #[test]
    fn rejects_zero_and_multiple_receipts_for_single_receipt_contract() {
        assert!(catch_unwind(AssertUnwindSafe(|| {
            assert_exactly_one_receipt_identity::<Receipt, _, _, _>(
                &[],
                "alpha".to_string(),
                identity,
            );
        }))
        .is_err());

        let receipts = [receipt("alpha"), receipt("beta")];
        assert!(catch_unwind(AssertUnwindSafe(|| {
            assert_exactly_one_receipt_identity(&receipts, "alpha".to_string(), identity);
        }))
        .is_err());
    }

    #[test]
    fn rejects_duplicate_contradictory_and_unexpected_identities() {
        let expected = BTreeSet::from(["alpha".to_string(), "beta".to_string()]);
        let duplicates = [receipt("alpha"), receipt("alpha")];
        assert!(catch_unwind(AssertUnwindSafe(|| {
            assert_exact_receipt_identity_set(&duplicates, &expected, identity);
        }))
        .is_err());

        let contradictory = [
            Receipt {
                identity: "alpha".to_string(),
                claimed_identity: "beta".to_string(),
            },
            receipt("beta"),
        ];
        assert!(catch_unwind(AssertUnwindSafe(|| {
            assert_exact_receipt_identity_set(&contradictory, &expected, identity);
        }))
        .is_err());

        let unexpected = [receipt("alpha"), receipt("gamma")];
        assert!(catch_unwind(AssertUnwindSafe(|| {
            assert_exact_receipt_identity_set(&unexpected, &expected, identity);
        }))
        .is_err());
    }

    #[test]
    fn rejects_receipts_that_exceed_the_canonical_byte_budget() {
        let payload = json!({"receipt": "alpha"});
        let bytes = canonical_json_bytes(&payload).expect("canonical JSON");
        assert!(catch_unwind(|| {
            assert_serialized_receipt_within_byte_budget(&payload, bytes.len() - 1);
        })
        .is_err());
    }
}
