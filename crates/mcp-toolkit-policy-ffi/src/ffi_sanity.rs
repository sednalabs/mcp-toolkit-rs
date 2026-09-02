//! # ABI Sanity Checks
//!
//! Build-time validation for C-compatible structure memory layouts.
//!
//! ## Ownership
//! This module owns the static assertions that verify structural alignment and
//! size parity between the Rust `ffi` definitions and the expected C ABI.
//!
//! ## Non-ownership
//! This module does not provide runtime functionality; it acts as a build-time
//! safety gate to prevent ABI-related memory errors.
//!
//! ## Policy & Guarantees
//! * **Layout Parity**: Ensures that FFI structures maintain identical binary
//!   layouts across platform-specific compiler representations, protecting
//!   against silent memory corruption.
//!
//! ## Caller Responsibility
//! This module runs automatically during compilation. No manual invocation is required.
//!
//! ## References
//! * [Rust ABI Guarantees (repr(C))]

use core::mem::{align_of, size_of};
use std::os::raw::{c_char, c_int};

use crate::ffi::{
    PkAbiVersion, PkAudClaim, PkAudKind, PkDecision, PkDecisionCode, PkOptStr, PkStrList, PkStrView,
};

// ... internal helper and assertion logic ...

#[allow(dead_code)]
const fn align_up(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
}

#[allow(dead_code)]
const fn max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

#[allow(dead_code)]
const fn c_struct_size_2(size1: usize, align1: usize, size2: usize, align2: usize) -> usize {
    let offset2 = align_up(size1, align2);
    let size = offset2 + size2;
    align_up(size, max(align1, align2))
}

#[allow(dead_code)]
const fn c_struct_size_3(
    size1: usize,
    align1: usize,
    size2: usize,
    align2: usize,
    size3: usize,
    align3: usize,
) -> usize {
    let offset2 = align_up(size1, align2);
    let offset3 = align_up(offset2 + size2, align3);
    let size = offset3 + size3;
    align_up(size, max(align1, max(align2, align3)))
}

const _: () = {
    let expected_str_view = c_struct_size_2(
        size_of::<*const c_char>(),
        align_of::<*const c_char>(),
        size_of::<usize>(),
        align_of::<usize>(),
    );
    assert!(size_of::<PkStrView>() == expected_str_view);

    let expected_str_list = c_struct_size_2(
        size_of::<*const PkStrView>(),
        align_of::<*const PkStrView>(),
        size_of::<usize>(),
        align_of::<usize>(),
    );
    assert!(size_of::<PkStrList>() == expected_str_list);

    let expected_opt_str = c_struct_size_2(
        size_of::<u8>(),
        align_of::<u8>(),
        size_of::<PkStrView>(),
        align_of::<PkStrView>(),
    );
    assert!(size_of::<PkOptStr>() == expected_opt_str);

    let expected_decision = c_struct_size_2(
        size_of::<u8>(),
        align_of::<u8>(),
        size_of::<PkDecisionCode>(),
        align_of::<PkDecisionCode>(),
    );
    assert!(size_of::<PkDecision>() == expected_decision);

    let expected_abi = c_struct_size_2(
        size_of::<u32>(),
        align_of::<u32>(),
        size_of::<u32>(),
        align_of::<u32>(),
    );
    assert!(size_of::<PkAbiVersion>() == expected_abi);

    let expected_aud = c_struct_size_3(
        size_of::<PkAudKind>(),
        align_of::<PkAudKind>(),
        size_of::<PkStrView>(),
        align_of::<PkStrView>(),
        size_of::<PkStrList>(),
        align_of::<PkStrList>(),
    );
    assert!(size_of::<PkAudClaim>() == expected_aud);

    assert!(size_of::<PkDecisionCode>() == size_of::<c_int>());
};
