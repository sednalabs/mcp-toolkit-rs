//! # Duration Estimates
//!
//! Pure arithmetic for estimating a duration from caller-selected completed
//! duration samples.
//!
//! ## Ownership
//! Callers choose eligible samples and their bound. This module only computes
//! an arithmetic mean; it does not select history, read a clock, persist data,
//! or apply workload-specific policy.

use std::time::Duration;

/// Computes the arithmetic mean of completed duration samples.
///
/// The caller is responsible for selecting a bounded set of eligible samples.
/// The result is rounded down to whole nanoseconds because [`Duration`] has
/// nanosecond precision.
///
/// # Errors
/// Returns [`DurationEstimateError::NanosecondSumOverflow`] if the sample
/// durations cannot be accumulated in `u128` nanoseconds.
pub fn mean_duration(samples: &[Duration]) -> Result<Option<Duration>, DurationEstimateError> {
    if samples.is_empty() {
        return Ok(None);
    }

    let total = samples.iter().try_fold(0_u128, |total, sample| {
        checked_add_nanos(total, sample.as_nanos())
    })?;
    let mean_nanos = total / samples.len() as u128;
    let seconds = (mean_nanos / 1_000_000_000) as u64;
    let subsecond_nanos = (mean_nanos % 1_000_000_000) as u32;

    Ok(Some(Duration::new(seconds, subsecond_nanos)))
}

fn checked_add_nanos(total: u128, sample_nanos: u128) -> Result<u128, DurationEstimateError> {
    total
        .checked_add(sample_nanos)
        .ok_or(DurationEstimateError::NanosecondSumOverflow)
}

/// An error produced while calculating a duration estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationEstimateError {
    /// The sum of the input samples exceeded `u128` nanoseconds.
    NanosecondSumOverflow,
}

impl std::fmt::Display for DurationEstimateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NanosecondSumOverflow => {
                formatter.write_str("duration sample sum overflowed u128 nanoseconds")
            }
        }
    }
}

impl std::error::Error for DurationEstimateError {}

#[cfg(test)]
mod tests {
    use super::{checked_add_nanos, mean_duration, DurationEstimateError};
    use std::time::Duration;

    #[test]
    fn empty_samples_are_unknown() {
        assert_eq!(mean_duration(&[]), Ok(None));
    }

    #[test]
    fn one_sample_is_returned_unchanged() {
        let sample = Duration::new(7, 123_456_789);
        assert_eq!(mean_duration(&[sample]), Ok(Some(sample)));
    }

    #[test]
    fn averages_samples() {
        assert_eq!(
            mean_duration(&[Duration::from_secs(2), Duration::from_secs(4)]),
            Ok(Some(Duration::from_secs(3)))
        );
    }

    #[test]
    fn floors_subnanosecond_average() {
        assert_eq!(
            mean_duration(&[Duration::from_nanos(1), Duration::from_nanos(2)]),
            Ok(Some(Duration::from_nanos(1)))
        );
    }

    #[test]
    fn maximum_duration_sample_is_representable() {
        let sample = Duration::new(u64::MAX, 999_999_999);
        assert_eq!(mean_duration(&[sample]), Ok(Some(sample)));
    }

    #[test]
    fn checked_sum_reports_overflow() {
        assert_eq!(
            checked_add_nanos(u128::MAX, 1),
            Err(DurationEstimateError::NanosecondSumOverflow)
        );
    }
}
