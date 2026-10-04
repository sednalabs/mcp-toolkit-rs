//! Bounded selection over a caller-provided view of retained operation logs.

/// One already-authorized and redacted log record borrowed from caller storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationLogRecordRef<'a> {
    /// Monotonically assigned source offset.
    pub offset: u64,
    /// Caller-provided timestamp in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Caller-provided stream label.
    pub stream: &'a str,
    /// Redacted payload text. Byte limits count its UTF-8 representation.
    pub payload: &'a str,
}

/// Bounds and source metadata for a query over retained records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationLogQuery {
    /// Exclusive source cursor. `None` starts at the beginning.
    pub after_offset: Option<u64>,
    /// Maximum number of newest matching source records considered.
    pub tail: usize,
    /// Maximum number of records returned.
    pub max_records: usize,
    /// Maximum UTF-8 payload bytes returned. Record metadata is not counted.
    pub max_payload_bytes: usize,
    /// Retention-gap fact supplied by the storage owner, if known.
    pub retention_gap_since_cursor: Option<bool>,
    /// Latest source offset captured before application filtering/coalescing.
    pub latest_source_offset: Option<u64>,
}

/// Result of applying a bounded query to caller-owned records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationLogQueryResult<'a> {
    /// Selected records in increasing source-offset order.
    pub entries: Vec<OperationLogRecordRef<'a>>,
    /// First offset in the supplied record view, not an inferred retention floor.
    pub earliest_retained_offset: Option<u64>,
    /// Source cursor supplied by the caller, independent of returned entries.
    pub latest_source_offset: Option<u64>,
    /// Explicit retention-gap metadata supplied by the caller.
    pub retention_gap: Option<bool>,
    /// True when candidate records were omitted by the count or byte limits.
    pub response_truncated: bool,
    /// Number of candidate records omitted by the response limits.
    pub omitted_records: usize,
    /// UTF-8 payload bytes omitted by the response limits.
    pub omitted_payload_bytes: usize,
}

/// Invalid ordering or source metadata supplied to a log query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationLogQueryError {
    /// Input records were not in strictly increasing source-offset order.
    NonIncreasingOffsets,
    /// Nonempty input had no latest-source cursor, or a row exceeded that cursor.
    InconsistentLatestSourceOffset,
}

/// Selects a bounded tail from an ordered, caller-authorized record view.
///
/// Records must already be filtered and redacted according to caller policy.
/// The exclusive cursor, tail, count, and UTF-8 payload-byte limit affect only
/// the returned view; `latest_source_offset` and `retention_gap` are echoed
/// independently so callers can advance even when rows are omitted.
/// Oversized records are omitted and counted while older fitting records remain
/// eligible. The helper does not infer a retention gap from sparse offsets.
///
/// # Errors
/// Returns [`OperationLogQueryError::NonIncreasingOffsets`] when input offsets
/// are duplicated or decrease. Returns
/// [`OperationLogQueryError::InconsistentLatestSourceOffset`] when nonempty
/// input has no source cursor, or any row lies beyond that cursor.
pub fn select_operation_logs<'a>(
    records: &'a [OperationLogRecordRef<'a>],
    query: OperationLogQuery,
) -> Result<OperationLogQueryResult<'a>, OperationLogQueryError> {
    for pair in records.windows(2) {
        if pair[0].offset >= pair[1].offset {
            return Err(OperationLogQueryError::NonIncreasingOffsets);
        }
    }

    if let Some(latest) = query.latest_source_offset {
        if records.iter().any(|record| record.offset > latest) {
            return Err(OperationLogQueryError::InconsistentLatestSourceOffset);
        }
    } else if !records.is_empty() {
        return Err(OperationLogQueryError::InconsistentLatestSourceOffset);
    }

    let earliest_retained_offset = records.first().map(|record| record.offset);
    let candidates: Vec<_> = records
        .iter()
        .copied()
        .filter(|record| {
            query
                .after_offset
                .is_none_or(|after_offset| record.offset > after_offset)
        })
        .collect();

    let tail_count = query.tail.min(candidates.len());
    let candidate_start = candidates.len() - tail_count;
    let candidates = &candidates[candidate_start..];
    let record_limit = query.max_records.min(candidates.len());
    let mut selected_reversed = Vec::with_capacity(record_limit);
    let mut remaining_bytes = query.max_payload_bytes;
    let mut omitted_records = candidates.len().saturating_sub(record_limit);
    let mut omitted_payload_bytes = 0usize;

    for record in candidates.iter().rev().take(record_limit) {
        let payload_bytes = record.payload.len();
        if payload_bytes <= remaining_bytes {
            remaining_bytes -= payload_bytes;
            selected_reversed.push(*record);
        } else {
            omitted_records = omitted_records.saturating_add(1);
            omitted_payload_bytes = omitted_payload_bytes.saturating_add(payload_bytes);
        }
    }
    selected_reversed.reverse();

    Ok(OperationLogQueryResult {
        entries: selected_reversed,
        earliest_retained_offset,
        latest_source_offset: query.latest_source_offset,
        retention_gap: query.retention_gap_since_cursor,
        response_truncated: omitted_records > 0,
        omitted_records,
        omitted_payload_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(offset: u64, payload: &'static str) -> OperationLogRecordRef<'static> {
        OperationLogRecordRef {
            offset,
            timestamp_ms: offset,
            stream: "stdout",
            payload,
        }
    }

    fn query(latest_source_offset: Option<u64>) -> OperationLogQuery {
        OperationLogQuery {
            after_offset: None,
            tail: usize::MAX,
            max_records: usize::MAX,
            max_payload_bytes: usize::MAX,
            retention_gap_since_cursor: None,
            latest_source_offset,
        }
    }

    #[test]
    fn cursor_is_exclusive_and_rows_remain_in_source_order() {
        let rows = [record(0, "zero"), record(1, "one"), record(2, "two")];
        let result = select_operation_logs(
            &rows,
            OperationLogQuery {
                after_offset: None,
                latest_source_offset: Some(2),
                ..query(Some(2))
            },
        )
        .expect("valid ordered rows");

        assert_eq!(
            result.entries.iter().map(|row| row.offset).collect::<Vec<_>>(),
            [0, 1, 2]
        );
    }

    #[test]
    fn invalid_order_and_inconsistent_latest_are_rejected() {
        let duplicate = [record(2, "a"), record(2, "b")];
        assert_eq!(
            select_operation_logs(&duplicate, query(Some(2))),
            Err(OperationLogQueryError::NonIncreasingOffsets)
        );

        let rows = [record(3, "a")];
        assert_eq!(
            select_operation_logs(&rows, query(Some(2))),
            Err(OperationLogQueryError::InconsistentLatestSourceOffset)
        );
        assert_eq!(
            select_operation_logs(&rows, query(None)),
            Err(OperationLogQueryError::InconsistentLatestSourceOffset)
        );
    }

    #[test]
    fn skips_oversized_utf8_payload_and_continues_to_older_rows() {
        let rows = [record(1, "old"), record(2, "éé"), record(3, "new")];
        let result = select_operation_logs(
            &rows,
            OperationLogQuery {
                max_payload_bytes: 4,
                latest_source_offset: Some(3),
                ..query(Some(3))
            },
        )
        .expect("valid ordered rows");

        assert_eq!(result.entries.iter().map(|row| row.offset).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(result.omitted_records, 1);
        assert_eq!(result.omitted_payload_bytes, 4);
        assert!(result.response_truncated);
        assert_eq!(result.latest_source_offset, Some(3));
    }

    #[test]
    fn preserves_cursor_and_gap_for_filtered_future_and_empty_views() {
        let empty: [OperationLogRecordRef<'_>; 0] = [];
        let result = select_operation_logs(
            &empty,
            OperationLogQuery {
                after_offset: Some(99),
                retention_gap_since_cursor: Some(true),
                latest_source_offset: Some(17),
                ..query(Some(17))
            },
        )
        .expect("empty candidate view is valid");

        assert!(result.entries.is_empty());
        assert_eq!(result.latest_source_offset, Some(17));
        assert_eq!(result.retention_gap, Some(true));
        assert_eq!(result.earliest_retained_offset, None);
    }

    #[test]
    fn zero_limits_omit_candidates_without_losing_source_cursor() {
        let rows = [record(1, "a"), record(2, "b")];
        let result = select_operation_logs(
            &rows,
            OperationLogQuery {
                max_records: 0,
                latest_source_offset: Some(2),
                ..query(Some(2))
            },
        )
        .expect("valid ordered rows");

        assert!(result.entries.is_empty());
        assert_eq!(result.latest_source_offset, Some(2));
        assert_eq!(result.omitted_records, 2);
        assert!(result.response_truncated);

        let no_tail = select_operation_logs(
            &rows,
            OperationLogQuery {
                tail: 0,
                latest_source_offset: Some(2),
                ..query(Some(2))
            },
        )
        .expect("valid ordered rows");
        assert!(no_tail.entries.is_empty());
        assert_eq!(no_tail.omitted_records, 0);
    }
}
