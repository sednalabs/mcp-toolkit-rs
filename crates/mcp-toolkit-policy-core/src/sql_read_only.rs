//! Restricted read-only SQL checks for policy enforcement.
//!
//! ## Rationale
//! Enforce read-only SQL constraints to prevent unauthorized data modification,
//! structural changes, or execution of high-risk utility functions by untrusted
//! SQL inputs.
//!
//! ## Security Boundaries
//! * Implements a lexical surface analyzer to safely strip SQL literals/comments.
//! * Performs keyword-based validation for DML/DDL operations.
//! * Blocklists high-risk system functions (e.g., `pg_sleep`, `pg_terminate_backend`).
//! * Fails closed if the classifier cannot reliably parse the input.
//!
//! ## References
//! * [PostgreSQL Error Codes] https://www.postgresql.org/docs/current/errcodes-appendix.html
//! * [SQL Injection Mitigation] (internal project guidance)
//!
//! ## Notes
//! * Classifier logic is based on a simplified lexical state machine.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::boundary::string_within_boundary_limit;
use crate::{Decision, DecisionCode};

pub const SQL_POLICY_CONTRACT_VERSION: &str = "sql-restricted/v1";
pub const SQL_POLICY_REASON: &str = "restricted_sql";

/// Error codes returned when SQL fails the restricted policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictedSqlErrorCode {
    EmptySql,
    UnterminatedToken,
    MultipleStatements,
    NotReadOnlyPrefix,
    ForbiddenKeyword,
    ForbiddenFunction,
    ExplainNotReadOnly,
    ClassifierUnavailable,
}

impl RestrictedSqlErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmptySql => "EMPTY_SQL",
            Self::UnterminatedToken => "UNTERMINATED_TOKEN",
            Self::MultipleStatements => "MULTIPLE_STATEMENTS",
            Self::NotReadOnlyPrefix => "NOT_READ_ONLY_PREFIX",
            Self::ForbiddenKeyword => "FORBIDDEN_KEYWORD",
            Self::ForbiddenFunction => "FORBIDDEN_FUNCTION",
            Self::ExplainNotReadOnly => "EXPLAIN_NOT_READ_ONLY",
            Self::ClassifierUnavailable => "CLASSIFIER_UNAVAILABLE",
        }
    }

    pub fn decision_code(self) -> DecisionCode {
        match self {
            Self::EmptySql => DecisionCode::EmptySql,
            Self::UnterminatedToken => DecisionCode::UnterminatedToken,
            Self::MultipleStatements => DecisionCode::MultipleStatements,
            Self::NotReadOnlyPrefix => DecisionCode::NotReadOnlyPrefix,
            Self::ForbiddenKeyword => DecisionCode::ForbiddenKeyword,
            Self::ForbiddenFunction => DecisionCode::ForbiddenFunction,
            Self::ExplainNotReadOnly => DecisionCode::ExplainNotReadOnly,
            Self::ClassifierUnavailable => DecisionCode::ClassifierUnavailable,
        }
    }
}

/// Error type returned by SQL classification operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictedSqlError {
    pub code: RestrictedSqlErrorCode,
    pub message: String,
}

impl std::fmt::Display for RestrictedSqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RestrictedSqlError {}

/// Input structure for SQL restricted policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlRestrictedPolicyInput {
    pub policy_contract_version: String,
    pub sql: String,
}

/// Validates SQL string against read-only constraints.
///
/// # Errors
/// Returns an error message if the SQL violates restricted policy or fails to parse.
pub fn validate_restricted_sql(sql: &str) -> Result<(), String> {
    classify_restricted_sql(sql).map_err(|err| err.message)
}

/// Classifies a SQL statement and returns detailed error information on failure.
///
/// # Errors
/// Returns `RestrictedSqlError` if the SQL is structurally invalid, contains
/// forbidden operations, or if the internal classifier fails to initialize.
///
/// # Security
/// * Performs lexical analysis to prevent bypasses using literals or comments.
/// * Enforces a 'single statement' restriction to prevent multi-statement injection.
pub fn classify_restricted_sql(sql: &str) -> Result<(), RestrictedSqlError> {
    let lexical = lexical_surface(sql, true)?;
    let lexical_functions = lexical_surface(sql, false)?;
    let trimmed = lexical.trim();
    let function_surface = lexical_functions.trim();

    if trimmed.is_empty() {
        return Err(RestrictedSqlError {
            code: RestrictedSqlErrorCode::EmptySql,
            message: "sql must not be empty".to_string(),
        });
    }

    let statement_count = trimmed
        .split(';')
        .filter(|part| !part.trim().is_empty())
        .count();
    if statement_count > 1 {
        return Err(RestrictedSqlError {
            code: RestrictedSqlErrorCode::MultipleStatements,
            message: "restricted mode allows only a single SQL statement".to_string(),
        });
    }

    let upper = trimmed.to_ascii_uppercase();
    let allowed_prefixes = [
        "SELECT",
        "WITH",
        "EXPLAIN",
        "SHOW",
        "VALUES",
        "DECLARE",
        "FETCH",
        "CLOSE",
        "PREPARE",
        "DEALLOCATE",
    ];
    if !allowed_prefixes
        .iter()
        .any(|prefix| upper.starts_with(prefix))
    {
        return Err(RestrictedSqlError {
            code: RestrictedSqlErrorCode::NotReadOnlyPrefix,
            message: "restricted mode allows only allowlisted SQL prefixes".to_string(),
        });
    }

    if upper.starts_with("EXPLAIN") {
        if explain_forbidden_re()?.is_match(trimmed) {
            return Err(RestrictedSqlError {
                code: RestrictedSqlErrorCode::ExplainNotReadOnly,
                message: "restricted mode allows EXPLAIN only for read-only statements".to_string(),
            });
        }
    } else if forbidden_keyword_re()?.is_match(trimmed) {
        return Err(RestrictedSqlError {
            code: RestrictedSqlErrorCode::ForbiddenKeyword,
            message: "restricted mode rejected write/admin SQL".to_string(),
        });
    }
    if contains_forbidden_function(function_surface)? {
        return Err(RestrictedSqlError {
            code: RestrictedSqlErrorCode::ForbiddenFunction,
            message: "restricted mode rejected unsafe function call".to_string(),
        });
    }

    Ok(())
}

/// Evaluates a SQL policy decision.
///
/// # Security
/// * Verifies that the policy version is supported to prevent downgrade attacks.
/// * Sanitizes input and denies if it exceeds boundary limits.
pub fn sql_restricted_policy_decision(input: &SqlRestrictedPolicyInput) -> Decision {
    if !string_within_boundary_limit(&input.policy_contract_version)
        || !string_within_boundary_limit(&input.sql)
    {
        return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limits"));
    }
    if input.policy_contract_version != SQL_POLICY_CONTRACT_VERSION {
        return Decision::deny(DecisionCode::ClassifierUnavailable, Some(SQL_POLICY_REASON));
    }

    match classify_restricted_sql(&input.sql) {
        Ok(()) => Decision::allow(),
        Err(code) => Decision::deny(code.code.decision_code(), Some(SQL_POLICY_REASON)),
    }
}

const FORBIDDEN_KEYWORD_PATTERN: &str = r"(?i)\b(INSERT|UPDATE|DELETE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|CALL|DO|MERGE|REINDEX|CLUSTER|COMMENT|SECURITY\s+LABEL|CREATE|DISCARD|RESET|SET|LOCK|REFRESH)\b";
const EXPLAIN_FORBIDDEN_PATTERN: &str = r"(?i)\b(INSERT|UPDATE|DELETE|MERGE|ALTER|DROP|TRUNCATE|CREATE|GRANT|REVOKE|COPY|CALL|DO|LOCK|FOR\s+UPDATE)\b";
const FORBIDDEN_FUNCTION_PATTERN: &str = r#"(?i)\b(pg_sleep|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_log_backend_memory_contexts|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|pg_write_file|set_config|dblink_connect|dblink_exec|dblink_send_query|lo_import|lo_export|pg_advisory_lock|pg_advisory_lock_shared|pg_advisory_xact_lock|pg_advisory_xact_lock_shared)\b(?:\s*"\s*)?\("#;

fn forbidden_keyword_re() -> Result<&'static Regex, RestrictedSqlError> {
    static FORBIDDEN_RE: OnceLock<Result<Regex, String>> = OnceLock::new();
    FORBIDDEN_RE
        .get_or_init(|| Regex::new(FORBIDDEN_KEYWORD_PATTERN).map_err(|err| err.to_string()))
        .as_ref()
        .map_err(|_| RestrictedSqlError {
            code: RestrictedSqlErrorCode::ClassifierUnavailable,
            message: "restricted mode policy classifier unavailable".to_string(),
        })
}

fn explain_forbidden_re() -> Result<&'static Regex, RestrictedSqlError> {
    static EXPLAIN_FORBIDDEN_RE: OnceLock<Result<Regex, String>> = OnceLock::new();
    EXPLAIN_FORBIDDEN_RE
        .get_or_init(|| Regex::new(EXPLAIN_FORBIDDEN_PATTERN).map_err(|err| err.to_string()))
        .as_ref()
        .map_err(|_| RestrictedSqlError {
            code: RestrictedSqlErrorCode::ClassifierUnavailable,
            message: "restricted mode policy classifier unavailable".to_string(),
        })
}

fn forbidden_function_re() -> Result<&'static Regex, RestrictedSqlError> {
    static FORBIDDEN_FUNCTION_RE: OnceLock<Result<Regex, String>> = OnceLock::new();
    FORBIDDEN_FUNCTION_RE
        .get_or_init(|| Regex::new(FORBIDDEN_FUNCTION_PATTERN).map_err(|err| err.to_string()))
        .as_ref()
        .map_err(|_| RestrictedSqlError {
            code: RestrictedSqlErrorCode::ClassifierUnavailable,
            message: "restricted mode policy classifier unavailable".to_string(),
        })
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn previous_word_upper(surface: &str, before: usize) -> Option<String> {
    let bytes = surface.as_bytes();
    if before == 0 || before > bytes.len() {
        return None;
    }

    let mut i = before;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let end = i;
    while i > 0 && is_word_byte(bytes[i - 1]) {
        i -= 1;
    }
    if i == end {
        return None;
    }

    Some(surface[i..end].to_ascii_uppercase())
}

fn next_word_upper(surface: &str, start: usize) -> Option<String> {
    let bytes = surface.as_bytes();
    if start >= bytes.len() {
        return None;
    }

    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let begin = i;
    while i < bytes.len() && is_word_byte(bytes[i]) {
        i += 1;
    }
    if begin == i {
        return None;
    }

    Some(surface[begin..i].to_ascii_uppercase())
}

fn matching_close_paren(bytes: &[u8], open_paren: usize) -> Option<usize> {
    if open_paren >= bytes.len() || bytes[open_paren] != b'(' {
        return None;
    }

    let mut depth: u32 = 1;
    let mut i = open_paren + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth = depth.saturating_add(1),
            b')' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }

    None
}

fn is_cte_header_forbidden_match(surface: &str, match_start: usize, open_paren: usize) -> bool {
    let previous = previous_word_upper(surface, match_start);
    if previous.as_deref() != Some("WITH") && previous.as_deref() != Some("RECURSIVE") {
        return false;
    }

    let bytes = surface.as_bytes();
    let Some(close_paren) = matching_close_paren(bytes, open_paren) else {
        return false;
    };

    matches!(
        next_word_upper(surface, close_paren + 1).as_deref(),
        Some("AS")
    )
}

fn contains_forbidden_function(surface: &str) -> Result<bool, RestrictedSqlError> {
    let re = forbidden_function_re()?;
    for matched in re.find_iter(surface) {
        if matched.end() == 0 {
            continue;
        }
        let open_paren = matched.end() - 1;
        if !is_cte_header_forbidden_match(surface, matched.start(), open_paren) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn lexical_surface(sql: &str, mask_double_quoted: bool) -> Result<String, RestrictedSqlError> {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum State {
        Normal,
        SingleQuote,
        DoubleQuote,
        LineComment,
        BlockComment(u32),
    }

    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;
    let mut state = State::Normal;
    let mut dollar_tag: Option<Vec<u8>> = None;

    while i < bytes.len() {
        if let Some(tag) = dollar_tag.as_ref() {
            if bytes[i..].starts_with(tag) {
                for _ in 0..tag.len() {
                    out.push(' ');
                }
                i += tag.len();
                dollar_tag = None;
                continue;
            }

            out.push(mask_hidden_byte(bytes[i]));
            i += 1;
            continue;
        }

        match state {
            State::Normal => {
                if bytes[i..].starts_with(b"--") {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    state = State::LineComment;
                    continue;
                }
                if bytes[i..].starts_with(b"/*") {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    state = State::BlockComment(1);
                    continue;
                }
                if bytes[i] == b'\'' {
                    out.push(' ');
                    i += 1;
                    state = State::SingleQuote;
                    continue;
                }
                if bytes[i] == b'"' {
                    out.push(if mask_double_quoted { ' ' } else { '"' });
                    i += 1;
                    state = State::DoubleQuote;
                    continue;
                }
                if let Some(tag_len) = parse_dollar_tag(&bytes[i..]) {
                    let tag = bytes[i..i + tag_len].to_vec();
                    for _ in 0..tag_len {
                        out.push(' ');
                    }
                    i += tag_len;
                    dollar_tag = Some(tag);
                    continue;
                }

                out.push(mask_byte(bytes[i]));
                i += 1;
            }
            State::SingleQuote => {
                if bytes[i] == b'\'' {
                    out.push(' ');
                    i += 1;
                    if i < bytes.len() && bytes[i] == b'\'' {
                        out.push(' ');
                        i += 1;
                    } else {
                        state = State::Normal;
                    }
                    continue;
                }
                out.push(mask_hidden_byte(bytes[i]));
                i += 1;
            }
            State::DoubleQuote => {
                if bytes[i] == b'"' {
                    out.push(if mask_double_quoted { ' ' } else { '"' });
                    i += 1;
                    if i < bytes.len() && bytes[i] == b'"' {
                        out.push(if mask_double_quoted { ' ' } else { '"' });
                        i += 1;
                    } else {
                        state = State::Normal;
                    }
                    continue;
                }
                out.push(if mask_double_quoted {
                    mask_hidden_byte(bytes[i])
                } else {
                    mask_byte(bytes[i])
                });
                i += 1;
            }
            State::LineComment => {
                if bytes[i] == b'\n' || bytes[i] == b'\r' {
                    out.push(char::from(bytes[i]));
                    i += 1;
                    state = State::Normal;
                    continue;
                }
                out.push(' ');
                i += 1;
            }
            State::BlockComment(depth) => {
                if bytes[i..].starts_with(b"/*") {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    state = State::BlockComment(depth + 1);
                    continue;
                }
                if bytes[i..].starts_with(b"*/") {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    if depth == 1 {
                        state = State::Normal;
                    } else {
                        state = State::BlockComment(depth - 1);
                    }
                    continue;
                }
                out.push(mask_hidden_byte(bytes[i]));
                i += 1;
            }
        }
    }

    if dollar_tag.is_some()
        || matches!(
            state,
            State::SingleQuote | State::DoubleQuote | State::BlockComment(_)
        )
    {
        return Err(RestrictedSqlError {
            code: RestrictedSqlErrorCode::UnterminatedToken,
            message: "restricted mode could not parse SQL lexical surface".to_string(),
        });
    }

    Ok(out)
}

fn parse_dollar_tag(input: &[u8]) -> Option<usize> {
    if input.first().copied()? != b'$' {
        return None;
    }

    for (idx, byte) in input.iter().enumerate().skip(1) {
        if *byte == b'$' {
            return Some(idx + 1);
        }
        if !byte.is_ascii_alphanumeric() && *byte != b'_' {
            return None;
        }
    }

    None
}

fn mask_byte(b: u8) -> char {
    match b {
        b'\n' | b'\r' | b'\t' => char::from(b),
        b if b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b' ' | b',' | b'.' | b'(' | b')' | b';') =>
        {
            char::from(b)
        }
        _ => ' ',
    }
}

fn mask_hidden_byte(b: u8) -> char {
    match b {
        b'\n' | b'\r' | b'\t' => char::from(b),
        _ => ' ',
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_restricted_sql, lexical_surface, sql_restricted_policy_decision,
        validate_restricted_sql, RestrictedSqlErrorCode, SqlRestrictedPolicyInput,
        SQL_POLICY_CONTRACT_VERSION,
    };

    fn must_err(result: Result<(), super::RestrictedSqlError>) -> super::RestrictedSqlError {
        result.expect_err("expected SQL classifier to reject input")
    }

    #[test]
    fn allows_select() {
        assert!(validate_restricted_sql("SELECT 1").is_ok());
    }

    #[test]
    fn rejects_insert() {
        let err = must_err(classify_restricted_sql("INSERT INTO t VALUES (1)"));
        assert_eq!(err.code, RestrictedSqlErrorCode::NotReadOnlyPrefix);
    }

    #[test]
    fn rejects_vacuum_prefix() {
        let err = must_err(classify_restricted_sql("VACUUM"));
        assert_eq!(err.code, RestrictedSqlErrorCode::NotReadOnlyPrefix);
    }

    #[test]
    fn rejects_analyze_prefix() {
        let err = must_err(classify_restricted_sql("ANALYZE users"));
        assert_eq!(err.code, RestrictedSqlErrorCode::NotReadOnlyPrefix);
    }

    #[test]
    fn rejects_multi_statement() {
        let err = must_err(classify_restricted_sql("SELECT 1; SELECT 2;"));
        assert_eq!(err.code, RestrictedSqlErrorCode::MultipleStatements);
    }

    #[test]
    fn allows_semicolon_inside_string_literal() {
        assert!(validate_restricted_sql("SELECT ';'::text").is_ok());
    }

    #[test]
    fn allows_select_with_for_update_in_string() {
        assert!(validate_restricted_sql("SELECT 'FOR UPDATE'::text").is_ok());
    }

    #[test]
    fn rejects_unterminated_string() {
        let err = must_err(classify_restricted_sql("SELECT 'oops"));
        assert_eq!(err.code, RestrictedSqlErrorCode::UnterminatedToken);
    }

    #[test]
    fn rejects_unterminated_block_comment() {
        let err = must_err(classify_restricted_sql("SELECT 1 /* missing end"));
        assert_eq!(err.code, RestrictedSqlErrorCode::UnterminatedToken);
    }

    #[test]
    fn rejects_explain_mutation() {
        let err = must_err(classify_restricted_sql("EXPLAIN INSERT INTO t VALUES (1)"));
        assert_eq!(err.code, RestrictedSqlErrorCode::ExplainNotReadOnly);
    }

    #[test]
    fn allows_leading_comments() {
        assert!(validate_restricted_sql("-- note\n/* block */\nSELECT 1").is_ok());
    }

    #[test]
    fn lexical_surface_masks_literals_and_comments() {
        let masked = lexical_surface("SELECT 'secret' /* comment */ col -- tail\nFROM t", true)
            .expect("masked SQL");
        assert!(masked.contains("SELECT"));
        assert!(masked.contains("FROM t"));
        assert!(!masked.contains("secret"));
        assert!(!masked.contains("comment"));
    }

    #[test]
    fn allows_dollar_quoted_body_without_false_positive() {
        let sql = "SELECT $$DROP TABLE users$$::text";
        assert!(validate_restricted_sql(sql).is_ok());
    }

    #[test]
    fn allows_nested_block_comments_before_read_only_query() {
        let sql = "/* outer /* inner */ done */ SELECT 1";
        assert!(validate_restricted_sql(sql).is_ok());
    }

    #[test]
    fn allows_dml_keywords_in_identifiers() {
        let sql = "SELECT insert_count, update_flag FROM metrics";
        assert!(validate_restricted_sql(sql).is_ok());
    }

    #[test]
    fn rejects_write_in_cte() {
        let sql =
            "WITH mutated AS (UPDATE users SET active = false RETURNING id) SELECT id FROM mutated";
        let err = must_err(classify_restricted_sql(sql));
        assert_eq!(err.code, RestrictedSqlErrorCode::ForbiddenKeyword);
    }

    #[test]
    fn allows_parameter_placeholder_syntax() {
        assert!(validate_restricted_sql("SELECT $1::int").is_ok());
    }

    #[test]
    fn rejects_unterminated_dollar_quote() {
        let err = must_err(classify_restricted_sql("SELECT $tag$missing"));
        assert_eq!(err.code, RestrictedSqlErrorCode::UnterminatedToken);
    }

    #[test]
    fn allows_for_update_keyword_inside_comments_and_literals() {
        let sql = "SELECT 1 /* FOR UPDATE */ WHERE note = 'FOR UPDATE'";
        assert!(validate_restricted_sql(sql).is_ok());
    }

    #[test]
    fn rejects_copy_hidden_in_cte() {
        let sql = "WITH staged AS (COPY users TO STDOUT) SELECT * FROM staged";
        let err = must_err(classify_restricted_sql(sql));
        assert_eq!(err.code, RestrictedSqlErrorCode::ForbiddenKeyword);
    }

    #[test]
    fn rejects_unsafe_function_calls() {
        let err = must_err(classify_restricted_sql("SELECT pg_sleep(5)"));
        assert_eq!(err.code, RestrictedSqlErrorCode::ForbiddenFunction);
    }

    #[test]
    fn rejects_unsafe_function_calls_inside_explain() {
        let err = must_err(classify_restricted_sql(
            "EXPLAIN SELECT * FROM users WHERE id = pg_sleep(1)",
        ));
        assert_eq!(err.code, RestrictedSqlErrorCode::ForbiddenFunction);
    }

    #[test]
    fn rejects_quoted_forbidden_function_calls() {
        let err = must_err(classify_restricted_sql(r#"SELECT "pg_sleep"(1)"#));
        assert_eq!(err.code, RestrictedSqlErrorCode::ForbiddenFunction);
    }

    #[test]
    fn allows_cte_name_matching_forbidden_function() {
        let sql = "WITH pg_sleep(id) AS (SELECT 1) SELECT id FROM pg_sleep";
        assert!(validate_restricted_sql(sql).is_ok());
    }

    #[test]
    fn allows_forbidden_function_name_inside_string_literal() {
        assert!(validate_restricted_sql("SELECT 'pg_sleep(5)'::text").is_ok());
    }

    #[test]
    fn line_comment_with_carriage_return_preserves_multi_statement_detection() {
        let err = must_err(classify_restricted_sql("SELECT 1; -- comment\rSELECT 2"));
        assert_eq!(err.code, RestrictedSqlErrorCode::MultipleStatements);
    }

    #[test]
    fn allows_trailing_line_comment_at_end_of_sql() {
        assert!(validate_restricted_sql("SELECT 1 -- trailing").is_ok());
    }

    #[test]
    fn restricted_errors_are_redacted() {
        let decision = sql_restricted_policy_decision(&SqlRestrictedPolicyInput {
            policy_contract_version: SQL_POLICY_CONTRACT_VERSION.to_string(),
            sql: "SELECT pg_sleep(5)".to_string(),
        });
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("FORBIDDEN_FUNCTION"));
        assert_eq!(decision.reason.as_deref(), Some("restricted_sql"));
    }
}
