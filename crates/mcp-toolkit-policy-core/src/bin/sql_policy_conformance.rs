//! SQL restricted-policy conformance runner against kernel vectors.

use mcp_toolkit_policy_core::sql_read_only::classify_restricted_sql;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;

const SQL_POLICY_OP: &str = "sql_restricted_policy_decision";
const DEFAULT_REASON: &str = "restricted_sql";
const DEFAULT_POLICY_CONTRACT_VERSION: &str = "sql-restricted/v1";

#[derive(Debug)]
struct Args {
    vectors: PathBuf,
    report: Option<PathBuf>,
    policy_contract_version: String,
    deny_reason: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DecisionExpect {
    allow: bool,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct VectorCase {
    op: String,
    case: String,
    input: Value,
    expect: DecisionExpect,
}

#[derive(Debug, Clone, Deserialize)]
struct SqlRestrictedPolicyInput {
    policy_contract_version: String,
    sql: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct Decision {
    allow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl Decision {
    fn allow() -> Self {
        Self {
            allow: true,
            code: None,
            reason: None,
        }
    }

    fn deny(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            code: Some(code.into()),
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Mismatch {
    case: String,
    expected: Decision,
    actual: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConformanceReport {
    vectors_path: String,
    policy_contract_version: String,
    deny_reason: String,
    evaluated_cases: usize,
    mismatch_count: usize,
    mismatches: Vec<Mismatch>,
}

fn usage(program: &str) -> String {
    format!(
        "Usage: {program} --vectors <path> [--report <path>] [--policy-contract-version <value>] [--deny-reason <value>]"
    )
}

fn parse_args() -> Result<Args, String> {
    let mut vectors: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;
    let mut policy_contract_version = DEFAULT_POLICY_CONTRACT_VERSION.to_string();
    let mut deny_reason = DEFAULT_REASON.to_string();

    let args: Vec<String> = env::args().collect();
    let program = args
        .first()
        .cloned()
        .unwrap_or_else(|| "sql_policy_conformance".to_string());

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--vectors" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| usage(&program))?;
                vectors = Some(PathBuf::from(value));
            }
            "--report" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| usage(&program))?;
                report = Some(PathBuf::from(value));
            }
            "--policy-contract-version" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| usage(&program))?;
                policy_contract_version = value.clone();
            }
            "--deny-reason" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| usage(&program))?;
                deny_reason = value.clone();
            }
            "--help" | "-h" => {
                return Err(usage(&program));
            }
            other => {
                return Err(format!("unknown argument: {other}\n{}", usage(&program)));
            }
        }
        i += 1;
    }

    let vectors = vectors.ok_or_else(|| usage(&program))?;
    if policy_contract_version.trim().is_empty() {
        return Err("policy contract version must not be empty".to_string());
    }
    if deny_reason.trim().is_empty() {
        return Err("deny reason must not be empty".to_string());
    }

    Ok(Args {
        vectors,
        report,
        policy_contract_version,
        deny_reason,
    })
}

fn expected_decision(expect: &DecisionExpect) -> Decision {
    Decision {
        allow: expect.allow,
        code: expect.code.clone(),
        reason: expect.reason.clone(),
    }
}

fn classify_decision(sql: &str, deny_reason: &str) -> Decision {
    match classify_restricted_sql(sql) {
        Ok(()) => Decision::allow(),
        Err(err) => Decision::deny(err.code.as_str(), deny_reason),
    }
}

fn evaluate_case(
    case: &VectorCase,
    expected_policy_contract_version: &str,
    deny_reason: &str,
) -> Result<Decision, String> {
    let input: SqlRestrictedPolicyInput = serde_json::from_value(case.input.clone())
        .map_err(|err| format!("failed to parse SQL policy input: {err}"))?;

    if input.policy_contract_version != expected_policy_contract_version {
        return Ok(Decision::deny("CLASSIFIER_UNAVAILABLE", deny_reason));
    }

    Ok(classify_decision(&input.sql, deny_reason))
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let raw = fs::read_to_string(&args.vectors).map_err(|err| {
        format!(
            "failed to read vectors file {}: {err}",
            args.vectors.display()
        )
    })?;
    let vectors: Vec<VectorCase> =
        serde_json::from_str(&raw).map_err(|err| format!("failed to parse vectors JSON: {err}"))?;

    let mut mismatches = Vec::new();
    let mut evaluated_cases = 0usize;
    for case in vectors.iter().filter(|entry| entry.op == SQL_POLICY_OP) {
        evaluated_cases += 1;
        let expected = expected_decision(&case.expect);
        match evaluate_case(case, &args.policy_contract_version, &args.deny_reason) {
            Ok(actual) => {
                if actual != expected {
                    mismatches.push(Mismatch {
                        case: case.case.clone(),
                        expected,
                        actual,
                        parse_error: None,
                    });
                }
            }
            Err(parse_error) => {
                mismatches.push(Mismatch {
                    case: case.case.clone(),
                    expected,
                    actual: Decision::deny("CLASSIFIER_UNAVAILABLE", &args.deny_reason),
                    parse_error: Some(parse_error),
                });
            }
        }
    }

    if evaluated_cases == 0 {
        return Err(format!(
            "no '{SQL_POLICY_OP}' cases found in {}",
            args.vectors.display()
        ));
    }

    let report = ConformanceReport {
        vectors_path: args.vectors.display().to_string(),
        policy_contract_version: args.policy_contract_version.clone(),
        deny_reason: args.deny_reason.clone(),
        evaluated_cases,
        mismatch_count: mismatches.len(),
        mismatches,
    };

    if let Some(path) = args.report {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "failed to create report directory {}: {err}",
                    parent.display()
                )
            })?;
        }
        let encoded = serde_json::to_string_pretty(&report)
            .map_err(|err| format!("failed to serialize report JSON: {err}"))?;
        fs::write(&path, format!("{encoded}\n"))
            .map_err(|err| format!("failed to write report {}: {err}", path.display()))?;
        println!("wrote report: {}", path.display());
    }

    if report.mismatch_count > 0 {
        return Err(format!(
            "sql policy conformance mismatches: {}",
            report.mismatch_count
        ));
    }

    println!(
        "sql policy conformance ok ({} SQL cases)",
        report.evaluated_cases
    );
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
