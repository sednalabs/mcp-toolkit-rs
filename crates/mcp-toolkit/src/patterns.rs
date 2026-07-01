//! # MCP Toolkit Pattern Registry
//!
//! Exposes the reference archetypes and manifest summaries used by the
//! new-server lane.
//!
//! ## Rationale
//! Keeps the atlas, manifest, recipe, and generator path discoverable from one
//! command surface so new server authors can choose a proven shape before
//! writing provider-specific code.
//!
//! ## Security Boundaries
//! * Registry data is generated at build time from checked-in manifest files.
//! * No provider credentials, secrets, or live repository data are loaded.
//! * Pattern recommendations select maintained templates only; service-specific
//!   auth scopes and domain semantics stay in server repositories.
//!
//! ## References
//! * `docs/reference-server-atlas.md`
//! * `docs/pattern-manifests.md`
//! * `docs/pattern-recipes.md`

use crate::new_server::{find_template, TemplateSpec};

mod generated_registry {
    use super::{
        PatternConformanceSpec, PatternManifestSpec, PatternReferenceSpec, PatternScratchpadSpec,
        PatternServerSpec,
    };

    include!(concat!(env!("OUT_DIR"), "/pattern_registry.rs"));
}

/// Declares one reusable new-server archetype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternSpec {
    /// Stable archetype id from `docs/reference-server-atlas.md`.
    pub id: &'static str,
    /// Human-readable summary for CLI selection.
    pub description: &'static str,
    /// Maintained template id that is the safest starting point.
    pub recommended_template: Option<&'static str>,
    /// Anchor in `docs/pattern-recipes.md`.
    pub recipe_anchor: &'static str,
}

/// Summarizes one checked-in pattern manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternManifestSpec {
    /// Repository-relative manifest path.
    pub path: &'static str,
    /// Reference server or adoption slice described by the manifest.
    pub server: PatternServerSpec,
    /// Archetype ids demonstrated by this manifest.
    pub patterns: &'static [&'static str],
    /// Toolkit crates used or implied by the reference.
    pub toolkit_crates: &'static [&'static str],
    /// MCP transport shapes demonstrated by the reference.
    pub transports: &'static [&'static str],
    /// Auth modes demonstrated by the reference.
    pub auth_modes: &'static [&'static str],
    /// Discovery mechanisms used by the reference.
    pub discovery: &'static [&'static str],
    /// Mutation posture for the tool surface.
    pub mutation_policy: &'static str,
    /// Tool-schema snapshot posture.
    pub schema_snapshot: &'static str,
    /// Scratchpad posture for large-result workflows.
    pub scratchpad: PatternScratchpadSpec,
    /// Profiles marked as default by the manifest.
    pub default_profiles: &'static [&'static str],
    /// All profile names in the manifest.
    pub profiles: &'static [&'static str],
    /// Structured proof posture for the downstream reference.
    pub conformance: PatternConformanceSpec,
    /// Notes from the conformance block.
    pub conformance_notes: &'static str,
    /// Source landmarks for the reference.
    pub references: &'static [PatternReferenceSpec],
}

/// Summarizes the reference server described by a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternServerSpec {
    /// Reference server name.
    pub name: &'static str,
    /// Public repository or source URL.
    pub repository: &'static str,
    /// Manifest role.
    pub role: &'static str,
    /// Short notes from the manifest.
    pub notes: &'static str,
}

/// Summarizes scratchpad support in one manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternScratchpadSpec {
    /// Whether the reference supports scratchpad workflows.
    pub supported: bool,
    /// Scratchpad engine name.
    pub engine: &'static str,
    /// Profile that enables the scratchpad path.
    pub profile: &'static str,
    /// Short notes from the manifest.
    pub notes: &'static str,
}

/// Summarizes the proof posture claimed by a pattern manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternConformanceSpec {
    /// Tool schema snapshot posture.
    pub schema_snapshot: &'static str,
    /// Transport contract posture.
    pub transport_contract: &'static str,
    /// Auth metadata and challenge contract posture.
    pub auth_surface_contract: &'static str,
    /// Domain-specific contract posture.
    pub domain_contracts: &'static str,
    /// Hosted validation posture.
    pub hosted_validation: &'static str,
    /// Release and provenance evidence posture.
    pub release_evidence: &'static str,
    /// Short notes from the manifest.
    pub notes: &'static str,
}

/// Identifies one source landmark in a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternReferenceSpec {
    /// Human-readable landmark label.
    pub label: &'static str,
    /// Landmark kind, such as `doc`, `source`, or `test`.
    pub kind: &'static str,
    /// Path in the reference repository.
    pub path: &'static str,
}

/// Returns the maintained archetype registry.
pub fn patterns() -> &'static [PatternSpec] {
    const PATTERNS: &[PatternSpec] = &[
        PatternSpec {
            id: "minimal-stdio-intent",
            description:
                "Small stdio server with a curated intent tool surface and schema snapshots.",
            recommended_template: Some("curated-stdio-intent"),
            recipe_anchor: "minimal-stdio-intent",
        },
        PatternSpec {
            id: "google-provider-read-only",
            description:
                "Google API server with low-friction ADC/OAuth login and read-only defaults.",
            recommended_template: Some("curated-stdio-intent"),
            recipe_anchor: "google-provider-read-only",
        },
        PatternSpec {
            id: "analytics-scratchpad",
            description:
                "Analytics server that moves large tabular results into a bounded scratchpad.",
            recommended_template: Some("curated-stdio-intent"),
            recipe_anchor: "analytics-scratchpad",
        },
        PatternSpec {
            id: "hosted-http-auth",
            description: "Hosted Streamable HTTP server with OAuth metadata and bearer challenges.",
            recommended_template: Some("hosted-http-auth"),
            recipe_anchor: "hosted-http-auth",
        },
        PatternSpec {
            id: "operator-mutation",
            description:
                "Service with legitimate mutation tools hidden behind explicit operator profiles.",
            recommended_template: Some("curated-stdio-intent"),
            recipe_anchor: "operator-mutation",
        },
        PatternSpec {
            id: "database-policy",
            description: "SQL or database-backed server with policy checks and response profiles.",
            recommended_template: Some("single-crate-public-stdio"),
            recipe_anchor: "database-policy",
        },
        PatternSpec {
            id: "public-release-ready",
            description:
                "Standalone public MCP repository with CI, CodeQL, governance, and snapshots.",
            recommended_template: Some("single-crate-public-stdio"),
            recipe_anchor: "public-release-ready",
        },
    ];

    PATTERNS
}

/// Finds an archetype by id.
pub fn find_pattern(id: &str) -> Option<PatternSpec> {
    patterns().iter().copied().find(|pattern| pattern.id == id)
}

/// Returns checked-in pattern manifest summaries.
pub fn pattern_manifests() -> &'static [PatternManifestSpec] {
    generated_registry::PATTERN_MANIFESTS
}

/// Iterates over manifest summaries that demonstrate the given archetype.
pub fn manifests_for_pattern<'a>(
    pattern_id: &'a str,
) -> impl Iterator<Item = &'static PatternManifestSpec> + 'a {
    pattern_manifests()
        .iter()
        .filter(move |manifest| manifest.patterns.contains(&pattern_id))
}

/// Returns the maintained template recommended for an archetype.
pub fn recommended_template_for_pattern(pattern_id: &str) -> Option<TemplateSpec> {
    find_pattern(pattern_id)
        .and_then(|pattern| pattern.recommended_template)
        .and_then(find_template)
}

/// Classifies a conformance issue found in a checked-in manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternConformanceSeverity {
    /// A contradiction in the manifest that should fail strict checks.
    Hard,
    /// A visible gap that is acceptable while the harness is advisory.
    Advisory,
}

/// Describes one downstream conformance finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternConformanceFinding {
    /// Manifest path that produced the finding.
    pub manifest_path: &'static str,
    /// Reference server named by the manifest.
    pub server_name: &'static str,
    /// Finding severity.
    pub severity: PatternConformanceSeverity,
    /// Contract area, such as `schema_snapshot` or `release_evidence`.
    pub contract: &'static str,
    /// Human-readable explanation.
    pub message: String,
}

/// Returns advisory and hard conformance findings for one manifest.
pub fn conformance_findings(manifest: &PatternManifestSpec) -> Vec<PatternConformanceFinding> {
    let mut findings = Vec::new();

    if manifest.schema_snapshot == "present" && manifest.conformance.schema_snapshot != "present" {
        findings.push(hard(
            manifest,
            "schema_snapshot",
            format!(
                "tool_surface.schema_snapshot is present but conformance.schema_snapshot is {}",
                manifest.conformance.schema_snapshot
            ),
        ));
    }

    if manifest.discovery.contains(&"schema_snapshot")
        && manifest.conformance.schema_snapshot != "present"
    {
        findings.push(hard(
            manifest,
            "schema_snapshot",
            format!(
                "discovery includes schema_snapshot but conformance.schema_snapshot is {}",
                manifest.conformance.schema_snapshot
            ),
        ));
    }

    if manifest.patterns.contains(&"analytics-scratchpad") && !manifest.scratchpad.supported {
        findings.push(hard(
            manifest,
            "scratchpad",
            "analytics-scratchpad pattern requires scratchpad.supported=true".to_string(),
        ));
    }

    if manifest.scratchpad.supported && !manifest.patterns.contains(&"analytics-scratchpad") {
        findings.push(hard(
            manifest,
            "scratchpad",
            "scratchpad.supported=true requires analytics-scratchpad pattern evidence".to_string(),
        ));
    }

    if !manifest.scratchpad.supported && manifest.scratchpad.engine != "none" {
        findings.push(hard(
            manifest,
            "scratchpad",
            format!(
                "scratchpad.supported=false must use engine=none, found {}",
                manifest.scratchpad.engine
            ),
        ));
    }

    if manifest.patterns.contains(&"operator-mutation")
        && !matches!(
            manifest.mutation_policy,
            "profile-gated" | "operator-only" | "external-policy"
        )
    {
        findings.push(hard(
            manifest,
            "tool_surface",
            format!(
                "operator-mutation requires a gated mutation policy, found {}",
                manifest.mutation_policy
            ),
        ));
    }

    if manifest.patterns.contains(&"hosted-http-auth")
        && !manifest.transports.contains(&"hosted-http")
        && !manifest.transports.contains(&"streamable-http")
    {
        findings.push(hard(
            manifest,
            "transport_contract",
            "hosted-http-auth requires hosted-http or streamable-http transport evidence"
                .to_string(),
        ));
    }

    if manifest.patterns.contains(&"public-release-ready")
        && manifest.conformance.release_evidence != "present"
    {
        findings.push(hard(
            manifest,
            "release_evidence",
            format!(
                "public-release-ready requires release_evidence=present, found {}",
                manifest.conformance.release_evidence
            ),
        ));
    }

    if manifest.patterns.contains(&"google-provider-read-only")
        && !manifest.default_profiles.contains(&"read_only")
    {
        findings.push(advisory(
            manifest,
            "profiles",
            "google-provider-read-only should expose read_only as a default profile".to_string(),
        ));
    }

    if manifest
        .auth_modes
        .iter()
        .any(|mode| !matches!(*mode, "none" | "database-policy" | "external-policy"))
        && manifest.conformance.auth_surface_contract == "unknown"
    {
        findings.push(advisory(
            manifest,
            "auth_surface_contract",
            "auth-enabled references should document auth-surface contract evidence".to_string(),
        ));
    }

    if manifest.conformance.transport_contract == "unknown" {
        findings.push(advisory(
            manifest,
            "transport_contract",
            "transport contract is still unknown".to_string(),
        ));
    }

    if manifest.conformance.hosted_validation == "unknown" {
        findings.push(advisory(
            manifest,
            "hosted_validation",
            "hosted validation evidence is still unknown".to_string(),
        ));
    }

    if manifest.conformance.release_evidence != "present" {
        findings.push(advisory(
            manifest,
            "release_evidence",
            format!(
                "release evidence is {}, so the row remains advisory",
                manifest.conformance.release_evidence
            ),
        ));
    }

    findings
}

fn hard(
    manifest: &PatternManifestSpec,
    contract: &'static str,
    message: String,
) -> PatternConformanceFinding {
    finding(
        manifest,
        PatternConformanceSeverity::Hard,
        contract,
        message,
    )
}

fn advisory(
    manifest: &PatternManifestSpec,
    contract: &'static str,
    message: String,
) -> PatternConformanceFinding {
    finding(
        manifest,
        PatternConformanceSeverity::Advisory,
        contract,
        message,
    )
}

fn finding(
    manifest: &PatternManifestSpec,
    severity: PatternConformanceSeverity,
    contract: &'static str,
    message: String,
) -> PatternConformanceFinding {
    PatternConformanceFinding {
        manifest_path: manifest.path,
        server_name: manifest.server.name,
        severity,
        contract,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_has_manifest_evidence() {
        for pattern in patterns() {
            assert!(
                manifests_for_pattern(pattern.id).next().is_some(),
                "missing manifest evidence for {}",
                pattern.id
            );
        }
    }

    #[test]
    fn every_manifest_pattern_has_registry_entry() {
        for manifest in pattern_manifests() {
            for pattern in manifest.patterns {
                assert!(
                    find_pattern(pattern).is_some(),
                    "{} references unregistered pattern {}",
                    manifest.path,
                    pattern
                );
            }
        }
    }

    #[test]
    fn recommended_templates_resolve() {
        for pattern in patterns() {
            if let Some(template_id) = pattern.recommended_template {
                assert!(
                    find_template(template_id).is_some(),
                    "recommended template `{template_id}` does not resolve"
                );
            }
        }
    }

    #[test]
    fn generated_manifest_summaries_include_reference_shape() {
        let gsc = pattern_manifests()
            .iter()
            .find(|manifest| manifest.server.name == "google-search-console-mcp")
            .unwrap_or_else(|| panic!("google-search-console manifest"));

        assert_eq!(gsc.mutation_policy, "profile-gated");
        assert!(gsc.scratchpad.supported);
        assert!(gsc.patterns.contains(&"analytics-scratchpad"));
        assert!(gsc.default_profiles.contains(&"read_only"));
        assert_eq!(gsc.conformance.schema_snapshot, "present");
        assert_eq!(gsc.conformance.transport_contract, "present");
    }

    #[test]
    fn manifests_have_no_hard_conformance_contradictions() {
        let hard_findings: Vec<_> = pattern_manifests()
            .iter()
            .flat_map(conformance_findings)
            .filter(|finding| finding.severity == PatternConformanceSeverity::Hard)
            .collect();

        assert!(
            hard_findings.is_empty(),
            "hard conformance findings: {hard_findings:#?}"
        );
    }
}
