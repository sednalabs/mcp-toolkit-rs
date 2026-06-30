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
        PatternManifestSpec, PatternReferenceSpec, PatternScratchpadSpec, PatternServerSpec,
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
    }
}
