const STARTER_TEMPLATES_DOC: &str = include_str!("../../../docs/starter-templates.md");
const EASY_SERVER_ERGONOMICS_DOC: &str = include_str!("../../../docs/easy-server-ergonomics.md");
const PROVIDER_AUTH_CLIENT_CONFIG_DOC: &str =
    include_str!("../../../docs/provider-auth-and-client-config.md");
const GUARDED_ACTION_DOC: &str = include_str!("../../../docs/guarded-action-pattern.md");
const CODEQL_REUSE_DOC: &str = include_str!("../../../docs/codeql-query-pack-reuse.md");

#[test]
fn starter_templates_doc_mentions_standalone_public_template() {
    for needle in [
        "templates/single-crate-public-stdio-server",
        "standalone public stdio",
        "StdioServerBuilder",
        "ToolCatalog",
        "CodeQL workflow-security queries",
        "dependency governance",
    ] {
        assert!(
            STARTER_TEMPLATES_DOC.contains(needle),
            "starter template doc is missing `{needle}`"
        );
    }
}

#[test]
fn starter_templates_doc_mentions_generator_front_door() {
    for needle in [
        "mcp-toolkit --bin mcp-toolkit -- new",
        "mcp-toolkit patterns",
        "mcp-toolkit patterns <id>",
        "mcp-toolkit templates",
        "--pattern <id>",
        "--toolkit-git",
        "--force",
        "evidence behind an archetype",
        "LocalMcpHttpServerBuilder",
    ] {
        assert!(
            STARTER_TEMPLATES_DOC.contains(needle),
            "starter template doc is missing generator front-door detail `{needle}`"
        );
    }
}

#[test]
fn starter_templates_doc_distinguishes_curated_and_standalone_ci() {
    for needle in [
        "minimal\n`.github/workflows/rust-baseline.yml`",
        "does not carry the standalone public template's CodeQL",
        "Inside a generated standalone repository",
        "./scripts/rebaseline_tool_schema_snapshot.sh",
    ] {
        assert!(
            STARTER_TEMPLATES_DOC.contains(needle),
            "starter template doc is missing curated-vs-standalone detail `{needle}`"
        );
    }
}

#[test]
fn ergonomics_docs_cover_guarded_actions_and_redacted_outputs() {
    for needle in [
        "GuardedActionPosture",
        "GuardedActionRuntimeMode",
        "Redacted Structured Output",
    ] {
        assert!(
            EASY_SERVER_ERGONOMICS_DOC.contains(needle),
            "easy server ergonomics doc is missing `{needle}`"
        );
    }
}

#[test]
fn provider_auth_docs_cover_profiles_google_and_client_config() {
    for needle in [
        "MCP Auth",
        "Provider auth",
        "Tool profiles",
        "auth_status",
        "read_only",
        "operator",
        "quota project",
        "gcloud auth application-default set-quota-project YOUR_PROJECT",
        "service-account",
        "[mcp_servers.my_mcp_server]",
        "TOOL_DENIED_READ_ONLY_PROFILE",
        "restart the MCP client",
    ] {
        assert!(
            PROVIDER_AUTH_CLIENT_CONFIG_DOC.contains(needle),
            "provider auth/client config doc is missing `{needle}`"
        );
    }
}

#[test]
fn guarded_action_pattern_doc_names_core_types() {
    for needle in [
        "GuardedActionPlanSeed",
        "GuardedActionPreview",
        "GuardedActionApply",
        "ToolCapability::with_risk_posture",
    ] {
        assert!(
            GUARDED_ACTION_DOC.contains(needle),
            "guarded action pattern doc is missing `{needle}`"
        );
    }
}

#[test]
fn codeql_reuse_doc_mentions_template_and_query_tests() {
    for needle in [
        "templates/single-crate-public-stdio-server",
        "codeql-query-tests",
        "qlpack.yml",
        "fork-safe",
    ] {
        assert!(
            CODEQL_REUSE_DOC.contains(needle),
            "CodeQL reuse doc is missing `{needle}`"
        );
    }
}
