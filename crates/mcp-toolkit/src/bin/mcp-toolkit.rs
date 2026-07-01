use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use mcp_toolkit::client_config::{
    render_client_config, ClientConfigOptions, ClientConfigTransport,
};
use mcp_toolkit::doctor::inspect_project;
use mcp_toolkit::new_server::{
    default_template_id, default_toolkit_git_url, default_toolkit_root, generate_new_server,
    templates, NewServerOptions, ToolkitDependencySource,
};
use mcp_toolkit::patterns::{
    conformance_findings, find_pattern, manifests_for_pattern, pattern_manifests, patterns,
    PatternConformanceSeverity, PatternManifestSpec,
};
use mcp_toolkit::release_preflight::inspect_release_preflight;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("new") => run_new(&args[1..]),
        Some("doctor") => run_doctor(&args[1..]),
        Some("release-preflight") | Some("release_preflight") | Some("preflight") => {
            run_release_preflight(&args[1..])
        }
        Some("client-config") | Some("client_config") => run_client_config(&args[1..]),
        Some("templates") | Some("list-templates") => {
            print_templates();
            Ok(())
        }
        Some("conformance") => run_conformance(&args[1..]),
        Some("patterns") | Some("archetypes") => run_patterns(&args[1..]),
        Some("pattern") | Some("archetype") => run_pattern(&args[1..]),
        Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some("--version") | Some("-V") => {
            println!("mcp-toolkit {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(command) => Err(format!(
            "unknown command `{command}`; run `mcp-toolkit --help`"
        )),
    }
}

fn run_new(args: &[String]) -> Result<(), String> {
    let mut package_name: Option<String> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut template: Option<String> = None;
    let mut pattern: Option<String> = None;
    let mut toolkit_root: Option<PathBuf> = None;
    let mut toolkit_git: Option<String> = None;
    let mut overwrite = false;
    let mut positional = Vec::new();

    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--name" => {
                package_name = Some(take_value(args, &mut index, "--name")?);
            }
            "--output" | "-o" => {
                output_dir = Some(PathBuf::from(take_value(args, &mut index, "--output")?));
            }
            "--template" | "-t" => {
                template = Some(take_value(args, &mut index, "--template")?);
            }
            "--pattern" | "--archetype" => {
                pattern = Some(take_value(args, &mut index, "--pattern")?);
            }
            "--toolkit-root" => {
                toolkit_root = Some(PathBuf::from(take_value(
                    args,
                    &mut index,
                    "--toolkit-root",
                )?));
            }
            "--toolkit-git" => {
                toolkit_git = Some(take_value(args, &mut index, "--toolkit-git")?);
            }
            "--force" => {
                overwrite = true;
            }
            "--help" | "-h" => {
                print_new_help();
                return Ok(());
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option `{value}`"));
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if package_name.is_none() {
        package_name = positional.first().cloned();
    }
    let package_name = package_name.ok_or_else(|| {
        "missing package name; use `mcp-toolkit new --name my-server`".to_string()
    })?;
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from(&package_name));
    let selected_pattern = match pattern {
        Some(pattern_id) => {
            let pattern = find_pattern(&pattern_id).ok_or_else(|| {
                format!("unknown pattern `{pattern_id}`; run `mcp-toolkit patterns`")
            })?;
            Some(pattern)
        }
        None => None,
    };
    let template = match (template, selected_pattern) {
        (Some(template), _) => template,
        (None, Some(pattern)) => pattern
            .recommended_template
            .ok_or_else(|| {
                format!(
                    "pattern `{}` does not declare a recommended template; use --template",
                    pattern.id
                )
            })?
            .to_string(),
        (None, None) => default_template_id().to_string(),
    };
    let toolkit_dependency = match (toolkit_root, toolkit_git) {
        (Some(_), Some(_)) => {
            return Err("use either --toolkit-root or --toolkit-git, not both".to_string());
        }
        (Some(root), None) => ToolkitDependencySource::LocalPath(canonical_toolkit_root(root)?),
        (None, Some(url)) => ToolkitDependencySource::Git(url),
        (None, None) => ToolkitDependencySource::LocalPath(default_toolkit_root()),
    };

    let summary = generate_new_server(&NewServerOptions {
        template,
        package_name,
        output_dir,
        toolkit_dependency,
        overwrite,
    })
    .map_err(|error| error.to_string())?;

    if let Some(pattern) = selected_pattern {
        println!(
            "Pattern: {} (recipe docs/pattern-recipes.md#{})",
            pattern.id, pattern.recipe_anchor
        );
        if pattern.id == "analytics-scratchpad" {
            println!(
                "Scratchpad: add `mcp-toolkit-scratchpad` when replacing the starter tools with large-result ingest/query tools."
            );
        }
    }
    println!(
        "Created {} from `{}` in {}",
        summary.package_name,
        summary.template.id,
        summary.output_dir.display()
    );
    println!(
        "Files: {} created, {} unchanged, {} overwritten",
        summary.created_files, summary.unchanged_files, summary.overwritten_files
    );
    println!();
    println!("Next:");
    println!("  mcp-toolkit doctor {}", summary.output_dir.display());
    println!(
        "  mcp-toolkit client-config {}",
        summary.output_dir.display()
    );
    println!("  cd {}", summary.output_dir.display());
    println!("  cargo fmt --all --check");
    println!("  cargo test --all-targets --all-features");
    println!();
    println!(
        "For public or portable repos, rerun with `--toolkit-git {}` instead of local path dependencies.",
        default_toolkit_git_url()
    );

    Ok(())
}

fn run_client_config(args: &[String]) -> Result<(), String> {
    let mut options = ClientConfigOptions::default();
    let mut positional = Vec::new();

    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--name" => {
                options.server_name = Some(take_value(args, &mut index, "--name")?);
            }
            "--transport" => {
                let value = take_value(args, &mut index, "--transport")?;
                options.transport =
                    Some(ClientConfigTransport::parse(&value).ok_or_else(|| {
                        format!("unknown transport `{value}`; use `stdio` or `http`")
                    })?);
            }
            "--command" => {
                options.command = Some(take_value(args, &mut index, "--command")?);
            }
            "--url" => {
                options.url = Some(take_value(args, &mut index, "--url")?);
            }
            "--profile" => {
                options.profile = take_value(args, &mut index, "--profile")?;
            }
            "--help" | "-h" => {
                print_client_config_help();
                return Ok(());
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown client-config option `{value}`"));
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    match positional.as_slice() {
        [] => {}
        [path] => options.root = PathBuf::from(path),
        _ => return Err("usage: mcp-toolkit client-config [generated-server-dir]".to_string()),
    }

    let root = if options.root.is_absolute() {
        options.root.clone()
    } else {
        env::current_dir()
            .map_err(|error| format!("failed to resolve current directory: {error}"))?
            .join(&options.root)
    };
    options.root = root;

    let output = render_client_config(&options).map_err(|error| error.to_string())?;
    print!("{output}");
    Ok(())
}

fn run_doctor(args: &[String]) -> Result<(), String> {
    let root = match args {
        [] => PathBuf::from("."),
        [flag] if flag == "--help" || flag == "-h" => {
            print_doctor_help();
            return Ok(());
        }
        [path] if !path.starts_with('-') => PathBuf::from(path),
        [flag] if flag.starts_with('-') => return Err(format!("unknown doctor option `{flag}`")),
        _ => return Err("usage: mcp-toolkit doctor [path]".to_string()),
    };

    if !root.exists() {
        return Err(format!("doctor path `{}` does not exist", root.display()));
    }
    if !root.is_dir() {
        return Err(format!(
            "doctor path `{}` is not a directory",
            root.display()
        ));
    }

    let report = inspect_project(root);
    print!("{}", report.render());

    if report.ready() {
        Ok(())
    } else {
        Err("doctor found missing required generated-server files".to_string())
    }
}

fn run_release_preflight(args: &[String]) -> Result<(), String> {
    let root = match args {
        [] => PathBuf::from("."),
        [flag] if flag == "--help" || flag == "-h" => {
            print_release_preflight_help();
            return Ok(());
        }
        [path] if !path.starts_with('-') => PathBuf::from(path),
        [flag] if flag.starts_with('-') => {
            return Err(format!("unknown release-preflight option `{flag}`"));
        }
        _ => return Err("usage: mcp-toolkit release-preflight [path]".to_string()),
    };

    if !root.exists() {
        return Err(format!(
            "release-preflight path `{}` does not exist",
            root.display()
        ));
    }
    if !root.is_dir() {
        return Err(format!(
            "release-preflight path `{}` is not a directory",
            root.display()
        ));
    }

    let report = inspect_release_preflight(root);
    print!("{}", report.render());

    if report.ready() {
        Ok(())
    } else {
        Err("release-preflight found missing public-readiness requirements".to_string())
    }
}

fn run_conformance(args: &[String]) -> Result<(), String> {
    let mut strict = false;
    let mut server: Option<String> = None;
    let mut pattern: Option<String> = None;

    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--strict" => {
                strict = true;
            }
            "--server" => {
                server = Some(take_value(args, &mut index, "--server")?);
            }
            "--pattern" | "--archetype" => {
                pattern = Some(take_value(args, &mut index, "--pattern")?);
            }
            "--help" | "-h" => {
                print_conformance_help();
                return Ok(());
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown conformance option `{value}`"));
            }
            value => {
                if server.is_some() || pattern.is_some() {
                    return Err("use at most one positional server or pattern filter".to_string());
                }
                if find_pattern(value).is_some() {
                    pattern = Some(value.to_string());
                } else {
                    server = Some(value.to_string());
                }
            }
        }
        index += 1;
    }

    if server.is_some() && pattern.is_some() {
        return Err("use either --server or --pattern, not both".to_string());
    }

    let manifests = filtered_manifests(server.as_deref(), pattern.as_deref())?;
    print_conformance_report(&manifests);

    if strict {
        let hard_count = manifests
            .iter()
            .flat_map(|manifest| conformance_findings(manifest))
            .filter(|finding| finding.severity == PatternConformanceSeverity::Hard)
            .count();

        if hard_count > 0 {
            return Err(format!(
                "conformance found {hard_count} hard manifest violation{}",
                if hard_count == 1 { "" } else { "s" }
            ));
        }
    }

    Ok(())
}

fn filtered_manifests(
    server: Option<&str>,
    pattern: Option<&str>,
) -> Result<Vec<&'static PatternManifestSpec>, String> {
    let manifests: Vec<_> = pattern_manifests()
        .iter()
        .filter(|manifest| {
            server
                .map(|server| manifest.server.name == server)
                .unwrap_or(true)
        })
        .filter(|manifest| {
            pattern
                .map(|pattern| manifest.patterns.contains(&pattern))
                .unwrap_or(true)
        })
        .collect();

    if manifests.is_empty() {
        match (server, pattern) {
            (Some(server), _) => Err(format!("unknown server `{server}`")),
            (_, Some(pattern)) => Err(format!(
                "no conformance manifests found for pattern `{pattern}`"
            )),
            _ => Err("no conformance manifests found".to_string()),
        }
    } else {
        Ok(manifests)
    }
}

fn print_conformance_report(manifests: &[&PatternManifestSpec]) {
    println!("Downstream MCP conformance posture:");
    for manifest in manifests {
        let findings = conformance_findings(manifest);
        let hard_count = findings
            .iter()
            .filter(|finding| finding.severity == PatternConformanceSeverity::Hard)
            .count();
        let advisory_count = findings
            .iter()
            .filter(|finding| finding.severity == PatternConformanceSeverity::Advisory)
            .count();
        println!(
            "  {:30} hard={}, advisory={} - {}",
            manifest.server.name, hard_count, advisory_count, manifest.path
        );
        println!(
            "    schema={} transport={} auth={} domain={} hosted={} release={}",
            manifest.conformance.schema_snapshot,
            manifest.conformance.transport_contract,
            manifest.conformance.auth_surface_contract,
            manifest.conformance.domain_contracts,
            manifest.conformance.hosted_validation,
            manifest.conformance.release_evidence
        );
        println!(
            "    patterns: {}; transports: {}; auth: {}",
            join_values(manifest.patterns),
            join_values(manifest.transports),
            join_values(manifest.auth_modes)
        );
        for finding in findings {
            println!(
                "    {} {}: {}",
                match finding.severity {
                    PatternConformanceSeverity::Hard => "hard",
                    PatternConformanceSeverity::Advisory => "advisory",
                },
                finding.contract,
                finding.message
            );
        }
    }
    println!();
    println!("Use `mcp-toolkit conformance --strict` to fail on hard manifest contradictions.");
}

fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("missing value for {}", option))
}

fn canonical_toolkit_root(root: PathBuf) -> Result<PathBuf, String> {
    let root = if root.is_absolute() {
        root
    } else {
        env::current_dir()
            .map_err(|error| format!("failed to resolve current directory: {error}"))?
            .join(root)
    };
    fs::canonicalize(&root)
        .map_err(|error| format!("invalid --toolkit-root `{}`: {error}", root.display()))
}

fn run_patterns(args: &[String]) -> Result<(), String> {
    match args {
        [] => {
            print_patterns();
            Ok(())
        }
        [flag] if flag == "--help" || flag == "-h" => {
            print_patterns_help();
            Ok(())
        }
        [pattern_id] if !pattern_id.starts_with('-') => print_pattern(pattern_id),
        [flag] if flag.starts_with('-') => Err(format!("unknown patterns option `{flag}`")),
        _ => Err("usage: mcp-toolkit patterns [pattern-id]".to_string()),
    }
}

fn run_pattern(args: &[String]) -> Result<(), String> {
    match args {
        [flag] if flag == "--help" || flag == "-h" => {
            println!("Usage:");
            println!("  mcp-toolkit pattern <pattern-id>");
            Ok(())
        }
        [pattern_id] => print_pattern(pattern_id),
        [] => Err("missing pattern id; run `mcp-toolkit patterns`".to_string()),
        _ => Err("usage: mcp-toolkit pattern <pattern-id>".to_string()),
    }
}

fn print_templates() {
    println!("Maintained mcp-toolkit templates:");
    for template in templates() {
        println!("  {:28} {}", template.id, template.description);
    }
}

fn print_patterns() {
    println!("Maintained mcp-toolkit archetypes:");
    for pattern in patterns() {
        let template = pattern.recommended_template.unwrap_or("manual");
        let evidence_count = manifests_for_pattern(pattern.id).count();
        println!(
            "  {:28} {:28} {} ({} manifest{})",
            pattern.id,
            template,
            pattern.description,
            evidence_count,
            if evidence_count == 1 { "" } else { "s" }
        );
    }
    println!();
    println!("Run `mcp-toolkit patterns <id>` for manifest evidence and recipe links.");
}

fn print_pattern(pattern_id: &str) -> Result<(), String> {
    let pattern = find_pattern(pattern_id)
        .ok_or_else(|| format!("unknown pattern `{pattern_id}`; run `mcp-toolkit patterns`"))?;
    let manifests: Vec<_> = manifests_for_pattern(pattern.id).collect();

    println!("Archetype: {}", pattern.id);
    println!("Summary: {}", pattern.description);
    println!(
        "Recommended template: {}",
        pattern.recommended_template.unwrap_or("manual")
    );
    println!("Recipe: docs/pattern-recipes.md#{}", pattern.recipe_anchor);
    println!("Atlas: docs/reference-server-atlas.md");
    println!();
    println!("Manifest evidence:");
    for manifest in manifests {
        println!(
            "  {} ({}) - {}",
            manifest.server.name, manifest.server.role, manifest.path
        );
        println!("    transports: {}", join_values(manifest.transports));
        println!("    auth: {}", join_values(manifest.auth_modes));
        println!(
            "    tools: mutation={}, schema_snapshot={}, discovery={}",
            manifest.mutation_policy,
            manifest.schema_snapshot,
            join_values(manifest.discovery)
        );
        println!(
            "    profiles: {} (default: {})",
            join_values(manifest.profiles),
            join_values(manifest.default_profiles)
        );
        println!(
            "    scratchpad: {} via {}",
            if manifest.scratchpad.supported {
                "supported"
            } else {
                "not supported"
            },
            manifest.scratchpad.engine
        );
        println!(
            "    conformance: schema={}, transport={}, auth={}, domain={}, hosted={}, release={}",
            manifest.conformance.schema_snapshot,
            manifest.conformance.transport_contract,
            manifest.conformance.auth_surface_contract,
            manifest.conformance.domain_contracts,
            manifest.conformance.hosted_validation,
            manifest.conformance.release_evidence
        );
    }

    Ok(())
}

fn join_values(values: &[&str]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn print_help() {
    println!("mcp-toolkit {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage:");
    println!("  mcp-toolkit new --name <package> [--template <id>] [--output <relative-dir>]");
    println!("  mcp-toolkit doctor [generated-server-dir]");
    println!("  mcp-toolkit release-preflight [generated-server-dir]");
    println!("  mcp-toolkit client-config [generated-server-dir]");
    println!("  mcp-toolkit templates");
    println!("  mcp-toolkit conformance [--server <name>|--pattern <id>] [--strict]");
    println!("  mcp-toolkit patterns [pattern-id]");
    println!();
    println!("Run `mcp-toolkit new --help`, `mcp-toolkit doctor --help`,");
    println!("`mcp-toolkit release-preflight --help`, or `mcp-toolkit client-config --help` for options.");
}

fn print_new_help() {
    println!("Usage:");
    println!("  mcp-toolkit new --name <package> [options]");
    println!("  mcp-toolkit new <package> [options]");
    println!();
    println!("Options:");
    println!(
        "  -t, --template <id>       Template id or alias (default: {})",
        default_template_id()
    );
    println!("      --pattern <id>        Select the recommended template for an archetype");
    println!("  -o, --output <dir>        Relative output directory (default: package name)");
    println!("      --toolkit-root <dir>  Local mcp-toolkit-rs checkout for path dependencies");
    println!("      --toolkit-git <url>   Git URL for portable toolkit dependencies");
    println!("      --force               Overwrite generated files that differ");
    println!("  -h, --help                Show this help");
    println!();
    print_templates();
    println!();
    println!("Run `mcp-toolkit patterns` to choose by server archetype instead of template id.");
}

fn print_doctor_help() {
    println!("Usage:");
    println!("  mcp-toolkit doctor [generated-server-dir]");
    println!();
    println!("Checks a generated Rust MCP server for starter source, contract, probe,");
    println!("and hosted validation files, then prints the next validation commands.");
}

fn print_release_preflight_help() {
    println!("Usage:");
    println!("  mcp-toolkit release-preflight [generated-server-dir]");
    println!();
    println!("Checks a generated Rust MCP server for public-ready README, license,");
    println!("CI, CodeQL, dependency governance, schema/probe proof, and obvious");
    println!("high-confidence secret markers without executing generated code.");
}

fn print_client_config_help() {
    println!("Usage:");
    println!("  mcp-toolkit client-config [generated-server-dir] [options]");
    println!();
    println!("Options:");
    println!("      --name <server-name>  MCP client server name (default: Cargo package name)");
    println!("      --transport <kind>    stdio or http (default: infer from generated files)");
    println!("      --command <path>      Stdio command path (default: target/release/<package>)");
    println!(
        "      --url <url>           Hosted HTTP MCP URL (default: http://127.0.0.1:9411/mcp)"
    );
    println!("      --profile <profile>   Tool profile for stdio env (default: read_only)");
    println!("  -h, --help                Show this help");
}

fn print_conformance_help() {
    println!("Usage:");
    println!("  mcp-toolkit conformance");
    println!("  mcp-toolkit conformance --server <server-name>");
    println!("  mcp-toolkit conformance --pattern <pattern-id>");
    println!("  mcp-toolkit conformance <server-name-or-pattern-id>");
    println!();
    println!("Reports advisory downstream conformance posture from checked-in pattern manifests.");
    println!("Use --strict to fail only on hard manifest contradictions.");
}

fn print_patterns_help() {
    println!("Usage:");
    println!("  mcp-toolkit patterns");
    println!("  mcp-toolkit patterns <pattern-id>");
    println!();
    println!("Patterns include manifest evidence from docs/pattern-manifests/*.json");
    println!("and link to docs/reference-server-atlas.md plus docs/pattern-recipes.md.");
    println!();
    print_patterns();
}
