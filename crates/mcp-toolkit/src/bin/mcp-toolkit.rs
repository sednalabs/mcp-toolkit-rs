use std::env;
use std::path::PathBuf;
use std::process;

use mcp_toolkit::new_server::{
    default_template_id, default_toolkit_git_url, default_toolkit_root, generate_new_server,
    templates, NewServerOptions, ToolkitDependencySource,
};

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("new") => run_new(&args[1..]),
        Some("templates") | Some("list-templates") => {
            print_templates();
            Ok(())
        }
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
    let mut template = default_template_id().to_string();
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
                template = take_value(args, &mut index, "--template")?;
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
    let toolkit_dependency = match (toolkit_root, toolkit_git) {
        (Some(_), Some(_)) => {
            return Err("use either --toolkit-root or --toolkit-git, not both".to_string());
        }
        (Some(root), None) => ToolkitDependencySource::LocalPath(root),
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

fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("missing value for {}", option))
}

fn print_templates() {
    println!("Maintained mcp-toolkit templates:");
    for template in templates() {
        println!("  {:28} {}", template.id, template.description);
    }
}

fn print_help() {
    println!("mcp-toolkit {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage:");
    println!("  mcp-toolkit new --name <package> [--template <id>] [--output <relative-dir>]");
    println!("  mcp-toolkit templates");
    println!();
    println!("Run `mcp-toolkit new --help` for generator options.");
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
    println!("  -o, --output <dir>        Relative output directory (default: package name)");
    println!("      --toolkit-root <dir>  Local mcp-toolkit-rs checkout for path dependencies");
    println!("      --toolkit-git <url>   Git URL for portable toolkit dependencies");
    println!("      --force               Overwrite generated files that differ");
    println!("  -h, --help                Show this help");
    println!();
    print_templates();
}
