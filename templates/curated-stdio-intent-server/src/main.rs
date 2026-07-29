use curated_stdio_intent_server::{IntentServer, IntentServerConfig};
use mcp_toolkit::client_config::{render_client_config, ClientConfigOptions};
use mcp_toolkit::doctor::inspect_project;
use mcp_toolkit::server::tools::{
    render_tool_surface_command, render_tool_surface_help, tool_surface_command_from_env,
    ToolSurfaceCommand,
};

const BINARY_NAME: &str = "curated-stdio-intent-server";

type MainResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> MainResult<()> {
    match tool_surface_command_from_env() {
        Ok(ToolSurfaceCommand::Serve) => serve().await,
        Ok(ToolSurfaceCommand::Help) => {
            print!("{}", render_tool_surface_help(BINARY_NAME));
            Ok(())
        }
        Ok(ToolSurfaceCommand::Doctor) => print_doctor(),
        Ok(ToolSurfaceCommand::PrintClientConfig) => print_client_config(),
        Ok(command) => print_tool_surface(command),
        Err(message) => {
            eprintln!("{message}");
            eprint!("{}", render_tool_surface_help(BINARY_NAME));
            std::process::exit(2);
        }
    }
}

async fn serve() -> MainResult<()> {
    let server = IntentServer::new(IntentServerConfig::from_env())?;
    mcp_toolkit::server::stdio::StdioServerBuilder::new()
        .serve(server)
        .await?;
    Ok(())
}

fn print_doctor() -> MainResult<()> {
    let report = inspect_project(std::env::current_dir()?);
    print!("{}", report.render());
    if report.ready() {
        Ok(())
    } else {
        std::process::exit(2);
    }
}

fn print_client_config() -> MainResult<()> {
    let options = ClientConfigOptions {
        root: std::env::current_dir()?,
        ..ClientConfigOptions::default()
    };
    print!("{}", render_client_config(&options)?);
    Ok(())
}

fn print_tool_surface(command: ToolSurfaceCommand) -> MainResult<()> {
    let (server, profile_key) = server_for_active_profile()?;
    let tools = server.tool_schema_snapshot_for_profile(&profile_key)?;
    if let Some(output) = render_tool_surface_command(command, &tools)? {
        print!("{output}");
    }
    Ok(())
}

fn server_for_active_profile() -> MainResult<(IntentServer, String)> {
    let config = IntentServerConfig::from_env();
    let profile_key = config.tool_profile.clone();
    Ok((IntentServer::new(config)?, profile_key))
}
