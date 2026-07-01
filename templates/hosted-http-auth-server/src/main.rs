use hosted_http_auth_server::{build_router, HostedHttpConfig, HostedHttpServer};
use mcp_toolkit::server::tools::{
    render_tool_surface_command, render_tool_surface_help, tool_surface_command_from_env,
    ToolSurfaceCommand,
};
use mcp_toolkit_core::tool_inventory::READ_ONLY_PROFILE_KEY;
use tokio::net::TcpListener;

const BINARY_NAME: &str = "hosted-http-auth-server";

type MainResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> MainResult<()> {
    match tool_surface_command_from_env() {
        Ok(ToolSurfaceCommand::Serve) => serve().await,
        Ok(ToolSurfaceCommand::Help) => {
            print!("{}", render_tool_surface_help(BINARY_NAME));
            Ok(())
        }
        Ok(command) => print_tool_surface(command),
        Err(message) => {
            eprintln!("{message}");
            eprint!("{}", render_tool_surface_help(BINARY_NAME));
            std::process::exit(2);
        }
    }
}

async fn serve() -> MainResult<()> {
    let config = HostedHttpConfig::from_env()?;
    config.bind_safety().validate(config.bind_addr)?;

    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, build_router(config)?).await?;
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

fn server_for_active_profile() -> MainResult<(HostedHttpServer, String)> {
    let profile_key = std::env::var("EXAMPLE_MCP_TOOL_PROFILE")
        .unwrap_or_else(|_| READ_ONLY_PROFILE_KEY.to_string());
    Ok((
        HostedHttpServer::with_tool_profile(profile_key.clone())?,
        profile_key,
    ))
}
