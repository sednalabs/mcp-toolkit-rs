use curated_stdio_intent_server::{IntentServer, IntentServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = IntentServer::new(IntentServerConfig::from_env())?;
    mcp_toolkit::server::stdio::StdioServerBuilder::new()
        .serve(server)
        .await?;
    Ok(())
}
