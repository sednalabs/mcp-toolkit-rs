use hosted_http_auth_server::{build_router, HostedHttpConfig};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = HostedHttpConfig::from_env()?;
    config.bind_safety().validate(config.bind_addr)?;

    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, build_router(config)?).await?;
    Ok(())
}
