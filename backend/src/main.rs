use codex_quality_guard::{Config, PLUGIN_ID, manifest, plugin};
use gateway_plugin_sdk::client::{PluginSession, SessionConfig, SessionError};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = PluginSession::accept(
        tokio::io::stdin(),
        tokio::io::stdout(),
        SessionConfig {
            // 后台维护 v2 由宿主持有父调用；页面刷新不影响其生命周期。
            maximum_call_timeout: std::time::Duration::from_secs(600),
            ..SessionConfig::default()
        },
    )
    .await?;
    let manifest = manifest()?;
    let handshake = session.handshake();
    if handshake.plugin_id != PLUGIN_ID || handshake.contributes != manifest.contributes {
        return Err(SessionError::Handshake.into());
    }
    let config: Config = serde_json::from_value(handshake.configuration.clone())?;
    config.validate()?;
    session.run(plugin(config)?).await?;
    Ok(())
}
