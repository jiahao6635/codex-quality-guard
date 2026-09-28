use codex_quality_guard::{Config, PLUGIN_ID, manifest, plugin};
use gateway_plugin_sdk::client::{PluginSession, SessionConfig, SessionError};
use std::collections::BTreeSet;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = PluginSession::accept(
        tokio::io::stdin(),
        tokio::io::stdout(),
        SessionConfig::default(),
    )
    .await?;
    let manifest = manifest()?;
    let handshake = session.handshake();
    if handshake.plugin_id != PLUGIN_ID
        || handshake.contributes != manifest.contributes
        || handshake
            .permissions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            != manifest.permissions
    {
        return Err(SessionError::Handshake.into());
    }
    let config: Config = serde_json::from_value(handshake.configuration.clone())?;
    config.validate()?;
    session.run(plugin(config)?).await?;
    Ok(())
}
