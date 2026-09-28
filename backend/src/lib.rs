mod config;
mod engine;
mod host;
pub mod scorer;
pub mod state;
pub use config::Config;
use gateway_plugin_sdk::{
    Manifest,
    call::management::*,
    client::{AuthorError, ComposedPlugin, Empty, PluginBuilder, TypedReply, methods},
};
use std::sync::Arc;

pub const PLUGIN_ID: &str = "jiahao6635.quality-guard";
pub fn manifest() -> Result<Manifest, gateway_plugin_sdk::ManifestError> {
    Manifest::from_author_slice(include_bytes!("../../plugin.json"))
}
pub fn plugin(config: Config) -> Result<ComposedPlugin, AuthorError> {
    let config = Arc::new(config);
    let maintenance_config = Arc::clone(&config);
    let status_config = Arc::clone(&config);
    PluginBuilder::from_json(include_bytes!("../../plugin.json"))?
        .on(methods::RECONCILE, move |call| {
            let config = Arc::clone(&maintenance_config);
            async move {
                engine::reconcile(&call.host, &config).await?;
                Ok(TypedReply::new(Empty {}))
            }
        })?
        .management(
            ManagementRegistration {
                routes: vec![ManagementRoute {
                    method: "GET".into(),
                    path: "/status".into(),
                    request_content_types: vec![],
                    response_content_types: vec!["application/json".into()],
                }],
                resources: vec![],
                pages: vec![],
                callbacks: vec![],
            },
            move |call| {
                let config = Arc::clone(&status_config);
                async move {
                    if call.request.method != "GET" || call.request.path != "/status" {
                        return Err(host::fault("unknown_route"));
                    }
                    let value = engine::status(&call.host, &config).await?;
                    Ok(TypedReply::new(ManagementResponse {
                        status: 200,
                        content_type: "application/json".into(),
                    })
                    .with_payload(
                        serde_json::to_vec(&value).map_err(|_| host::fault("status_encode"))?,
                    ))
                }
            },
        )?
        .command_line(
            CommandRegistration {
                commands: vec![
                    CommandDescriptor {
                        name: "tick".into(),
                        description: "执行一个到期账号的一道探题；不修改组成员".into(),
                        parameters: vec![],
                    },
                    CommandDescriptor {
                        name: "status".into(),
                        description: "查看配置范围、探测证据与组同步状态".into(),
                        parameters: vec![],
                    },
                ],
            },
            move |call| {
                let config = Arc::clone(&config);
                async move {
                    if !call.request.arguments.is_empty() {
                        return Err(host::fault("unexpected_arguments"));
                    }
                    let value = match call.request.name.as_str() {
                        "tick" => engine::tick(&call.host, &config).await?,
                        "status" => engine::status(&call.host, &config).await?,
                        _ => return Err(host::fault("unknown_command")),
                    };
                    Ok(TypedReply::new(CommandResult {
                        stdout: format!(
                            "{}\n",
                            serde_json::to_string_pretty(&value)
                                .map_err(|_| host::fault("result_encode"))?
                        ),
                        stderr: String::new(),
                        exit_code: 0,
                        accounts: vec![],
                    }))
                }
            },
        )?
        .build()
}
