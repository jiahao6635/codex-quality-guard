mod config;
mod engine;
mod host;
mod jobs;
pub mod scorer;
mod settings;
pub mod state;
pub use config::Config;
use gateway_plugin_sdk::{
    Manifest,
    call::management::*,
    client::{AuthorError, ComposedPlugin, Empty, PluginBuilder, TypedReply, methods},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const PLUGIN_ID: &str = "jiahao6635.quality-guard";
pub fn manifest() -> Result<Manifest, gateway_plugin_sdk::ManifestError> {
    Manifest::from_author_slice(include_bytes!("../../plugin.json"))
}
pub fn plugin(config: Config) -> Result<ComposedPlugin, AuthorError> {
    let config = Arc::new(config);
    let maintenance_config = Arc::clone(&config);
    let status_config = Arc::clone(&config);
    let worker_supported = Arc::new(AtomicBool::new(false));
    let management_worker_supported = Arc::clone(&worker_supported);
    PluginBuilder::from_json(include_bytes!("../../plugin.json"))?
        .on(methods::RECONCILE, move |call| {
            let config = Arc::clone(&maintenance_config);
            let worker_supported = Arc::clone(&worker_supported);
            async move {
                worker_supported.store(call.context.timeout_ms >= 600_000, Ordering::Relaxed);
                let started = Instant::now();
                engine::reconcile(&call.host, &config).await?;
                let remaining = Duration::from_millis(call.context.timeout_ms)
                    .saturating_sub(started.elapsed())
                    .saturating_sub(Duration::from_secs(30));
                if worker_supported.load(Ordering::Relaxed)
                    && remaining >= Duration::from_secs(1)
                    && jobs::run_one(
                        &call.host,
                        &config,
                        &call.context.incarnation,
                        remaining.min(Duration::from_secs(570)),
                    )
                    .await?
                {
                    return Ok(TypedReply::new(Empty {}));
                }
                if config.enabled && config.auto_probe {
                    // 为证据落库预留 5 秒；父调用结束后不能留下脱离生命周期的推理任务。
                    let remaining = Duration::from_millis(call.context.timeout_ms)
                        .saturating_sub(started.elapsed())
                        .saturating_sub(Duration::from_secs(5));
                    if remaining >= Duration::from_secs(1) {
                        engine::tick(
                            &call.host,
                            &config,
                            None,
                            remaining.min(Duration::from_secs(
                                if worker_supported.load(Ordering::Relaxed) {
                                    570
                                } else {
                                    20
                                },
                            )),
                        )
                        .await?;
                    }
                }
                Ok(TypedReply::new(Empty {}))
            }
        })?
        .management(
            ManagementRegistration {
                routes: vec![
                    ManagementRoute {
                        method: "GET".into(),
                        path: "jobs".into(),
                        request_content_types: vec![],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "jobs".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "job".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "job-cancel".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "GET".into(),
                        path: "settings".into(),
                        request_content_types: vec![],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "settings".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "GET".into(),
                        path: "status".into(),
                        request_content_types: vec![],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "evidence".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "probe".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "visual".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "visual-evidence".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "logic".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "logic-evidence".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                    ManagementRoute {
                        method: "POST".into(),
                        path: "visual-review".into(),
                        request_content_types: vec!["application/json".into()],
                        response_content_types: vec!["application/json".into()],
                    },
                ],
                resources: vec![ManagementResource {
                    path: "web/index.html".into(),
                    public: false,
                }],
                pages: vec![
                    ManagementPage {
                        id: "quality-probes".into(),
                        title: "账号质量探针".into(),
                        description: Some(
                            "逐账号运行 ModelTrace 三题指纹、鹈鹕绘图与糖果逻辑测试".into(),
                        ),
                        entry: "web/index.html".into(),
                        icon: None,
                    },
                    ManagementPage {
                        id: "probe-settings".into(),
                        title: "探针设置".into(),
                        description: Some("选择纳管账号、检测方式与探针额度".into()),
                        entry: "web/index.html".into(),
                        icon: None,
                    },
                ],
                callbacks: vec![],
            },
            move |call| {
                let config = Arc::clone(&status_config);
                let worker_supported = Arc::clone(&management_worker_supported);
                async move {
                    let value = match (call.request.method.as_str(), call.request.path.as_str()) {
                        ("GET", "jobs") => {
                            let mut value = jobs::list(&call.host).await?;
                            value["worker_supported"] =
                                worker_supported.load(Ordering::Relaxed).into();
                            value
                        }
                        ("POST", "jobs") => {
                            if !worker_supported.load(Ordering::Relaxed) {
                                return Err(host::fault(
                                    "background_worker_requires_maintenance_v2",
                                ));
                            }
                            let input = serde_json::from_slice(&call.payload)
                                .map_err(|_| host::fault("invalid_job_request"))?;
                            jobs::enqueue(&call.host, &config, input).await?
                        }
                        ("POST", "job" | "job-cancel") => {
                            let input = serde_json::from_slice(&call.payload)
                                .map_err(|_| host::fault("invalid_job_request"))?;
                            if call.request.path == "job" {
                                jobs::detail(&call.host, input).await?
                            } else {
                                jobs::cancel(&call.host, input).await?
                            }
                        }
                        ("GET", "settings") => {
                            settings::read(&call.host, &call.context.instance_id).await?
                        }
                        ("POST", "settings") => {
                            let input = serde_json::from_slice(&call.payload)
                                .map_err(|_| host::fault("invalid_settings_request"))?;
                            settings::save(&call.host, &call.context.instance_id, input).await?
                        }
                        ("GET", "status") => engine::status(&call.host, &config).await?,
                        ("POST", "visual" | "logic") => {
                            let input = serde_json::from_slice(&call.payload)
                                .map_err(|_| host::fault("invalid_visual_request"))?;
                            engine::manual_test(
                                &call.host,
                                &config,
                                input,
                                if call.request.path == "visual" {
                                    engine::ManualCase::Visual
                                } else {
                                    engine::ManualCase::Logic
                                },
                                probe_timeout(call.context.timeout_ms)?,
                            )
                            .await?
                        }
                        ("POST", "visual-review") => {
                            let input = serde_json::from_slice(&call.payload)
                                .map_err(|_| host::fault("invalid_visual_review"))?;
                            engine::visual_review(&call.host, &config, input).await?
                        }
                        ("POST", "probe" | "evidence" | "visual-evidence" | "logic-evidence") => {
                            #[derive(serde::Deserialize)]
                            #[serde(deny_unknown_fields)]
                            struct Probe {
                                account_id: String,
                            }
                            let input: Probe = serde_json::from_slice(&call.payload)
                                .map_err(|_| host::fault("invalid_probe_request"))?;
                            if ["visual-evidence", "logic-evidence"]
                                .contains(&call.request.path.as_str())
                            {
                                engine::manual_evidence(
                                    &call.host,
                                    &config,
                                    &input.account_id,
                                    if call.request.path == "visual-evidence" {
                                        engine::ManualCase::Visual
                                    } else {
                                        engine::ManualCase::Logic
                                    },
                                )
                                .await?
                            } else if call.request.path == "evidence" {
                                engine::evidence(&call.host, &config, &input.account_id).await?
                            } else {
                                engine::tick(
                                    &call.host,
                                    &config,
                                    Some(&input.account_id),
                                    probe_timeout(call.context.timeout_ms)?,
                                )
                                .await?
                            }
                        }
                        _ => return Err(host::fault("unknown_route")),
                    };
                    Ok(TypedReply::new(ManagementResponse {
                        status: 200,
                        headers: vec![],
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
                        parameters: vec![CommandParameter {
                            name: "account_id".into(),
                            description: "只探测这个已纳管且到期的账号；省略时自动选择".into(),
                            value_type: CommandParameterType::String,
                            required: false,
                            sensitive: false,
                            default: None,
                        }],
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
                    let account = match call.request.arguments.get("account_id") {
                        Some(CommandValue::String(id)) => Some(id.as_str()),
                        None => None,
                        _ => return Err(host::fault("invalid_account_id")),
                    };
                    if call.request.arguments.len() > usize::from(account.is_some())
                        || (call.request.name == "status" && account.is_some())
                    {
                        return Err(host::fault("unexpected_arguments"));
                    }
                    let value = match call.request.name.as_str() {
                        "tick" => {
                            engine::tick(
                                &call.host,
                                &config,
                                account,
                                probe_timeout(call.context.timeout_ms)?,
                            )
                            .await?
                        }
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

fn probe_timeout(parent_ms: u64) -> Result<Duration, gateway_plugin_sdk::PluginFault> {
    let ms = parent_ms.saturating_sub(5000).min(110000);
    if ms < 1000 {
        return Err(host::fault("insufficient_probe_deadline"));
    }
    Ok(Duration::from_millis(ms))
}
