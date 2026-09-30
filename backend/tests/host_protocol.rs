//! 真实插件子进程与 SDK 二进制帧联调；所有宿主数据和模型响应均在内存模拟。

use std::{
    collections::{BTreeMap, BTreeSet},
    process::Stdio,
    time::Duration,
};

use codex_quality_guard::{
    Config, PLUGIN_ID, manifest,
    state::{Phase, Record, Verdict},
};
use gateway_plugin_sdk::{
    CallContext, ErrorCode, Frame, Handshake, Message, PROTOCOL_VERSION, PluginFault, Stage,
    call::{
        host::{ModelEventBatch, StateRecord},
        model::{CanonicalEvent, ExecutionEvent, FinishReason},
    },
    client::{read_frame, write_frame},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const ACCOUNT: &str = "acct_probe_1";

#[derive(Default)]
struct FakeStore {
    state: BTreeMap<String, StateRecord>,
    groups: BTreeMap<String, BTreeSet<String>>,
    calls: Vec<(String, Value)>,
    model_accounts: Vec<String>,
    reject_account_writes: bool,
    bypass_probe_key_scope: bool,
    fail_membership_change: bool,
    stale_membership_readback: bool,
    take_over_during_model: bool,
    probe_budget_too_wide: bool,
    extra_account: bool,
    valid_model_output: bool,
    http_body: Option<Vec<u8>>,
    deny_budget: bool,
    fail_membership_read: bool,
}

impl FakeStore {
    fn callback(
        &mut self,
        method: &str,
        params: Value,
        payload: &[u8],
    ) -> Result<(Value, Vec<u8>), PluginFault> {
        let data: Value = if payload.is_empty() {
            params.clone()
        } else {
            serde_json::from_slice(payload).unwrap()
        };
        self.calls.push((method.to_owned(), data.clone()));
        let response = match method {
            "host.state.get" => {
                assert_eq!(params["namespace"], "quality");
                return Ok((
                    json!({"record": self.state.get(params["key"].as_str().unwrap())}),
                    vec![],
                ));
            }
            "host.state.put" => {
                assert_eq!(params["namespace"], "quality");
                let key = params["key"].as_str().unwrap().to_owned();
                let existing = self.state.get(&key).map(|record| record.version);
                if existing != params["expected_version"].as_u64()
                    || (self.reject_account_writes && key.starts_with("account."))
                {
                    return Err(PluginFault::new(
                        ErrorCode::Conflict,
                        "simulated CAS conflict",
                    ));
                }
                let version = existing.unwrap_or(0) + 1;
                self.state.insert(
                    key,
                    StateRecord {
                        value: params["value"].clone(),
                        version,
                        schema_version: 1,
                    },
                );
                return Ok((json!({"version": version}), vec![]));
            }
            "host.state.delete" => {
                assert_eq!(params["namespace"], "quality");
                let key = params["key"].as_str().unwrap();
                if let Some(record) = self.state.get(key)
                    && Some(record.version) != params["expected_version"].as_u64()
                {
                    return Err(PluginFault::new(
                        ErrorCode::Conflict,
                        "simulated delete CAS conflict",
                    ));
                }
                return Ok((json!({"deleted": self.state.remove(key).is_some()}), vec![]));
            }
            "host.groups.ensure" => {
                let resource = data["resource_key"].as_str().unwrap();
                self.groups.entry(resource.to_owned()).or_default();
                json!({"id": format!("grp_{resource}"), "name": data["name"], "enabled": true})
            }
            "host.keys.ensure" => {
                let resource = data["resource_key"].as_str().unwrap();
                let (id, group) = match resource {
                    "probe-key" => ("key_probe", "probe"),
                    "business-key" => ("key_business", "healthy"),
                    _ => panic!("unexpected key resource"),
                };
                assert_eq!(data["group_resource_keys"], json!([group]));
                json!({"id": id, "name": data["name"], "enabled": true})
            }
            "host.groups.change_members" => {
                if self.fail_membership_change {
                    return Err(PluginFault::new(
                        ErrorCode::Fault,
                        "simulated membership failure",
                    ));
                }
                let resource = data["resource_key"].as_str().unwrap();
                let members = self
                    .groups
                    .get_mut(resource)
                    .expect("group must be ensured before mutation");
                let previous = members.clone();
                let mut added = 0_u64;
                let mut removed = 0_u64;
                for value in data["add"].as_array().unwrap() {
                    added += u64::from(members.insert(value.as_str().unwrap().to_owned()));
                }
                for value in data["remove"].as_array().unwrap() {
                    removed += u64::from(members.remove(value.as_str().unwrap()));
                }
                if self.stale_membership_readback {
                    *members = previous;
                }
                json!({"added": added, "removed": removed})
            }
            "host.http.dispatch" => {
                assert_eq!(params["method"], "GET");
                let page = match params["uri"].as_str().unwrap() {
                    "/api/admin/accounts?page=1&pageSize=100" => 1,
                    "/api/admin/accounts?page=2&pageSize=100" if self.extra_account => 2,
                    other => panic!("unexpected URI: {other}"),
                };
                assert!(params["headers"].as_array().unwrap().is_empty());
                let ids = if page == 1 {
                    vec![ACCOUNT]
                } else {
                    vec!["acct_probe_2"]
                };
                let items: Vec<_> = ids
                    .into_iter()
                    .map(|id| {
                        let groups: Vec<_> = self
                            .groups
                            .iter()
                            .filter(|(_, members)| members.contains(id))
                            .map(|(key, _)| json!({"id":format!("grp_{key}")}))
                            .collect();
                        json!({"id":id,"groups":groups})
                    })
                    .collect();
                self.http_body = Some(
                    serde_json::to_vec(
                        &json!({"code":200,"data":{"items":items,"page":{"page":page,"totalPages":if self.extra_account {2} else {1}}}}),
                    )
                    .unwrap(),
                );
                return Ok((
                    json!({"status":if self.fail_membership_read {503} else {200},"version":"HTTP/1.1","headers":[],"body":{"kind":"handle","handle":"accounts-body"},"response":null,"session":false}),
                    vec![],
                ));
            }
            "host.http.body_read" => {
                let bytes = self.http_body.take();
                return Ok((
                    json!({"eof":bytes.is_none(),"trailers":null}),
                    bytes.unwrap_or_default(),
                ));
            }
            "host.http.body_close" => {
                self.http_body = None;
                return Ok((json!({}), vec![]));
            }
            "host.data.accounts.list" => {
                let mut ids = vec![ACCOUNT];
                if self.extra_account {
                    ids.push("acct_probe_2");
                }
                let accounts: Vec<_> = ids.into_iter().map(|id| {
                    // 重现 3.18 的空分组缺陷，真实成员只能从公开账号列表取得。
                    json!({"account_id": id, "name": id, "email": null, "provider_id": "openai", "group_ids": [], "enabled": true, "updated_at_ms": 0})
                }).collect();
                json!({"schema_version": 1, "accounts": accounts, "next_cursor": null})
            }
            "host.data.keys.get" => {
                let group = match data["client_key_id"].as_str().unwrap() {
                    "key_probe" => "grp_probe",
                    "key_business" => "grp_healthy",
                    _ => panic!("unexpected Key ID"),
                };
                let groups = if self.bypass_probe_key_scope && data["client_key_id"] == "key_probe"
                {
                    vec![group, "grp_unmanaged"]
                } else {
                    vec![group]
                };
                json!({"schema_version": 1, "client_key_id": data["client_key_id"], "enabled": true, "group_ids": groups})
            }
            "host.keys.get_budget" => {
                if self.deny_budget {
                    return Err(PluginFault::new(ErrorCode::Rejected, "budget unavailable"));
                }
                let daily = if self.probe_budget_too_wide {
                    "10"
                } else {
                    "5"
                };
                json!({"client_key_id": data["client_key_id"], "daily_limit_usd": daily, "weekly_limit_usd": "25", "daily_used_usd": "0", "weekly_used_usd": "0", "daily_resets_at_ms": null, "weekly_resets_at_ms": null})
            }
            "host.model.execute" => {
                self.model_accounts
                    .push(params["account_id"].as_str().unwrap().to_owned());
                // 响应有终态但内容不属于题库；只验证请求归属和未知样本处理。
                assert_eq!(params["client_key_id"], "key_probe");
                assert!(
                    [ACCOUNT, "acct_probe_2"].contains(&params["account_id"].as_str().unwrap())
                );
                assert_eq!(params["provider"], "openai");
                assert_eq!(params["model"], "gpt-6-astra");
                assert!(params["previous_response_id"].is_null());
                assert_eq!(data["input"].as_array().unwrap().len(), 1);
                assert_eq!(data["model"], "gpt-6-astra");
                if self.take_over_during_model {
                    let key = format!("account.{:x}", Sha256::digest(ACCOUNT.as_bytes()));
                    let record = self
                        .state
                        .get_mut(&key)
                        .expect("model call requires a claimed lease");
                    record.version += 1;
                    record.value["quality"]["lease_id"] = json!("replacement-worker");
                    record.value["takeover_marker"] = json!("must-survive-late-response");
                }
                let events = vec![
                    ExecutionEvent::canonical(CanonicalEvent::Started {
                        id: "resp_mock".into(),
                        model: Some("gpt-6-astra".into()),
                    }),
                    ExecutionEvent::canonical(CanonicalEvent::TextDelta {
                        index: 0,
                        text: if self.valid_model_output {
                            format!(
                                "完整回答：\n```\n{}\n```",
                                (1..=300)
                                    .map(|n| n.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        } else {
                            "unrecognized-probe-output".into()
                        },
                    }),
                    ExecutionEvent::canonical(CanonicalEvent::Completed {
                        id: "resp_mock".into(),
                        model: Some("gpt-6-astra".into()),
                        reason: FinishReason::Stop,
                    }),
                ];
                return Ok((
                    json!({"request_id": "req_mock", "events": events.len()}),
                    ModelEventBatch { events }.encode().unwrap(),
                ));
            }
            "host.log" => return Ok((json!({}), vec![])),
            _ => panic!("unexpected host callback: {method}"),
        };
        Ok((json!({}), serde_json::to_vec(&response).unwrap()))
    }

    fn seed_record(&mut self, record: &Record) {
        let key = format!("account.{:x}", Sha256::digest(ACCOUNT.as_bytes()));
        let version = self.state.get(&key).map_or(1, |old| old.version + 1);
        self.state.insert(
            key,
            StateRecord {
                value: json!({"quality": record, "last_sample": null}),
                version,
                schema_version: 1,
            },
        );
    }

    fn count(&self, method: &str) -> usize {
        self.calls.iter().filter(|(name, _)| name == method).count()
    }
}

struct Peer {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    next_id: u64,
}

impl Peer {
    async fn start(config: &Config) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_codex-quality-guard"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let manifest = manifest().unwrap();
        write_frame(
            &mut input,
            &Frame::control(Message::Hello {
                handshake: Handshake {
                    protocol_version: PROTOCOL_VERSION,
                    artifact_sha256: "a".repeat(64),
                    plugin_id: PLUGIN_ID.into(),
                    instance_id: "quality-instance".into(),
                    generation: 1,
                    incarnation: "test-incarnation".into(),
                    configuration: serde_json::to_value(config).unwrap(),
                    contributes: manifest.contributes,
                },
            }),
        )
        .await
        .unwrap();
        let mut peer = Self {
            child,
            input,
            output,
            next_id: 1,
        };
        assert!(matches!(
            peer.receive().await.message,
            Message::Ready {
                protocol_version: PROTOCOL_VERSION,
                ..
            }
        ));
        peer
    }

    async fn receive(&mut self) -> Frame {
        tokio::time::timeout(Duration::from_secs(5), read_frame(&mut self.output))
            .await
            .expect("plugin response timed out")
            .expect("invalid plugin frame")
    }

    async fn invoke(
        &mut self,
        store: &mut FakeStore,
        method: &str,
        stage: Stage,
        params: Value,
        payload: Vec<u8>,
    ) -> Result<Frame, PluginFault> {
        let id = self.next_id;
        self.next_id += 2;
        write_frame(
            &mut self.input,
            &Frame {
                message: Message::Call {
                    id,
                    method: method.into(),
                    params,
                    context: CallContext {
                        call_id: id,
                        instance_id: "quality-instance".into(),
                        generation: 1,
                        incarnation: "test-incarnation".into(),
                        stage,
                        timeout_ms: 120000,
                        resource_stream: false,
                        resource_scope_id: format!("scope-{id}"),
                        request_id: Some(format!("parent-{id}")),
                        attempt_id: None,
                        account_id: None,
                        credential_revision: None,
                    },
                },
                payload,
            },
        )
        .await
        .unwrap();
        loop {
            let frame = self.receive().await;
            match frame.message {
                Message::Callback {
                    id: callback_id,
                    parent_id,
                    method,
                    params,
                } => {
                    assert_eq!(parent_id, id);
                    let result = store.callback(&method, params, &frame.payload);
                    let reply = match result {
                        Ok((result, payload)) => Frame {
                            message: Message::Result {
                                id: callback_id,
                                result,
                            },
                            payload,
                        },
                        Err(error) => Frame::control(Message::Error {
                            id: callback_id,
                            error,
                        }),
                    };
                    write_frame(&mut self.input, &reply).await.unwrap();
                }
                Message::Result { id: result_id, .. } => {
                    assert_eq!(result_id, id);
                    return Ok(frame);
                }
                Message::Error {
                    id: result_id,
                    error,
                } => {
                    assert_eq!(result_id, id);
                    return Err(error);
                }
                _ => panic!("unexpected plugin message"),
            }
        }
    }

    async fn reconcile(&mut self, store: &mut FakeStore) {
        self.invoke(
            store,
            "plugin.reconcile",
            Stage::Maintenance,
            json!({}),
            vec![],
        )
        .await
        .unwrap();
    }

    async fn command(&mut self, store: &mut FakeStore, name: &str) -> Result<Value, PluginFault> {
        let frame = self
            .invoke(
                store,
                "command_line.execute",
                Stage::CommandLine,
                json!({}),
                serde_json::to_vec(&json!({"name": name, "arguments": {}})).unwrap(),
            )
            .await?;
        let command: Value = serde_json::from_slice(&frame.payload).unwrap();
        assert_eq!(command["exit_code"], 0, "{}", command["stderr"]);
        Ok(serde_json::from_str(command["stdout"].as_str().unwrap()).unwrap())
    }

    async fn shutdown(mut self) {
        write_frame(&mut self.input, &Frame::control(Message::Shutdown))
            .await
            .unwrap();
        let status = tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(status.success());
    }
}

fn config() -> Config {
    Config {
        enabled: true,
        account_ids: vec![ACCOUNT.into()],
        max_quarantined_percent: 100,
        ..Config::default()
    }
}

#[tokio::test]
async fn management_registers_relative_status_route_and_serves_it() {
    let mut peer = Peer::start(&Config::default()).await;
    let mut store = FakeStore::default();
    let registration = peer
        .invoke(
            &mut store,
            "management.register",
            Stage::Registration,
            json!({}),
            vec![],
        )
        .await
        .unwrap();
    let registration: Value = serde_json::from_slice(&registration.payload).unwrap();
    assert_eq!(registration["pages"][0]["entry"], "web/index.html");
    assert_eq!(
        registration["resources"],
        json!([{"path":"web/index.html","public":false}])
    );
    assert!(
        codex_quality_guard::manifest()
            .unwrap()
            .resources
            .contains_key("web/index.html")
    );
    // 宿主要求相对路径；首斜杠会在安装时被拒绝。
    assert_eq!(
        registration["routes"],
        json!([{"method": "GET", "path": "status", "request_content_types": [],
            "response_content_types": ["application/json"]}, {"method":"POST", "path":"evidence", "request_content_types":["application/json"], "response_content_types":["application/json"]}, {"method":"POST", "path":"probe", "request_content_types":["application/json"], "response_content_types":["application/json"]}])
    );
    assert!(
        store.calls.is_empty(),
        "registration must not call the host"
    );
    let response = peer
        .invoke(
            &mut store,
            "management.handle",
            Stage::Management,
            json!({"method": "GET", "path": "status", "query": "", "content_type": null}),
            vec![],
        )
        .await
        .unwrap();
    match response.message {
        Message::Result { result, .. } => {
            assert_eq!(
                result,
                json!({"status": 200, "content_type": "application/json", "headers": []})
            );
        }
        _ => panic!("expected management response"),
    }
    assert!(
        serde_json::from_slice::<Value>(&response.payload)
            .unwrap()
            .is_object()
    );
    assert_eq!(store.count("host.model.execute"), 0);
    assert_eq!(store.count("host.groups.change_members"), 0);
    peer.shutdown().await;
}

#[tokio::test]
async fn disabled_status_round_trips_without_model_or_group_writes() {
    let mut peer = Peer::start(&Config::default()).await;
    let mut store = FakeStore::default();
    assert!(
        peer.command(&mut store, "status")
            .await
            .unwrap()
            .is_object()
    );
    assert_eq!(store.count("host.model.execute"), 0);
    assert_eq!(store.count("host.groups.change_members"), 0);
    peer.shutdown().await;
}

#[tokio::test]
async fn budget_failure_stops_probe() {
    let mut peer = Peer::start(&config()).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    let status = peer.command(&mut store, "status").await.unwrap();
    assert_eq!(status["probe_budget_ok"], true);

    store.deny_budget = true;
    let status = peer.command(&mut store, "status").await.unwrap();
    assert_eq!(status["probe_budget_ok"], false);
    let error = peer.command(&mut store, "tick").await.unwrap_err();
    assert_eq!(error.code, ErrorCode::Rejected);
    assert_eq!(store.count("host.model.execute"), 0);
    peer.shutdown().await;
}

#[tokio::test]
async fn tick_locks_account_and_persists_unknown_evidence_across_restart() {
    let config = config();
    let mut peer = Peer::start(&config).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    let group_writes = store.count("host.groups.change_members");
    let sample = peer.command(&mut store, "tick").await.unwrap();
    assert_eq!(store.count("host.model.execute"), 1);
    assert_eq!(
        store.count("host.groups.change_members"),
        group_writes,
        "CLI must leave reconciliation to maintenance"
    );
    let key = format!("account.{:x}", Sha256::digest(ACCOUNT.as_bytes()));
    let persisted = store
        .state
        .get(&key)
        .expect("probe evidence must persist")
        .value
        .clone();
    assert_eq!(persisted["quality"]["sample_counter"], 0);
    assert_eq!(sample["status"], "challenge_recorded");
    assert_eq!(
        persisted["batch"]["attempts"][0]["output"],
        "unrecognized-probe-output"
    );
    assert!(persisted["batch"]["score"].is_null());
    assert!(persisted.get("last_sample").is_none());
    assert!(sample["sample"].is_null());
    assert_eq!(persisted["history"], json!([]));
    let status = peer.command(&mut store, "status").await.unwrap();
    assert_eq!(status["accounts"][0]["last_sample"], sample["sample"]);
    assert!(
        !store.groups["healthy"].contains(ACCOUNT),
        "unknown sample cannot admit traffic"
    );
    peer.shutdown().await;

    let mut restarted = Peer::start(&config).await;
    assert!(
        restarted
            .command(&mut store, "status")
            .await
            .unwrap()
            .is_object()
    );
    assert_eq!(store.state[&key].value, persisted);
    restarted.shutdown().await;
}

#[tokio::test]
async fn conflicting_probe_lease_cannot_issue_a_model_call() {
    let mut peer = Peer::start(&config()).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    store.reject_account_writes = true;
    let _ = peer.command(&mut store, "tick").await;
    assert_eq!(store.count("host.model.execute"), 0);
    peer.shutdown().await;
}

#[tokio::test]
async fn late_model_result_cannot_overwrite_a_replacement_worker_record() {
    let mut peer = Peer::start(&config()).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    let group_writes = store.count("host.groups.change_members");
    store.take_over_during_model = true;
    assert!(peer.command(&mut store, "tick").await.is_err());
    assert_eq!(store.count("host.model.execute"), 1);
    assert_eq!(store.count("host.groups.change_members"), group_writes);
    let key = format!("account.{:x}", Sha256::digest(ACCOUNT.as_bytes()));
    let record = &store.state[&key];
    assert_eq!(
        record.value["takeover_marker"],
        "must-survive-late-response"
    );
    assert_eq!(record.value["quality"]["lease_id"], "replacement-worker");
    assert_eq!(record.value["quality"]["sample_counter"], 0);
    assert_eq!(record.value["history"], json!([]));
    peer.shutdown().await;
}

#[tokio::test]
async fn exhausted_daily_attempt_budget_releases_lease_without_model_or_group_write() {
    let config = config();
    let mut peer = Peer::start(&config).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    let group_writes = store.count("host.groups.change_members");
    let day = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86400;
    store.state.insert("budget".into(), StateRecord {
        value: json!({"day": day, "attempts": config.max_daily_attempts, "reserved_output_tokens": 0}),
        version: 1, schema_version: 1,
    });
    let result = peer.command(&mut store, "tick").await.unwrap();
    assert_eq!(result["status"], "daily_budget_exhausted");
    assert_eq!(store.count("host.model.execute"), 0);
    assert_eq!(store.count("host.groups.change_members"), group_writes);
    let key = format!("account.{:x}", Sha256::digest(ACCOUNT.as_bytes()));
    assert_eq!(store.state[&key].value["quality"]["lease_id"], "");
    assert_eq!(store.state[&key].value["quality"]["lease_until_ms"], 0);
    peer.shutdown().await;
}

#[tokio::test]
async fn probe_key_budget_wider_than_configuration_stops_tick() {
    let mut peer = Peer::start(&config()).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    let group_writes = store.count("host.groups.change_members");
    store.probe_budget_too_wide = true;
    assert!(peer.command(&mut store, "tick").await.is_err());
    assert_eq!(store.count("host.model.execute"), 0);
    assert_eq!(store.count("host.groups.change_members"), group_writes);
    peer.shutdown().await;
}

#[tokio::test]
async fn maintenance_removes_state_for_accounts_removed_from_configuration() {
    let mut config = config();
    let mut peer = Peer::start(&config).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    store.seed_record(&Record::new(config.tag(), 0));
    let key = format!("account.{:x}", Sha256::digest(ACCOUNT.as_bytes()));
    assert!(store.state.contains_key(&key));
    peer.shutdown().await;

    config.account_ids = vec!["acct_probe_2".into()];
    store.extra_account = true;
    let mut replacement = Peer::start(&config).await;
    replacement.reconcile(&mut store).await;
    assert!(!store.state.contains_key(&key));
    assert_eq!(
        store.state["managed-index"].value["account_ids"],
        json!(["acct_probe_2"])
    );
    assert!(!store.groups["probe"].contains(ACCOUNT));
    assert!(store.groups["probe"].contains("acct_probe_2"));
    assert_eq!(store.count("host.model.execute"), 0);
    replacement.shutdown().await;
}

#[tokio::test]
async fn probe_key_scope_bypass_stops_tick_without_group_writes() {
    let mut peer = Peer::start(&config()).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    let group_writes = store.count("host.groups.change_members");
    store.bypass_probe_key_scope = true;
    assert!(peer.command(&mut store, "tick").await.is_err());
    assert_eq!(store.count("host.model.execute"), 0);
    assert_eq!(store.count("host.groups.change_members"), group_writes);
    peer.shutdown().await;
}

#[tokio::test]
async fn failed_membership_change_is_reported_without_probe_execution() {
    let mut peer = Peer::start(&config()).await;
    let mut store = FakeStore {
        fail_membership_change: true,
        ..FakeStore::default()
    };
    assert!(
        peer.invoke(
            &mut store,
            "plugin.reconcile",
            Stage::Maintenance,
            json!({}),
            vec![]
        )
        .await
        .is_err()
    );
    assert_eq!(store.state["maintenance"].value["ok"], false);
    assert_eq!(store.count("host.model.execute"), 0);
    peer.shutdown().await;
}

#[tokio::test]
async fn stale_membership_readback_does_not_claim_successful_isolation() {
    let mut peer = Peer::start(&config()).await;
    let mut store = FakeStore {
        stale_membership_readback: true,
        ..FakeStore::default()
    };
    peer.reconcile(&mut store).await;
    assert_eq!(store.state["maintenance"].value["ok"], false);
    assert_eq!(
        store.state["maintenance"].value["runtime_isolation_verified"],
        false
    );
    assert_eq!(store.count("host.model.execute"), 0);
    peer.shutdown().await;
}

#[tokio::test]
async fn reconciliation_removes_cooling_accounts_and_restores_only_recovered_accounts() {
    let config = config();
    let mut peer = Peer::start(&config).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    let mut record = Record::new(config.tag(), 0);
    record.observe(Verdict::Healthy, "gpt-6-astra", 0, &config.policy);
    store.seed_record(&record);
    peer.reconcile(&mut store).await;
    assert!(store.groups["healthy"].contains(ACCOUNT));

    for _ in 0..config.policy.anomaly_rounds {
        let due = record.next_probe_at_ms;
        record.observe(Verdict::Anomaly, "gpt-5.6-luna", due, &config.policy);
    }
    assert_eq!(record.phase, Phase::Cooling);
    store.seed_record(&record);
    peer.reconcile(&mut store).await;
    assert!(!store.groups["healthy"].contains(ACCOUNT));
    assert!(
        store.groups["probe"].contains(ACCOUNT),
        "isolation must retain probe access"
    );

    for round in 0..config.policy.recovery_rounds {
        let due = record.next_probe_at_ms;
        record.observe(Verdict::Healthy, "gpt-6-astra", due, &config.policy);
        store.seed_record(&record);
        peer.reconcile(&mut store).await;
        assert_eq!(
            store.groups["healthy"].contains(ACCOUNT),
            round + 1 == config.policy.recovery_rounds
        );
    }
    assert_eq!(
        store.count("host.model.execute"),
        0,
        "maintenance cannot execute models"
    );
    peer.shutdown().await;
}

#[tokio::test]
async fn pool_guard_stops_expansion_without_restoring_existing_isolation() {
    let mut config = config();
    config.account_ids.push("acct_probe_2".into());
    config.max_quarantined_percent = 50;
    let mut peer = Peer::start(&config).await;
    let mut store = FakeStore {
        extra_account: true,
        ..FakeStore::default()
    };
    peer.reconcile(&mut store).await;
    let mut record = Record::new(config.tag(), 0);
    record.observe(Verdict::Healthy, "gpt-6-astra", 0, &config.policy);
    store.seed_record(&record);
    let first_key = format!("account.{:x}", Sha256::digest(ACCOUNT.as_bytes()));
    let second_key = format!("account.{:x}", Sha256::digest(b"acct_probe_2"));
    store
        .state
        .insert(second_key.clone(), store.state[&first_key].clone());
    peer.reconcile(&mut store).await;
    assert_eq!(store.groups["healthy"].len(), 2);
    for _ in 0..2 {
        let due = record.next_probe_at_ms;
        record.observe(Verdict::Anomaly, "gpt-5.6-luna", due, &config.policy);
    }
    store.seed_record(&record);
    // 预算漂移只阻止付费探针，不阻断已有冷却结论的移组。
    store.probe_budget_too_wide = true;
    peer.reconcile(&mut store).await;
    assert!(!store.groups["healthy"].contains(ACCOUNT));
    assert_eq!(store.state["maintenance"].value["pool_guard"], false);
    store
        .state
        .insert(second_key, store.state[&first_key].clone());
    peer.reconcile(&mut store).await;
    assert_eq!(store.state["maintenance"].value["pool_guard"], true);
    assert_eq!(store.state["maintenance"].value["ok"], false);
    assert!(!store.groups["healthy"].contains(ACCOUNT));
    assert!(store.groups["healthy"].contains("acct_probe_2"));
    peer.shutdown().await;
}

async fn probe_account(
    peer: &mut Peer,
    store: &mut FakeStore,
    id: &str,
) -> Result<Value, PluginFault> {
    let response = peer
        .invoke(
            store,
            "management.handle",
            Stage::Management,
            json!({"method":"POST","path":"probe","query":"","content_type":"application/json"}),
            serde_json::to_vec(&json!({"account_id":id})).unwrap(),
        )
        .await?;
    Ok(serde_json::from_slice(&response.payload).unwrap())
}

#[tokio::test]
async fn explicit_accounts_are_isolated_and_do_not_bypass_due_time() {
    let mut c = config();
    c.account_ids.push("acct_probe_2".into());
    let mut peer = Peer::start(&c).await;
    let mut store = FakeStore {
        extra_account: true,
        ..FakeStore::default()
    };
    peer.reconcile(&mut store).await;
    assert_eq!(store.state["maintenance"].value["ok"], true);
    // 基础事实故意返回空组；两次请求仍须指定不同账号，并各自持久化证据。
    let first = probe_account(&mut peer, &mut store, "acct_probe_2")
        .await
        .unwrap();
    assert_eq!(first["account_id"], "acct_probe_2");
    let response = peer.invoke(&mut store, "command_line.execute", Stage::CommandLine, json!({}),
        serde_json::to_vec(&json!({"name":"tick","arguments":{"account_id":{"type":"string","value":ACCOUNT}}})).unwrap()).await.unwrap();
    let command: Value = serde_json::from_slice(&response.payload).unwrap();
    let second: Value = serde_json::from_str(command["stdout"].as_str().unwrap()).unwrap();
    assert_eq!(second["account_id"], ACCOUNT);
    assert_eq!(store.count("host.model.execute"), 2);
    assert_eq!(store.model_accounts, vec!["acct_probe_2", ACCOUNT]);
    // An explicit account cannot bypass its active lease.
    let leased_key = format!("account.{:x}", Sha256::digest(ACCOUNT.as_bytes()));
    store.state.get_mut(&leased_key).unwrap().value["quality"]["lease_until_ms"] = json!(i64::MAX);
    assert_eq!(
        probe_account(&mut peer, &mut store, ACCOUNT).await.unwrap()["status"],
        "no_due_account"
    );
    assert!(
        probe_account(&mut peer, &mut store, "acct_unmanaged")
            .await
            .is_err()
    );
    assert_eq!(store.count("host.model.execute"), 2);
    for id in [ACCOUNT, "acct_probe_2"] {
        let key = format!("account.{:x}", Sha256::digest(id.as_bytes()));
        assert_eq!(
            store.state[&key].value["batch"]["attempts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.state[&key].value["quality"]["lease_id"], "");
    }
    peer.shutdown().await;
}

#[tokio::test]
async fn automatic_probes_rotate_accounts_and_obey_global_budget() {
    let mut c = config();
    c.auto_probe = true;
    c.max_daily_attempts = 4;
    c.account_ids.push("acct_probe_2".into());
    let mut peer = Peer::start(&c).await;
    let mut store = FakeStore {
        extra_account: true,
        valid_model_output: true,
        ..FakeStore::default()
    };
    for _ in 0..4 {
        peer.reconcile(&mut store).await;
    }
    assert_eq!(
        store.model_accounts,
        [ACCOUNT, ACCOUNT, ACCOUNT, "acct_probe_2"]
    );
    assert_eq!(store.state["budget"].value["attempts"], 4);
    for (id, count) in [(ACCOUNT, 3), ("acct_probe_2", 1)] {
        let key = format!("account.{:x}", Sha256::digest(id.as_bytes()));
        assert_eq!(
            store.state[&key].value["batch"]["attempts"]
                .as_array()
                .unwrap()
                .len(),
            count
        );
    }
    peer.reconcile(&mut store).await;
    assert_eq!(store.count("host.model.execute"), 4);
    peer.shutdown().await;
}

#[tokio::test]
async fn missing_membership_does_not_execute_or_change_groups() {
    let mut peer = Peer::start(&config()).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    let writes = store.count("host.groups.change_members");
    store.fail_membership_read = true;
    assert!(peer.command(&mut store, "tick").await.is_err());
    assert_eq!(store.count("host.model.execute"), 0);
    assert_eq!(store.count("host.groups.change_members"), writes);
    peer.shutdown().await;
}

#[tokio::test]
async fn three_complete_answers_resume_and_score_once_with_raw_evidence() {
    let mut c = config();
    c.max_daily_attempts = 1;
    let mut peer = Peer::start(&c).await;
    let mut store = FakeStore {
        valid_model_output: true,
        ..FakeStore::default()
    };
    peer.reconcile(&mut store).await;
    let first = probe_account(&mut peer, &mut store, ACCOUNT).await.unwrap();
    assert_eq!(first["status"], "challenge_recorded");
    assert_eq!(first["batch"]["attempts"][0]["number_count"], 300);
    assert!(first["batch"]["score"].is_null());
    assert!(first["quality"]["last_verdict"].is_null());
    assert_eq!(
        probe_account(&mut peer, &mut store, ACCOUNT).await.unwrap()["status"],
        "daily_budget_exhausted"
    );
    peer.shutdown().await;
    // Budget changes do not erase answers; process restart can continue the same round.
    c.max_daily_attempts = 3;
    let mut peer = Peer::start(&c).await;
    let second = probe_account(&mut peer, &mut store, ACCOUNT).await.unwrap();
    assert_eq!(second["status"], "challenge_recorded");
    assert_eq!(second["batch"]["attempts"].as_array().unwrap().len(), 2);
    assert!(second["batch"]["score"].is_null());
    let third = probe_account(&mut peer, &mut store, ACCOUNT).await.unwrap();
    assert_eq!(third["status"], "batch_completed");
    assert_eq!(third["batch"]["score"]["sample_count"], 3);
    assert_eq!(
        third["batch"]["score"]["candidates"]
            .as_array()
            .unwrap()
            .len(),
        16
    );
    assert_eq!(third["quality"]["sample_counter"], 1);
    let attempts = third["batch"]["attempts"].as_array().unwrap();
    let lengths: BTreeSet<_> = attempts
        .iter()
        .map(|a| a["expected_count"].as_u64().unwrap())
        .collect();
    assert_eq!(lengths.len(), 3);
    assert_eq!(attempts[0], first["batch"]["attempts"][0]);
    assert!(
        attempts
            .iter()
            .all(|a| a["output"].as_str().unwrap().starts_with("完整回答："))
    );
    let inputs: Vec<_> = attempts
        .iter()
        .map(|a| {
            (
                a["output"].as_str().unwrap(),
                a["expected_count"].as_u64().unwrap() as usize,
            )
        })
        .collect();
    let expected = codex_quality_guard::scorer::score_batch(&inputs, &c.model).unwrap();
    assert_eq!(
        third["batch"]["score"]["predicted_model"],
        expected.predicted_model
    );
    for (actual, expected) in third["batch"]["score"]["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expected.candidates)
    {
        assert_eq!(actual["model"], expected.model);
        assert!((actual["probability"].as_f64().unwrap() - expected.probability).abs() < 1e-12);
    }
    assert_eq!(store.state["budget"].value["attempts"], 3);
    assert_eq!(store.model_accounts, [ACCOUNT; 3]);
    let status = peer.command(&mut store, "status").await.unwrap();
    assert_eq!(
        status["accounts"][0]["history"].as_array().unwrap().len(),
        1
    );
    assert!(
        status["accounts"][0]["batch"]["attempts"][0]
            .get("output")
            .is_none()
    );
    assert_eq!(status["accounts"][0]["batch"]["score"]["sample_count"], 3);
    peer.shutdown().await;
}

#[tokio::test]
async fn six_invalid_answers_finish_unknown_without_fingerprint_or_admission() {
    let mut peer = Peer::start(&config()).await;
    let mut store = FakeStore::default();
    peer.reconcile(&mut store).await;
    for attempt in 1..=6 {
        let r = probe_account(&mut peer, &mut store, ACCOUNT).await.unwrap();
        assert_eq!(r["batch"]["attempts"].as_array().unwrap().len(), attempt);
        assert!(r["batch"]["score"].is_null());
        assert_eq!(
            r["status"],
            if attempt == 6 {
                "batch_completed"
            } else {
                "challenge_recorded"
            }
        );
        if attempt == 6 {
            assert_eq!(r["batch"]["verdict"], "unknown");
            assert_eq!(r["batch"]["error"], "insufficient_valid_answers");
            assert_eq!(r["quality"]["phase"], "pending");
        }
    }
    assert_eq!(
        probe_account(&mut peer, &mut store, ACCOUNT).await.unwrap()["status"],
        "no_due_account"
    );
    assert_eq!(store.count("host.model.execute"), 6);
    peer.shutdown().await;
}
