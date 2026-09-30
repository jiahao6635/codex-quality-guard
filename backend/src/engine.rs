use crate::{
    Config,
    config::PROVIDER,
    host::{self, fault},
    scorer::{self, Score},
    state::{Phase, Record, Verdict},
};
use gateway_plugin_sdk::{
    PluginFault,
    call::{
        data::{AccountFacts, ClientKeyFactsQuery},
        host::{ModelEventBatch, ModelExecuteRequest, ModelExecuteResult, ModelOperation},
        model::{CanonicalEvent, ContentKind, FinishReason, WirePayload},
        resources::{GroupEnsureRequest, GroupMembersChange, KeyEnsureRequest},
    },
    client::HostClient,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
struct Resources {
    probe_group_id: String,
    healthy_group_id: String,
    probe_key_id: String,
    business_key_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Evidence {
    at_ms: i64,
    challenge_id: String,
    request_id: Option<String>,
    verdict: Verdict,
    score: Option<Score>,
    error: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct AccountState {
    quality: Record,
    #[serde(default)]
    history: Vec<Evidence>,
}
#[derive(Default, Serialize, Deserialize)]
struct Budget {
    day: i64,
    attempts: u32,
    reserved_output_tokens: u64,
}

async fn load(
    host: &HostClient,
    id: &str,
    c: &Config,
) -> Result<(AccountState, Option<u64>), PluginFault> {
    let stored = host::get::<AccountState>(host, &host::account_key(id)).await?;
    let version = stored.as_ref().map(|s| s.1);
    let mut value = stored.map(|s| s.0).unwrap_or(AccountState {
        quality: Record::new(c.tag(), host::now()),
        history: vec![],
    });
    if value.quality.config_tag != c.tag() {
        value.quality = value.quality.reset_for_config(c.tag(), host::now());
    }
    Ok((value, version))
}
async fn resources(host: &HostClient) -> Result<Resources, PluginFault> {
    host::get(host, "resources")
        .await?
        .map(|r| r.0)
        .ok_or_else(|| fault("maintenance_has_not_created_resources"))
}
async fn key_scope(host: &HostClient, key: &str, group: &str) -> Result<(), PluginFault> {
    let facts = host
        .key_facts(ClientKeyFactsQuery {
            client_key_id: key.into(),
        })
        .await?;
    if facts.schema_version != 1 || !facts.enabled || facts.group_ids != [group] {
        return Err(fault("key_disabled_or_group_scope_bypass"));
    }
    Ok(())
}
async fn check_keys(host: &HostClient, r: &Resources, c: &Config) -> Result<(), PluginFault> {
    key_scope(host, &r.probe_key_id, &r.probe_group_id).await?;
    key_scope(host, &r.business_key_id, &r.healthy_group_id).await?;
    for id in &c.business_key_ids {
        key_scope(host, id, &r.healthy_group_id).await?;
    }
    Ok(())
}
async fn check_probe_budget(
    host: &HostClient,
    r: &Resources,
    c: &Config,
) -> Result<(), PluginFault> {
    let budget = host
        .get_key_budget(gateway_plugin_sdk::call::key_budgets::GetKeyBudgetRequest {
            client_key_id: r.probe_key_id.clone(),
        })
        .await?;
    for (actual, configured) in [
        (&budget.daily_limit_usd, &c.probe_daily_usd),
        (&budget.weekly_limit_usd, &c.probe_weekly_usd),
    ] {
        let actual = actual
            .parse::<f64>()
            .map_err(|_| fault("key_budget_invalid"))?;
        let configured = configured
            .parse::<f64>()
            .map_err(|_| fault("configuration_budget_invalid"))?;
        if !actual.is_finite() || actual <= 0.0 || actual > configured {
            return Err(fault("probe_key_budget_exceeds_configuration"));
        }
    }
    Ok(())
}
async fn ensure_resources(host: &HostClient, c: &Config) -> Result<Resources, PluginFault> {
    let mut groups = Vec::new();
    for (key, name) in [
        ("probe", "Quality Guard · 探测组"),
        ("healthy", "Quality Guard · 健康组"),
    ] {
        let group = host
            .ensure_group(GroupEnsureRequest {
                resource_key: key.into(),
                name: name.into(),
                color: "#2563EBFF".into(),
                description: Some("由 Quality Guard 独占管理成员".into()),
            })
            .await?;
        if !group.enabled {
            return Err(fault("managed_group_disabled"));
        }
        groups.push(group.id);
    }
    let mut keys = Vec::new();
    for (key, group, name) in [
        ("probe-key", "probe", "Quality Guard · 探针 Key"),
        ("business-key", "healthy", "Quality Guard · 业务 Key"),
    ] {
        let probe = group == "probe";
        let key = host
            .ensure_key(KeyEnsureRequest {
                resource_key: key.into(),
                name: name.into(),
                group_resource_keys: vec![group.into()],
                max_concurrency: if probe { 1 } else { 0 },
                requests_per_minute: if probe { 2 } else { 0 },
                daily_limit_usd: if probe {
                    c.probe_daily_usd.clone()
                } else {
                    "0".into()
                },
                weekly_limit_usd: if probe {
                    c.probe_weekly_usd.clone()
                } else {
                    "0".into()
                },
            })
            .await?;
        keys.push(key.id);
    }
    let r = Resources {
        probe_group_id: groups[0].clone(),
        healthy_group_id: groups[1].clone(),
        probe_key_id: keys[0].clone(),
        business_key_id: keys[1].clone(),
    };
    let old = host::get::<Resources>(host, "resources").await?;
    host::put(host, "resources", &r, old.map(|o| o.1)).await?;
    Ok(r)
}
fn managed(account: &AccountFacts, c: &Config) -> bool {
    account.enabled
        && account.provider_id == PROVIDER
        && c.account_ids.contains(&account.account_id)
}
async fn change(
    host: &HostClient,
    key: &str,
    add: Vec<String>,
    remove: Vec<String>,
) -> Result<(), PluginFault> {
    // 每次最多 200 个成员；100 纳管上限，小批顺序提交便于宿主补偿。
    for chunk in remove.chunks(100) {
        host.change_group_members(GroupMembersChange {
            resource_key: key.into(),
            add: vec![],
            remove: chunk.to_vec(),
        })
        .await?;
    }
    for chunk in add.chunks(100) {
        host.change_group_members(GroupMembersChange {
            resource_key: key.into(),
            add: chunk.to_vec(),
            remove: vec![],
        })
        .await?;
    }
    Ok(())
}
pub async fn reconcile(host: &HostClient, c: &Config) -> Result<(), PluginFault> {
    let result = reconcile_inner(host, c).await;
    let report = match &result {
        Ok(v) => v.clone(),
        Err(_) => {
            json!({"at_ms":host::now(),"ok":false,"error":"reconciliation_failed_check_permissions_and_key_scopes"})
        }
    };
    let old = host::get::<Value>(host, "maintenance").await?;
    host::put(host, "maintenance", &report, old.map(|v| v.1)).await?;
    result.map(|_| ())
}
async fn reconcile_inner(host: &HostClient, c: &Config) -> Result<Value, PluginFault> {
    let r = ensure_resources(host, c).await?;
    let key_scopes_ok = check_keys(host, &r, c).await.is_ok();
    if !c.enabled {
        return Ok(json!({"at_ms":host::now(),"ok":key_scopes_ok,"enabled":false}));
    }
    prune_removed_accounts(host, c).await?;
    let accounts = host::accounts(host).await?;
    let expected: BTreeSet<String> = accounts
        .iter()
        .filter(|a| managed(a, c))
        .map(|a| a.account_id.clone())
        .collect();
    let mut eligible = BTreeSet::new();
    let mut cold = BTreeSet::new();
    let mut baseline = 0usize;
    for id in &expected {
        let (s, version) = load(host, id, c).await?;
        if version.is_none() {
            host::put(host, &host::account_key(id), &s, None).await?;
        }
        if s.quality.eligible() {
            eligible.insert(id.clone());
        }
        if s.quality.ever_healthy {
            baseline += 1;
            if matches!(s.quality.phase, Phase::Cooling | Phase::Recovering) {
                cold.insert(id.clone());
            }
        }
    }
    let pool_guard =
        baseline > 1 && cold.len() * 100 > baseline * usize::from(c.max_quarantined_percent);
    let current_probe: BTreeSet<String> = accounts
        .iter()
        .filter(|a| a.group_ids.contains(&r.probe_group_id))
        .map(|a| a.account_id.clone())
        .collect();
    let current_healthy: BTreeSet<String> = accounts
        .iter()
        .filter(|a| a.group_ids.contains(&r.healthy_group_id))
        .map(|a| a.account_id.clone())
        .collect();
    change(
        host,
        "probe",
        expected.difference(&current_probe).cloned().collect(),
        current_probe.difference(&expected).cloned().collect(),
    )
    .await?;
    let removals: Vec<String> = current_healthy
        .difference(&eligible)
        .filter(|id| !(pool_guard && cold.contains(*id)))
        .cloned()
        .collect();
    change(host, "healthy", vec![], removals.clone()).await?;
    let mut added = Vec::new();
    for id in eligible
        .difference(&current_healthy)
        .filter(|_| key_scopes_ok)
    {
        let (fresh, _) = load(host, id, c).await?;
        if !fresh.quality.eligible() {
            continue;
        }
        change(host, "healthy", vec![id.clone()], vec![]).await?;
        // 两个宿主操作无法原子提交；读新状态，晚到异常立即补偿移出。
        let (after, _) = load(host, id, c).await?;
        if !after.quality.eligible() {
            change(host, "healthy", vec![], vec![id.clone()]).await?;
        } else {
            added.push(id.clone());
        }
    }
    let readback = host::accounts(host).await?;
    let membership: Vec<String> = readback
        .iter()
        .filter(|a| a.group_ids.contains(&r.healthy_group_id))
        .map(|a| a.account_id.clone())
        .collect();
    let probe_members: BTreeSet<String> = readback
        .iter()
        .filter(|a| a.group_ids.contains(&r.probe_group_id))
        .map(|a| a.account_id.clone())
        .collect();
    let readback_ok = probe_members == expected
        && added.iter().all(|id| membership.contains(id))
        && removals.iter().all(|id| !membership.contains(id));
    Ok(
        json!({"at_ms":host::now(),"ok":readback_ok && key_scopes_ok && !pool_guard,"enabled":true,"key_scopes_ok":key_scopes_ok,"pool_guard":pool_guard,"added":added,"removed":removals,"healthy_members":membership,"membership":"database_readback_only","runtime_isolation_verified":false,"missing_or_disabled_accounts":c.account_ids.iter().filter(|id|!expected.contains(*id)).collect::<Vec<_>>()}),
    )
}

#[derive(Default, Serialize, Deserialize)]
struct ManagedIndex {
    account_ids: Vec<String>,
}
async fn prune_removed_accounts(host: &HostClient, c: &Config) -> Result<(), PluginFault> {
    let previous = host::get::<ManagedIndex>(host, "managed-index").await?;
    let version = previous.as_ref().map(|v| v.1);
    let mut retained = c.account_ids.clone();
    for id in previous.map(|v| v.0.account_ids).unwrap_or_default() {
        if c.account_ids.contains(&id) {
            continue;
        }
        let key = host::account_key(&id);
        if let Some((state, version)) = host::get::<AccountState>(host, &key).await? {
            if state.quality.lease_until_ms > host::now() {
                retained.push(id);
                continue;
            }
            host::delete(host, &key, version).await?;
        }
    }
    retained.sort();
    retained.dedup();
    host::put(
        host,
        "managed-index",
        &ManagedIndex {
            account_ids: retained,
        },
        version,
    )
    .await?;
    Ok(())
}

async fn reserve_budget(host: &HostClient, c: &Config) -> Result<bool, PluginFault> {
    let old = host::get::<Budget>(host, "budget").await?;
    let version = old.as_ref().map(|v| v.1);
    let mut b = old.map(|v| v.0).unwrap_or_default();
    let day = host::now() / 86400000;
    // 回拨不刷新预算。预留整份输出额度，即使超时或无 usage 也不退款。
    if day > b.day {
        b = Budget {
            day,
            ..Budget::default()
        };
    }
    if b.attempts >= c.max_daily_attempts
        || b.reserved_output_tokens
            .saturating_add(u64::from(c.max_output_tokens))
            > c.max_daily_output_tokens
    {
        return Ok(false);
    }
    b.attempts += 1;
    b.reserved_output_tokens += u64::from(c.max_output_tokens);
    host::put(host, "budget", &b, version).await?;
    Ok(true)
}
pub async fn tick(
    host: &HostClient,
    c: &Config,
    account: Option<&str>,
    timeout: Duration,
) -> Result<Value, PluginFault> {
    let started = Instant::now();
    if account.is_some_and(|id| !c.account_ids.iter().any(|managed| managed == id)) {
        return Err(fault("account_not_managed"));
    }
    if !c.enabled {
        return Ok(json!({"status":"disabled"}));
    }
    let r = resources(host).await?;
    check_keys(host, &r, c).await?;
    check_probe_budget(host, &r, c).await?;
    let mut due = Vec::new();
    for a in host::accounts(host).await?.into_iter().filter(|a| {
        managed(a, c)
            && a.group_ids.contains(&r.probe_group_id)
            && account.is_none_or(|id| id == a.account_id)
    }) {
        let (s, v) = load(host, &a.account_id, c).await?;
        let now = host::now();
        if s.quality.next_probe_at_ms <= now
            && s.quality.lease_until_ms <= now
            && s.quality.updated_at_ms <= now
        {
            let priority = match s.quality.phase {
                Phase::Cooling | Phase::Recovering => 0,
                Phase::Suspect => 1,
                Phase::Pending => 2,
                Phase::Healthy => 3,
            };
            due.push((priority, s.quality.next_probe_at_ms, a.account_id, s, v));
        }
    }
    due.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
    let Some((_, _, id, mut s, version)) = due.into_iter().next() else {
        return Ok(json!({"status":"no_due_account"}));
    };
    let now = host::now();
    if !s.quality.lease_id.is_empty() {
        s.quality.observe(Verdict::Unknown, "", now, &c.policy);
        s.quality.last_error = Some("expired_probe_lease".into());
    }
    if s.quality.next_probe_at_ms > now {
        s.quality.lease_id.clear();
        s.quality.lease_until_ms = 0;
        host::put(host, &host::account_key(&id), &s, version).await?;
        return Ok(json!({"status":"expired_probe_recorded_unknown","account_id":id}));
    }
    let lease = format!(
        "{}-{}-{}",
        now,
        std::process::id(),
        s.quality.sample_counter
    );
    s.quality.lease_id = lease.clone();
    s.quality.lease_until_ms = now.saturating_add(150000);
    let claimed = host::put(host, &host::account_key(&id), &s, version).await?;
    match reserve_budget(host, c).await {
        Ok(true) => {}
        other => {
            s.quality.lease_id.clear();
            s.quality.lease_until_ms = 0;
            host::put(host, &host::account_key(&id), &s, Some(claimed)).await?;
            return match other {
                Ok(false) => Ok(json!({"status":"daily_budget_exhausted"})),
                Err(e) => Err(e),
                _ => unreachable!(),
            };
        }
    }
    let hash = Sha256::digest(format!("{id}:{lease}").as_bytes());
    let seed = u64::from_be_bytes(hash[..8].try_into().map_err(|_| fault("seed_failed"))?);
    let challenge = scorer::challenge(seed);
    let result = tokio::time::timeout(
        timeout.saturating_sub(started.elapsed()),
        execute(host, c, &r.probe_key_id, &id, &challenge),
    )
    .await;
    let (request_id, mut score, mut error) = match result {
        Ok(Ok((id, score))) => (Some(id), Some(score), None),
        Ok(Err((id, reason))) => (id, None, Some(reason)),
        Err(_) => (None, None, Some("probe_timeout".into())),
    };
    let finished = host::now();
    if finished >= s.quality.lease_until_ms || finished < now {
        score = None;
        error = Some("expired_or_clock_shifted_probe".into());
    }
    let verdict = score
        .as_ref()
        .map(|s| classify(s, c))
        .unwrap_or(Verdict::Unknown);
    let candidate = score
        .as_ref()
        .map(|s| s.predicted_model.as_str())
        .unwrap_or("");
    s.quality.observe(verdict, candidate, finished, &c.policy);
    s.quality.last_error = error.clone();
    s.quality.last_request_id = request_id.clone();
    s.quality.lease_id.clear();
    s.quality.lease_until_ms = 0;
    let evidence = Evidence {
        at_ms: finished,
        challenge_id: challenge.id,
        request_id,
        verdict,
        score,
        error,
    };
    s.history.push(evidence);
    if s.history.len() > 12 {
        s.history.remove(0);
    }
    // 精确 CAS；其他进程接管租约或改写记录时，旧结果不能覆盖新结论。
    host::put(host, &host::account_key(&id), &s, Some(claimed)).await?;
    Ok(
        json!({"status":"sample_recorded","account_id":id,"model":c.model,"quality":s.quality,"sample":s.history.last()}),
    )
}
fn classify(s: &Score, c: &Config) -> Verdict {
    if s.predicted_model == c.model && s.expected_probability >= c.confidence_threshold {
        Verdict::Healthy
    } else if s.predicted_model != c.model
        && s.predicted_probability >= c.confidence_threshold
        && s.expected_probability <= 1.0 - c.confidence_threshold
    {
        Verdict::Anomaly
    } else {
        Verdict::Unknown
    }
}
async fn execute(
    host: &HostClient,
    c: &Config,
    key: &str,
    account: &str,
    challenge: &scorer::Challenge,
) -> Result<(String, Score), (Option<String>, String)> {
    let failure = |reason: &str| (None, reason.to_string());
    let meta = ModelExecuteRequest {
        client_key_id: Some(key.into()),
        model: c.model.clone(),
        protocol: "openai".into(),
        operation: ModelOperation::Generate,
        provider: Some(PROVIDER.into()),
        account_id: Some(account.into()),
        previous_response_id: None,
    };
    let payload = json!({"model":c.model,"input":[{"role":"user","content":[{"type":"input_text","text":challenge.prompt}]}],"store":false,"stream":true,"max_output_tokens":c.max_output_tokens,"reasoning":{"effort":"low"}});
    let reply = host
        .call(
            "host.model.execute",
            serde_json::to_value(meta).map_err(|_| failure("request_encode"))?,
            serde_json::to_vec(&payload).map_err(|_| failure("request_encode"))?,
        )
        .await
        .map_err(|_| failure("upstream_or_host_execution_failed"))?;
    let result: ModelExecuteResult =
        serde_json::from_value(reply.result).map_err(|_| failure("invalid_model_metadata"))?;
    let score = (|| -> Result<Score, String> {
        let batch = ModelEventBatch::decode(&reply.payload).map_err(|_| "invalid_event_batch")?;
        if result.events as usize != batch.events.len() {
            return Err("event_count_mismatch".into());
        }
        let text = valid_output(batch)?;
        scorer::score(&text, challenge.expected_count, &c.model)
            .map_err(|_| "invalid_or_unscorable_output".into())
    })();
    match score {
        Ok(score) => Ok((result.request_id, score)),
        Err(reason) => Err((Some(result.request_id), reason)),
    }
}

fn valid_output(batch: ModelEventBatch) -> Result<String, String> {
    let mut text = String::new();
    let mut completed = false;
    let mut text_index = None;
    for event in batch.events {
        if let Some(wire) = event.wire {
            match wire.payload {
                WirePayload::Json { data, .. } => {
                    if bad_wire(&data) {
                        return Err("wire_error_or_incomplete".into());
                    }
                }
                WirePayload::RawJson { body } => {
                    let data: Value =
                        serde_json::from_slice(&body).map_err(|_| "invalid_wire_json")?;
                    if bad_wire(&data) {
                        return Err("wire_error_or_incomplete".into());
                    }
                }
                WirePayload::RawBody { body } if !body.is_empty() => {
                    return Err("unvalidated_wire_body".into());
                }
                WirePayload::RawSse { frame } => {
                    let raw = String::from_utf8(frame).map_err(|_| "invalid_wire_sse")?;
                    if raw.contains("error")
                        || raw.contains("response.failed")
                        || raw.contains("response.incomplete")
                    {
                        return Err("wire_error_or_incomplete".into());
                    }
                }
                _ => {}
            }
        }
        for fact in event.facts {
            match fact {
                CanonicalEvent::ContentAdded {
                    kind: ContentKind::ToolCall | ContentKind::Image | ContentKind::Audio,
                    ..
                }
                | CanonicalEvent::ToolCallDelta { .. } => return Err("non_text_response".into()),
                CanonicalEvent::TextDelta { index, text: delta } => {
                    if completed || text_index.is_some_and(|i| i != index) {
                        return Err("ambiguous_output".into());
                    }
                    text_index = Some(index);
                    text.push_str(&delta);
                    if text.len() > 32768 {
                        return Err("output_too_large".into());
                    }
                }
                CanonicalEvent::Completed {
                    reason: FinishReason::Stop,
                    ..
                } if !completed => completed = true,
                CanonicalEvent::Completed { .. } => {
                    return Err("incomplete_or_duplicate_completion".into());
                }
                _ => {}
            }
        }
    }
    if !completed || text.is_empty() {
        return Err("missing_completed_text".into());
    }
    Ok(text)
}
fn bad_wire(data: &Value) -> bool {
    data.get("error").is_some_and(|v| !v.is_null())
        || data
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|s| matches!(s, "error" | "response.failed" | "response.incomplete"))
        || data
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|s| matches!(s, "failed" | "incomplete" | "cancelled"))
        || data.get("response").is_some_and(bad_wire)
}
pub async fn status(host: &HostClient, c: &Config) -> Result<Value, PluginFault> {
    let r = host::get::<Resources>(host, "resources")
        .await?
        .map(|v| v.0);
    let accounts = host::accounts(host).await?;
    let mut records = Vec::new();
    for id in &c.account_ids {
        let (s, _) = load(host, id, c).await?;
        let account = accounts.iter().find(|a| a.account_id == *id);
        records.push(json!({"account_id":id,"name":account.map(|a| &a.name),"email":account.and_then(|a| a.email.as_deref()),"enabled":account.is_some_and(|a|a.enabled),"in_healthy_group":r.as_ref().is_some_and(|r|account.is_some_and(|a|a.group_ids.contains(&r.healthy_group_id))),"quality":s.quality,"last_sample":s.history.last(),"history":s.history,"overdue_ms":host::now().saturating_sub(s.quality.next_probe_at_ms).max(0)}));
    }
    let scope_ok = if let Some(r) = &r {
        check_keys(host, r, c).await.is_ok()
    } else {
        false
    };
    let budget_ok = if let Some(r) = &r {
        check_probe_budget(host, r, c).await.is_ok()
    } else {
        false
    };
    Ok(
        json!({"enabled":c.enabled,"auto_probe":c.auto_probe,"probe_limits":{"max_daily_attempts":c.max_daily_attempts,"max_daily_output_tokens":c.max_daily_output_tokens,"max_output_tokens":c.max_output_tokens},"model":c.model,"scorer_version":scorer::VERSION,"classifier_scores_are_not_model_identity_proof":true,"key_scopes_ok":scope_ok,"probe_budget_ok":budget_ok,"resources":r,"budget":host::get::<Budget>(host,"budget").await?.map(|v|v.0),"maintenance":host::get::<Value>(host,"maintenance").await?.map(|v|v.0),"accounts":records}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_plugin_sdk::call::model::ExecutionEvent;
    #[test]
    fn only_confident_expected_and_confident_alternative_are_actionable() {
        let c = Config::default();
        let s = |model: &str, p: f64, e: f64| Score {
            predicted_model: model.into(),
            predicted_probability: p,
            expected_probability: e,
        };
        assert_eq!(
            classify(&s("gpt-6-astra", 0.999, 0.999), &c),
            Verdict::Healthy
        );
        assert_eq!(
            classify(&s("gpt-5.6-luna", 0.999, 0.001), &c),
            Verdict::Anomaly
        );
        assert_eq!(classify(&s("gpt-5.6-luna", 0.8, 0.2), &c), Verdict::Unknown);
        assert_eq!(classify(&s("gpt-6-astra", 0.8, 0.8), &c), Verdict::Unknown);
    }
    #[test]
    fn require_clean_complete_text() {
        let text = || {
            ExecutionEvent::canonical(CanonicalEvent::TextDelta {
                index: 0,
                text: "1,2,3".into(),
            })
        };
        let done = |reason| {
            ExecutionEvent::canonical(CanonicalEvent::Completed {
                id: "test".into(),
                model: None,
                reason,
            })
        };
        assert!(
            valid_output(ModelEventBatch {
                events: vec![text()]
            })
            .is_err()
        );
        assert!(
            valid_output(ModelEventBatch {
                events: vec![text(), done(FinishReason::Length)]
            })
            .is_err()
        );
        assert_eq!(
            valid_output(ModelEventBatch {
                events: vec![text(), done(FinishReason::Stop)]
            })
            .unwrap(),
            "1,2,3"
        );
        assert!(bad_wire(&json!({"response":{"status":"incomplete"}})));
    }
}
