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
        host::{
            ModelEventBatch, ModelExecuteRequest, ModelOperation, ModelStreamCloseRequest,
            ModelStreamReadRequest, ModelStreamReadResult, ModelStreamResult,
        },
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
struct ChallengeEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_id: Option<String>,
    at_ms: i64,
    challenge_id: String,
    prompt: String,
    expected_count: usize,
    request_id: Option<String>,
    output: Option<String>,
    number_count: Option<usize>,
    error: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct FingerprintBatch {
    started_at_ms: i64,
    completed_at_ms: Option<i64>,
    model: String,
    attempts: Vec<ChallengeEvidence>,
    score: Option<Score>,
    verdict: Option<Verdict>,
    error: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct AccountState {
    quality: Record,
    #[serde(default)]
    history: Vec<Evidence>,
    #[serde(default)]
    batch: Option<FingerprintBatch>,
}
#[derive(Default, Serialize, Deserialize)]
struct Budget {
    day: i64,
    attempts: u32,
    reserved_output_tokens: u64,
}

const VISUAL_PROMPT: &str = "创建一个HTML，内容是SVG绘制一个鹈鹕骑自行车的2D动画，你不需要任何测试";
const LOGIC_PROMPT: &str = "在一个黑色的袋子里放有三种口味的糖果，每种糖果有两种不同的形状（圆形和五角星形，不同的形状靠手感可以分辨）。现已知不同口味的糖和不同形状的数量统计如下表。参赛者需要在活动前决定摸出的糖果数目，那么，最少取出多少个糖果才能保证手中同时拥有不同形状的苹果味和桃子味的糖？（同时手中有圆形苹果味匹配五角星桃子味糖果，或者有圆形桃子味匹配五角星苹果味糖果都满足要求） 苹果味 桃子味 西瓜味 圆形 7 9 8 五角星形 7 6 4";
const VISUAL_MAXIMUM_BYTES: usize = 24 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRequest {
    pub account_id: String,
    pub model: String,
    pub reasoning_effort: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct ManualEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_id: Option<String>,
    id: String,
    account_id: String,
    model: String,
    reasoning_effort: String,
    started_at_ms: i64,
    completed_at_ms: i64,
    duration_ms: u128,
    request_id: Option<String>,
    output: Option<String>,
    prompt: String,
    status: String,
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assessment: Option<Value>,
}

#[derive(Default, Serialize, Deserialize)]
struct ManualHistory {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    visual_tests: Vec<ManualEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    logic_tests: Vec<ManualEvidence>,
}

#[derive(Clone, Copy)]
pub enum ManualCase {
    Visual,
    Logic,
}
impl ManualCase {
    fn namespace(self) -> &'static str {
        match self {
            Self::Visual => "visual",
            Self::Logic => "logic",
        }
    }
    fn prompt(self) -> &'static str {
        match self {
            Self::Visual => VISUAL_PROMPT,
            Self::Logic => LOGIC_PROMPT,
        }
    }
    fn tests(self, history: &mut ManualHistory) -> &mut Vec<ManualEvidence> {
        match self {
            Self::Visual => &mut history.visual_tests,
            Self::Logic => &mut history.logic_tests,
        }
    }
}

fn manual_lease(lease: &str) -> bool {
    lease.starts_with("visual:") || lease.starts_with("logic:")
}

pub(crate) fn visual_models(c: &Config) -> Vec<String> {
    let mut models: Vec<_> = scorer::supported_models()
        .into_iter()
        .filter(|id| id.starts_with("gpt-"))
        .collect();
    if !models.contains(&c.model) && scorer::supports_model(&c.model) {
        models.push(c.model.clone());
    }
    models
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
        batch: None,
    });
    if value.quality.config_tag != c.tag() {
        value.quality = value.quality.reset_for_config(c.tag(), host::now());
        value.batch = None;
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
                requests_per_minute: if probe { 6 } else { 0 },
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
        for namespace in ["visual", "logic"] {
            if let Some((_, version)) = host::get_in::<ManualHistory>(host, namespace, &key).await?
            {
                host::delete_in(host, namespace, &key, version).await?;
            }
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
    let Some(lease) = crate::jobs::begin_legacy(host, timeout).await? else {
        return Ok(json!({"status":"queue_active"}));
    };
    let result = tick_for_job(host, c, account, timeout, None).await;
    crate::jobs::release_legacy(host, &lease).await?;
    result
}

pub(crate) async fn tick_for_job(
    host: &HostClient,
    c: &Config,
    account: Option<&str>,
    timeout: Duration,
    attempt_id: Option<&str>,
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
            let last_attempt = s
                .batch
                .as_ref()
                .and_then(|b| b.attempts.last())
                .map_or(0, |a| a.at_ms);
            let new_batch = s
                .batch
                .as_ref()
                .is_none_or(|b| b.completed_at_ms.is_some() || b.attempts.is_empty());
            due.push((priority, new_batch, last_attempt, a.account_id, s, v));
        }
    }
    due.sort_by(|a, b| (a.0, a.1, a.2, &a.3).cmp(&(b.0, b.1, b.2, &b.3)));
    let Some((_, _, _, id, mut s, version)) = due.into_iter().next() else {
        return Ok(json!({"status":"no_due_account"}));
    };
    let now = host::now();
    if manual_lease(&s.quality.lease_id) {
        // A cancelled manual comparison never changes fingerprint evidence or quality.
        s.quality.lease_id.clear();
        s.quality.lease_until_ms = 0;
    } else if !s.quality.lease_id.is_empty() {
        s.quality.observe(Verdict::Unknown, "", now, &c.policy);
        s.quality.last_error = Some("expired_probe_lease".into());
        s.batch = None;
    }
    if s.quality.next_probe_at_ms > now {
        s.quality.lease_id.clear();
        s.quality.lease_until_ms = 0;
        host::put(host, &host::account_key(&id), &s, version).await?;
        return Ok(json!({"status":"expired_probe_recorded_unknown","account_id":id}));
    }
    // Do not combine answers collected across long gaps or clock rollback.
    if s.batch.as_ref().is_some_and(|b| {
        b.completed_at_ms.is_none()
            && (now < b.started_at_ms || now - b.started_at_ms > 30 * 60 * 1000)
    }) {
        s.quality.observe(Verdict::Unknown, "", now, &c.policy);
        s.quality.last_error = Some("fingerprint_batch_expired".into());
        s.batch = None;
        host::put(host, &host::account_key(&id), &s, version).await?;
        return Ok(json!({"status":"fingerprint_batch_expired","account_id":id}));
    }
    if s.batch.as_ref().is_none_or(|b| b.completed_at_ms.is_some()) {
        s.batch = Some(FingerprintBatch {
            started_at_ms: now,
            completed_at_ms: None,
            model: c.model.clone(),
            attempts: vec![],
            score: None,
            verdict: None,
            error: None,
        });
    }
    let lease = attempt_id.map(|id| format!("job:{id}")).unwrap_or_else(|| {
        format!(
            "{}-{}-{}",
            now,
            std::process::id(),
            s.quality.sample_counter
        )
    });
    s.quality.lease_id = lease.clone();
    s.quality.lease_until_ms = now.saturating_add(lease_duration(timeout));
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
    let mut seed = u64::from_be_bytes(hash[..8].try_into().map_err(|_| fault("seed_failed"))?);
    let batch = s.batch.as_mut().expect("batch created before lease");
    // ModelTrace uses independent prompts with distinct requested lengths within a batch.
    let challenge = loop {
        let challenge = scorer::challenge(seed);
        if !batch
            .attempts
            .iter()
            .any(|a| a.expected_count == challenge.expected_count)
        {
            break challenge;
        }
        seed = seed.wrapping_add(1);
    };
    let result = execute(
        host,
        c,
        &r.probe_key_id,
        &id,
        &challenge,
        timeout.saturating_sub(started.elapsed()),
    )
    .await;
    let (request_id, output, mut error) = match result {
        Ok((id, text)) => (Some(id), Some(text), None),
        Err((id, reason)) => (id, None, Some(reason)),
    };
    let finished = host::now();
    if finished >= s.quality.lease_until_ms || finished < now {
        error = Some("expired_or_clock_shifted_probe".into());
    }
    let number_count = if error.is_none() {
        match scorer::validate_output(output.as_deref().unwrap_or(""), challenge.expected_count) {
            Ok(count) => Some(count),
            Err(reason) => {
                error = Some(reason);
                None
            }
        }
    } else {
        None
    };
    batch.attempts.push(ChallengeEvidence {
        attempt_id: attempt_id.map(str::to_owned),
        at_ms: finished,
        challenge_id: challenge.id.clone(),
        prompt: challenge.prompt,
        expected_count: challenge.expected_count,
        request_id: request_id.clone(),
        output,
        number_count,
        error: error.clone(),
    });
    let valid: Vec<_> = batch
        .attempts
        .iter()
        .filter(|a| a.error.is_none())
        .filter_map(|a| a.output.as_deref().map(|text| (text, a.expected_count)))
        .collect();
    let complete = valid.len() == 3 || batch.attempts.len() >= 6;
    if complete {
        let score = if valid.len() == 3 {
            match scorer::score_batch(&valid, &c.model) {
                Ok(score) => Some(score),
                Err(reason) => {
                    error = Some(reason);
                    None
                }
            }
        } else {
            error = Some("insufficient_valid_answers".into());
            None
        };
        let verdict = score
            .as_ref()
            .map(|score| classify(score, c))
            .unwrap_or(Verdict::Unknown);
        let candidate = score
            .as_ref()
            .map(|score| score.predicted_model.as_str())
            .unwrap_or("");
        // Exactly one verdict is consumed per three-answer fingerprint, never three votes.
        s.quality.observe(verdict, candidate, finished, &c.policy);
        batch.completed_at_ms = Some(finished);
        batch.score = score.clone();
        batch.verdict = Some(verdict);
        batch.error = error.clone();
        let summary_score = score.map(|mut score| {
            score.candidates.clear();
            score
        });
        s.history.push(Evidence {
            at_ms: finished,
            challenge_id: challenge.id,
            request_id: request_id.clone(),
            verdict,
            score: summary_score,
            error: error.clone(),
        });
        if s.history.len() > 12 {
            s.history.remove(0);
        }
    } else {
        s.quality.next_probe_at_ms = finished;
        s.quality.updated_at_ms = finished;
    }
    s.quality.last_error = error;
    s.quality.last_request_id = request_id;
    s.quality.lease_id.clear();
    s.quality.lease_until_ms = 0;
    // Exact CAS: a late response cannot overwrite a replacement worker's evidence.
    host::put(host, &host::account_key(&id), &s, Some(claimed)).await?;
    Ok(
        json!({"status":if complete {"batch_completed"} else {"challenge_recorded"},
        "account_id":id,"model":c.model,"quality":s.quality,"batch":s.batch,
        "sample":if complete {s.history.last()} else {None}}),
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

pub async fn manual_test(
    host: &HostClient,
    c: &Config,
    input: ManualRequest,
    case: ManualCase,
    timeout: Duration,
) -> Result<Value, PluginFault> {
    let Some(lease) = crate::jobs::begin_legacy(host, timeout).await? else {
        return Ok(json!({"status":"queue_active","account_id":input.account_id}));
    };
    let result = manual_test_for_job(host, c, input, case, timeout, None).await;
    crate::jobs::release_legacy(host, &lease).await?;
    result
}

pub(crate) async fn manual_test_for_job(
    host: &HostClient,
    c: &Config,
    input: ManualRequest,
    case: ManualCase,
    timeout: Duration,
    attempt_id: Option<&str>,
) -> Result<Value, PluginFault> {
    let started = Instant::now();
    let namespace = case.namespace();
    let id = &input.account_id;
    if !c.account_ids.contains(id) {
        return Err(fault("account_not_managed"));
    }
    if !visual_models(c).contains(&input.model)
        || !["low", "medium", "high"].contains(&input.reasoning_effort.as_str())
    {
        return Err(fault(match case {
            ManualCase::Visual => "invalid_visual_model_or_effort",
            ManualCase::Logic => "invalid_logic_model_or_effort",
        }));
    }
    if !c.enabled {
        return Ok(json!({"status":"disabled","account_id":id}));
    }
    let r = resources(host).await?;
    check_keys(host, &r, c).await?;
    check_probe_budget(host, &r, c).await?;
    if !host::accounts(host).await?.iter().any(|account| {
        account.account_id == *id
            && managed(account, c)
            && account.group_ids.contains(&r.probe_group_id)
    }) {
        return Err(fault("account_not_available_in_probe_group"));
    }
    let key = host::account_key(id);
    // Manual comparisons never migrate or reset fingerprint state for a new configuration.
    let stored = host::get::<AccountState>(host, &key).await?;
    let version = stored.as_ref().map(|record| record.1);
    let mut state = stored.map(|record| record.0).unwrap_or(AccountState {
        quality: Record::new(c.tag(), host::now()),
        history: vec![],
        batch: None,
    });
    let now = host::now();
    if state.quality.lease_until_ms > now
        || state.quality.updated_at_ms > now
        // Only the fingerprint path may resolve an interrupted fingerprint lease.
        || (!state.quality.lease_id.is_empty()
            && !manual_lease(&state.quality.lease_id))
    {
        return Ok(json!({"status":"account_busy","account_id":id}));
    }
    let lease = attempt_id
        .map(|id| format!("{namespace}:job:{id}"))
        .unwrap_or_else(|| {
            format!(
                "{namespace}:{now}:{}:{}",
                std::process::id(),
                version.unwrap_or(0)
            )
        });
    state.quality.lease_id = lease.clone();
    state.quality.lease_until_ms = now.saturating_add(lease_duration(timeout));
    let claimed = host::put(host, &key, &state, version).await?;
    match reserve_budget(host, c).await {
        Ok(true) => {}
        other => {
            state.quality.lease_id.clear();
            state.quality.lease_until_ms = 0;
            host::put(host, &key, &state, Some(claimed)).await?;
            return match other {
                Ok(false) => Ok(json!({"status":"daily_budget_exhausted","account_id":id})),
                Err(error) => Err(error),
                _ => unreachable!(),
            };
        }
    }
    let payload = json!({"model":input.model,"input":[{"role":"user","content":[{"type":"input_text","text":case.prompt()}]}],"store":false,"stream":true,"max_output_tokens":c.max_output_tokens,"reasoning":{"effort":input.reasoning_effort}});
    let result = execute_model(
        host,
        &r.probe_key_id,
        id,
        &input.model,
        &payload,
        timeout.saturating_sub(started.elapsed()),
        VISUAL_MAXIMUM_BYTES,
    )
    .await;
    let (request_id, output, error) = match result {
        Ok((request_id, output)) => {
            let error = if matches!(case, ManualCase::Visual) {
                visual_document(&output).err()
            } else {
                None
            };
            (Some(request_id), Some(output), error)
        }
        Err((request_id, error)) => (
            request_id,
            None,
            Some(error.replace("model_timeout", &format!("{namespace}_timeout"))),
        ),
    };
    let finished = host::now();
    let mut sample = ManualEvidence {
        attempt_id: attempt_id.map(str::to_owned),
        id: format!(
            "{namespace}-{:x}",
            Sha256::digest(format!("{id}:{lease}").as_bytes())
        ),
        account_id: id.clone(),
        model: input.model,
        reasoning_effort: input.reasoning_effort,
        started_at_ms: now,
        completed_at_ms: finished,
        duration_ms: started.elapsed().as_millis(),
        request_id,
        output,
        prompt: case.prompt().into(),
        status: if error.is_none() {
            "completed"
        } else {
            "error"
        }
        .into(),
        error,
        assessment: None,
    };
    if finished >= state.quality.lease_until_ms || finished < now {
        sample.error = Some(format!("expired_or_clock_shifted_{namespace}"));
        sample.output = None;
    }
    if matches!(case, ManualCase::Logic) {
        sample.assessment = Some(logic_assessment(
            sample.output.as_deref().filter(|_| sample.error.is_none()),
        ));
    }
    if serde_json::to_vec(&sample)
        .map_err(|_| fault("manual_evidence_encode"))?
        .len()
        > VISUAL_MAXIMUM_BYTES
    {
        sample.error = Some("output_too_large".into());
        sample.output = None;
        if matches!(case, ManualCase::Logic) {
            sample.assessment = Some(logic_assessment(None));
        }
    }
    if sample.error.is_some() {
        sample.status = "error".into();
    }
    let saved = async {
        // A review can update an older visual result while this request is running.
        let old = host::get_in::<ManualHistory>(host, namespace, &key).await?;
        let history_version = old.as_ref().map(|record| record.1);
        let mut history = old.map(|record| record.0).unwrap_or_default();
        let tests = case.tests(&mut history);
        tests.push(sample.clone());
        let discard = tests.len().saturating_sub(4);
        tests.drain(..discard);
        host::put_in(host, namespace, &key, &history, history_version).await
    }
    .await;
    state.quality.lease_id.clear();
    state.quality.lease_until_ms = 0;
    // Release even if saving evidence failed; CAS never overwrites a replacement worker.
    let released = host::put(host, &key, &state, Some(claimed)).await;
    saved?;
    released?;
    Ok(
        json!({"status":format!("{namespace}_recorded"),"account_id":id,(format!("{namespace}_sample")):sample}),
    )
}

fn lease_duration(timeout: Duration) -> i64 {
    i64::try_from(timeout.as_millis())
        .unwrap_or(i64::MAX)
        .saturating_add(40000)
}

// Clear only this interrupted job's fence; never release a replacement worker's lease.
pub(crate) async fn interrupt_job_attempt(
    host: &HostClient,
    c: &Config,
    account: &str,
    kind: &str,
    attempt_id: &str,
) -> Result<(), PluginFault> {
    let key = host::account_key(account);
    let Some((mut state, version)) = host::get::<AccountState>(host, &key).await? else {
        return Ok(());
    };
    let lease = if kind == "fingerprint" {
        format!("job:{attempt_id}")
    } else {
        format!("{kind}:job:{attempt_id}")
    };
    if state.quality.lease_id != lease {
        return Ok(());
    }
    if kind == "fingerprint" {
        state
            .quality
            .observe(Verdict::Unknown, "", host::now(), &c.policy);
        state.quality.last_error = Some("job_interrupted_not_replayed".into());
        state.batch = None;
    }
    state.quality.lease_id.clear();
    state.quality.lease_until_ms = 0;
    host::put(host, &key, &state, Some(version)).await?;
    Ok(())
}

// Recover the narrow window where model evidence was committed before its queue progress.
pub(crate) async fn completed_job_attempt(
    host: &HostClient,
    account: &str,
    kind: &str,
    attempt_id: &str,
) -> Result<Option<Value>, PluginFault> {
    let key = host::account_key(account);
    if kind == "fingerprint" {
        let Some((state, _)) = host::get::<AccountState>(host, &key).await? else {
            return Ok(None);
        };
        if state.batch.as_ref().is_some_and(|batch| {
            batch
                .attempts
                .iter()
                .any(|attempt| attempt.attempt_id.as_deref() == Some(attempt_id))
        }) {
            return Ok(Some(
                json!({"status":if state.batch.as_ref().is_some_and(|batch|batch.completed_at_ms.is_some()) {"batch_completed"} else {"challenge_recorded"},"account_id":account,"batch":state.batch,"quality":state.quality}),
            ));
        }
        return Ok(None);
    }
    let case = if kind == "visual" {
        ManualCase::Visual
    } else {
        ManualCase::Logic
    };
    let mut history = host::get_in::<ManualHistory>(host, kind, &key)
        .await?
        .map(|record| record.0)
        .unwrap_or_default();
    Ok(case.tests(&mut history).iter().find(|sample|sample.attempt_id.as_deref()==Some(attempt_id)).map(|sample|json!({"status":format!("{kind}_recorded"),"account_id":account,(format!("{kind}_sample")):sample})))
}

fn visual_document(output: &str) -> Result<(), String> {
    let html = output.to_ascii_lowercase();
    let opens: Vec<_> = html
        .match_indices("<html")
        .filter(|(at, _)| {
            html.as_bytes()
                .get(at + 5)
                .is_some_and(|c| c.is_ascii_whitespace() || *c == b'>')
        })
        .map(|(at, _)| at)
        .collect();
    let closes: Vec<_> = html.match_indices("</html>").map(|(at, _)| at).collect();
    if opens.len() != 1 || closes.len() != 1 || opens[0] >= closes[0] {
        return Err("incomplete_html_document".into());
    }
    let document = &html[opens[0]..closes[0]];
    let tags: Option<Vec<_>> = ["<head", "</head>", "<body", "</body>"]
        .iter()
        .map(|tag| document.find(tag))
        .collect();
    if tags.is_none_or(|tags| !tags.windows(2).all(|pair| pair[0] < pair[1]))
        || ![0, 2].contains(&output.matches("```").count())
    {
        return Err("incomplete_html_document".into());
    }
    Ok(())
}

fn logic_assessment(output: Option<&str>) -> Value {
    let answer = output.and_then(logic_answer);
    json!({
        "verdict":match answer { Some(21) => "pass", Some(_) => "fail", None => "unknown" },
        "expected_answer":21,
        "answer":answer,
        "note":match answer {
            Some(21) => "明确结论为 21，逻辑测试通过。",
            Some(_) => "明确结论不是 21，逻辑测试未通过，疑似降智；不用于确认真实模型或自动冷却。",
            None => "请求失败、没有明确最终答案或结论冲突，无法判定。",
        }
    })
}

fn logic_answer(output: &str) -> Option<u64> {
    // Accept an explicit conclusion, never a number merely appearing in the reasoning.
    let clean = output
        .replace(['*', '$', '#'], "")
        .replace("\\boxed{", "")
        .replace('}', "");
    let clean = clean.trim();
    if let Some(answer) = answer_number(clean) {
        return Some(answer);
    }
    let mut answers = BTreeSet::new();
    if let Some(last) = clean.lines().last().and_then(answer_number) {
        answers.insert(last);
    }
    for sentence in clean.split(['\n', '。', '！', ';', '；', '，', ',']) {
        let sentence = sentence.trim();
        if sentence.contains(['?', '？'])
            || ["如果", "假设", "若", "并非", "不是", "不确定"]
                .iter()
                .any(|term| sentence.contains(term))
        {
            continue;
        }
        for marker in [
            "最终答案",
            "最后答案",
            "答案",
            "结论",
            "最少需要取出",
            "最少需要摸出",
            "至少需要取出",
            "至少需要摸出",
            "最少取出",
            "最少摸出",
            "最少需要",
            "最少要取出",
            "最少要摸出",
            "最少要摸",
            "最少要取",
        ] {
            for (at, _) in sentence.match_indices(marker) {
                let tail = &sentence[at + marker.len()..];
                let tail = tail
                    .trim_start_matches([' ', '：', ':', '，', ','])
                    .trim_start_matches("应该")
                    .trim_start_matches("应当")
                    .trim_start_matches("应")
                    .trim_start_matches("就是")
                    .trim_start_matches("是")
                    .trim_start_matches("为")
                    .trim_start_matches([' ', '：', ':'])
                    .split(['，', ','])
                    .next()
                    .unwrap_or_default()
                    .trim();
                if let Some(answer) = answer_number(tail) {
                    answers.insert(answer);
                }
            }
        }
    }
    if answers.len() == 1 {
        answers.into_iter().next()
    } else {
        None
    }
}

fn answer_number(text: &str) -> Option<u64> {
    let text = text.trim().trim_end_matches(['.', '。', '!', '！']);
    let text = ["个糖果", "颗糖果", "个", "颗"]
        .into_iter()
        .find_map(|suffix| text.strip_suffix(suffix))
        .unwrap_or(text)
        .trim();
    if !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()) {
        return text.parse().ok();
    }
    let digit = |s: &str| {
        ["零", "一", "二", "三", "四", "五", "六", "七", "八", "九"]
            .iter()
            .position(|value| *value == s)
            .map(|v| v as u64)
    };
    if let Some((tens, ones)) = text.split_once('十') {
        let tens = if tens.is_empty() { 1 } else { digit(tens)? };
        let ones = if ones.is_empty() { 0 } else { digit(ones)? };
        return Some(tens * 10 + ones);
    }
    digit(text)
}

pub async fn manual_evidence(
    host: &HostClient,
    c: &Config,
    account: &str,
    case: ManualCase,
) -> Result<Value, PluginFault> {
    if !c.account_ids.iter().any(|id| id == account) {
        return Err(fault("account_not_managed"));
    }
    let mut history =
        host::get_in::<ManualHistory>(host, case.namespace(), &host::account_key(account))
            .await?
            .map(|record| record.0)
            .unwrap_or_default();
    Ok(
        json!({"account_id":account,(format!("{}_tests",case.namespace())):case.tests(&mut history)}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisualReview {
    account_id: String,
    sample_id: String,
    verdict: String,
}

pub async fn visual_review(
    host: &HostClient,
    c: &Config,
    input: VisualReview,
) -> Result<Value, PluginFault> {
    if !c.account_ids.contains(&input.account_id) {
        return Err(fault("account_not_managed"));
    }
    if !["pass", "fail"].contains(&input.verdict.as_str()) {
        return Err(fault("invalid_visual_review"));
    }
    let key = host::account_key(&input.account_id);
    let mut reviewed = None;
    if let Some((mut history, version)) =
        host::get_in::<ManualHistory>(host, "visual", &key).await?
        && let Some(sample) = history
            .visual_tests
            .iter_mut()
            .find(|sample| sample.id == input.sample_id)
    {
        if sample.status != "completed" || sample.output.is_none() {
            return Err(fault("visual_sample_not_completed"));
        }
        sample.assessment = Some(json!({"verdict":input.verdict,"source":"manual"}));
        if serde_json::to_vec(&sample)
            .map_err(|_| fault("manual_evidence_encode"))?
            .len()
            > VISUAL_MAXIMUM_BYTES
        {
            return Err(fault("visual_review_too_large"));
        }
        reviewed = Some(json!(sample));
        host::put_in(host, "visual", &key, &history, Some(version)).await?;
    }
    // Jobs retain complete older outputs beyond the per-account four-sample window.
    let saved =
        crate::jobs::visual_review(host, &input.account_id, &input.sample_id, &input.verdict)
            .await?;
    let sample = saved
        .or(reviewed)
        .ok_or_else(|| fault("visual_sample_not_found"))?;
    Ok(json!({"status":"visual_reviewed","account_id":input.account_id,"visual_sample":sample}))
}

async fn execute(
    host: &HostClient,
    c: &Config,
    key: &str,
    account: &str,
    challenge: &scorer::Challenge,
    timeout: Duration,
) -> Result<(String, String), (Option<String>, String)> {
    let payload = json!({"model":c.model,"input":[{"role":"user","content":[{"type":"input_text","text":challenge.prompt}]}],"store":false,"stream":true,"max_output_tokens":c.max_output_tokens,"reasoning":{"effort":"low"}});
    execute_model(host, key, account, &c.model, &payload, timeout, 16384)
        .await
        .map_err(|(id, error)| (id, error.replace("model_timeout", "probe_timeout")))
}

async fn execute_model(
    host: &HostClient,
    key: &str,
    account: &str,
    model: &str,
    payload: &Value,
    timeout: Duration,
    maximum_bytes: usize,
) -> Result<(String, String), (Option<String>, String)> {
    let started = Instant::now();
    // Cleanup stays inside the caller's total deadline, before the host cancels its parent.
    let work_timeout = timeout.saturating_sub(Duration::from_secs(2).min(timeout / 4));
    let failure = |reason: &str| (None, reason.to_owned());
    let meta = ModelExecuteRequest {
        client_key_id: Some(key.into()),
        model: model.into(),
        protocol: "openai".into(),
        operation: ModelOperation::Generate,
        provider: Some(PROVIDER.into()),
        account_id: Some(account.into()),
        previous_response_id: None,
    };
    let reply = tokio::time::timeout(
        work_timeout,
        host.call(
            "host.model.execute_stream",
            serde_json::to_value(meta).map_err(|_| failure("request_encode"))?,
            serde_json::to_vec(payload).map_err(|_| failure("request_encode"))?,
        ),
    )
    .await
    .map_err(|_| failure("model_timeout"))?
    .map_err(|_| failure("upstream_or_host_execution_failed"))?;
    let stream: ModelStreamResult =
        serde_json::from_value(reply.result).map_err(|_| failure("invalid_model_metadata"))?;
    let request_id = Some(stream.request_id.clone());
    let mut read = Box::pin(async {
        if !reply.payload.is_empty() {
            return Err("unexpected_model_start_payload");
        }
        let mut output = TextOutput::default();
        loop {
            let reply = host
                .call(
                    "host.model.stream_read",
                    serde_json::to_value(ModelStreamReadRequest {
                        stream: stream.stream.clone(),
                        maximum_bytes: 1024 * 1024,
                    })
                    .map_err(|_| "request_encode")?,
                    vec![],
                )
                .await
                .map_err(|_| "upstream_or_host_execution_failed")?;
            let read: ModelStreamReadResult =
                serde_json::from_value(reply.result).map_err(|_| "invalid_model_metadata")?;
            if read.end {
                // Core has finalized and removed the handle; closing it again would be denied.
                if read.events != 0 || !reply.payload.is_empty() {
                    return Err("invalid_model_stream_end");
                }
                return Ok(output);
            }
            let batch =
                ModelEventBatch::decode(&reply.payload).map_err(|_| "invalid_event_batch")?;
            if read.events as usize != batch.events.len() {
                return Err("event_count_mismatch");
            }
            output.append(batch, maximum_bytes)?;
        }
    });
    // Retain the pending read so close can wake it and its host finalizer can finish.
    let result =
        tokio::time::timeout(work_timeout.saturating_sub(started.elapsed()), &mut read).await;
    let timed_out = result.is_err();
    let result = result.unwrap_or(Err("model_timeout"));
    if !matches!(result, Ok(_) | Err("invalid_model_stream_end")) {
        let close = host.call(
            "host.model.stream_close",
            serde_json::to_value(ModelStreamCloseRequest {
                stream: stream.stream.clone(),
            })
            .map_err(|_| (request_id.clone(), "request_encode".into()))?,
            vec![],
        );
        if !matches!(tokio::time::timeout(timeout.saturating_sub(started.elapsed()), close).await, Ok(Ok(reply)) if reply.result == json!({}) && reply.payload.is_empty())
        {
            return Err((
                request_id,
                format!(
                    "{}; model_stream_close_failed",
                    result.err().unwrap_or("model_stream_failed")
                ),
            ));
        }
        // The close ACK is immediate. A read already holding the session finalizes before
        // replying; do not end the parent and abort that cleanup while it is still pending.
        if timed_out
            && tokio::time::timeout(timeout.saturating_sub(started.elapsed()), &mut read)
                .await
                .is_err()
        {
            return Err((
                request_id,
                "model_timeout; model_stream_cleanup_pending".into(),
            ));
        }
    }
    match result {
        Ok(output) => output
            .finish(maximum_bytes)
            .map(|text| (stream.request_id, text))
            .map_err(|error| (request_id, error.into())),
        Err(error) => Err((request_id, error.into())),
    }
}

#[derive(Default)]
struct TextOutput {
    text: String,
    completed: bool,
}

impl TextOutput {
    // Validate each bounded host batch, retaining only canonical text rather than repeated wire metadata.
    fn append(&mut self, batch: ModelEventBatch, maximum_bytes: usize) -> Result<(), &'static str> {
        for event in batch.events {
            if let Some(wire) = event.wire {
                match wire.payload {
                    WirePayload::Json { data, .. } => {
                        if bad_wire(&data) {
                            return Err("wire_error_or_incomplete");
                        }
                    }
                    WirePayload::RawJson { body } => {
                        let data: Value =
                            serde_json::from_slice(&body).map_err(|_| "invalid_wire_json")?;
                        if bad_wire(&data) {
                            return Err("wire_error_or_incomplete");
                        }
                    }
                    WirePayload::RawBody { body } if !body.is_empty() => {
                        return Err("unvalidated_wire_body");
                    }
                    WirePayload::RawSse { frame } => {
                        let raw = String::from_utf8(frame).map_err(|_| "invalid_wire_sse")?;
                        if raw.contains("error")
                            || raw.contains("response.failed")
                            || raw.contains("response.incomplete")
                        {
                            return Err("wire_error_or_incomplete");
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
                    | CanonicalEvent::ToolCallDelta { .. } => return Err("non_text_response"),
                    CanonicalEvent::TextDelta { text: delta, .. } => {
                        if self.completed {
                            return Err("ambiguous_output");
                        }
                        if self.text.len().saturating_add(delta.len()) > maximum_bytes {
                            return Err("output_too_large");
                        }
                        self.text.push_str(&delta);
                    }
                    CanonicalEvent::Completed {
                        reason: FinishReason::Stop,
                        ..
                    } if !self.completed => self.completed = true,
                    CanonicalEvent::Completed { .. } => {
                        return Err("incomplete_or_duplicate_completion");
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn finish(self, maximum_bytes: usize) -> Result<String, &'static str> {
        if !self.completed || self.text.is_empty() {
            return Err("missing_completed_text");
        }
        // Bound the stored JSON size too: control characters can expand sixfold.
        if serde_json::to_vec(&self.text)
            .map_err(|_| "invalid_output_encoding")?
            .len()
            > maximum_bytes
        {
            return Err("output_too_large");
        }
        Ok(self.text)
    }
}

#[cfg(test)]
fn bounded_output(batch: ModelEventBatch, maximum_bytes: usize) -> Result<String, String> {
    let mut output = TextOutput::default();
    output.append(batch, maximum_bytes).map_err(str::to_owned)?;
    output.finish(maximum_bytes).map_err(str::to_owned)
}
#[cfg(test)]
fn valid_output(batch: ModelEventBatch) -> Result<String, String> {
    bounded_output(batch, 16384)
}
#[cfg(test)]
fn visual_output(batch: ModelEventBatch) -> Result<String, String> {
    {
        let output = bounded_output(batch, VISUAL_MAXIMUM_BYTES)?;
        visual_document(&output)?;
        Ok(output)
    }
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
fn batch_summary(batch: Option<&FingerprintBatch>) -> Value {
    let mut value = json!(batch);
    if let Some(attempts) = value.get_mut("attempts").and_then(Value::as_array_mut) {
        for attempt in attempts {
            if let Some(fields) = attempt.as_object_mut() {
                fields.remove("prompt");
                fields.remove("output");
            }
        }
    }
    value
}
pub async fn evidence(host: &HostClient, c: &Config, account: &str) -> Result<Value, PluginFault> {
    if !c.account_ids.iter().any(|id| id == account) {
        return Err(fault("account_not_managed"));
    }
    let (s, _) = load(host, account, c).await?;
    Ok(json!({"account_id":account,"batch":s.batch,"history":s.history,"quality":s.quality}))
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
        let mut visual = manual_evidence(host, c, id, ManualCase::Visual).await?;
        let mut logic = manual_evidence(host, c, id, ManualCase::Logic).await?;
        for sample in visual["visual_tests"]
            .as_array_mut()
            .into_iter()
            .flatten()
            .chain(logic["logic_tests"].as_array_mut().into_iter().flatten())
        {
            if let Some(sample) = sample.as_object_mut() {
                sample.remove("output");
                sample.remove("prompt");
            }
        }
        records.push(json!({"visual_tests":visual["visual_tests"],"logic_tests":logic["logic_tests"],"account_id":id,"name":account.map(|a| &a.name),"email":account.and_then(|a| a.email.as_deref()),"enabled":account.is_some_and(|a|a.enabled),"in_healthy_group":r.as_ref().is_some_and(|r|account.is_some_and(|a|a.group_ids.contains(&r.healthy_group_id))),"quality":s.quality,"last_sample":s.history.last(),"history":s.history,"batch":batch_summary(s.batch.as_ref()),"overdue_ms":host::now().saturating_sub(s.quality.next_probe_at_ms).max(0)}));
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
        json!({"visual_models":visual_models(c),"visual_efforts":["low","medium","high"],"visual_timeout_ms":110000,"enabled":c.enabled,"auto_probe":c.auto_probe,"probe_limits":{"max_daily_attempts":c.max_daily_attempts,"max_daily_output_tokens":c.max_daily_output_tokens,"max_output_tokens":c.max_output_tokens},"model":c.model,"scorer_version":scorer::VERSION,"classifier_scores_are_not_model_identity_proof":true,"key_scopes_ok":scope_ok,"probe_budget_ok":budget_ok,"resources":r,"budget":host::get::<Budget>(host,"budget").await?.map(|v|v.0),"maintenance":host::get::<Value>(host,"maintenance").await?.map(|v|v.0),"accounts":records}),
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
            sample_count: 3,
            candidates: vec![],
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
    fn full_evidence_and_hundred_account_summary_fit_host_limits() {
        let output = "\"".repeat(8191);
        assert_eq!(serde_json::to_vec(&output).unwrap().len(), 16384);
        let mut batch = FingerprintBatch {
            started_at_ms: 1,
            completed_at_ms: Some(2),
            model: "gpt-6-astra".into(),
            attempts: vec![],
            score: Some(
                scorer::score_batch(&[("7,".repeat(300).as_str(), 300); 3], "gpt-6-astra").unwrap(),
            ),
            verdict: Some(Verdict::Unknown),
            error: Some("insufficient_valid_answers".into()),
        };
        for seed in 0..6 {
            let challenge = scorer::challenge(seed);
            batch.attempts.push(ChallengeEvidence {
                attempt_id: None,
                at_ms: 2,
                challenge_id: challenge.id,
                prompt: challenge.prompt,
                expected_count: challenge.expected_count,
                request_id: Some("x".repeat(128)),
                output: Some(output.clone()),
                number_count: None,
                error: Some("insufficient_valid_answers".into()),
            });
        }
        let mut score = batch.score.clone().unwrap();
        score.candidates.clear();
        let state = AccountState {
            quality: Record::new("x".repeat(64), 1),
            batch: Some(batch),
            history: vec![
                Evidence {
                    at_ms: 2,
                    challenge_id: "x".repeat(128),
                    request_id: Some("x".repeat(128)),
                    verdict: Verdict::Unknown,
                    score: Some(score),
                    error: None
                };
                12
            ],
        };
        assert!(serde_json::to_vec(&state).unwrap().len() < 131072);
        let summary = json!({"quality":state.quality,"batch":batch_summary(state.batch.as_ref()),"history":state.history});
        assert!(serde_json::to_vec(&vec![summary; 100]).unwrap().len() < 1024 * 1024);
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

    #[test]
    fn visual_evidence_requires_a_complete_bounded_document_and_preserves_raw_fences() {
        let events = |text: &str, reason| ModelEventBatch {
            events: vec![
                ExecutionEvent::canonical(CanonicalEvent::TextDelta {
                    index: 0,
                    text: text.into(),
                }),
                ExecutionEvent::canonical(CanonicalEvent::Completed {
                    id: "visual".into(),
                    model: None,
                    reason,
                }),
            ],
        };
        let html = "<!DOCTYPE html><html><head></head><body><svg></svg></body></html>";
        for raw in [
            html.to_string(),
            format!("```html\n{html}\n```"),
            format!("```\r\n{html}\r\n```"),
            format!("以下是完整页面：\n```html\n{html}\n```\n保存后打开即可。"),
            format!("完整页面：\n{html}\n说明：用 SVG 绘制。"),
        ] {
            assert_eq!(
                visual_output(events(&raw, FinishReason::Stop)).unwrap(),
                raw
            );
        }
        for raw in [
            "<svg></svg>",
            "<!doctype html><html><head></head><body>",
            "```html\n<html><head></head><body></body></html>",
            "<html><head></head><body></body></html><html><head></head><body></body></html>",
            "<html><body></body><head></head></html>",
        ] {
            assert_eq!(
                visual_output(events(raw, FinishReason::Stop)).unwrap_err(),
                "incomplete_html_document"
            );
        }
        assert!(visual_output(events(html, FinishReason::Length)).is_err());
        assert_eq!(
            visual_output(events(
                &format!(
                    "<html><head></head><body>{}</body></html>",
                    "x".repeat(VISUAL_MAXIMUM_BYTES)
                ),
                FinishReason::Stop
            ))
            .unwrap_err(),
            "output_too_large"
        );
    }
    #[test]
    fn logic_judgment_requires_an_unambiguous_explicit_final_answer() {
        for (output, expected) in [
            ("21", Some(21)),
            ("21 个糖果", Some(21)),
            ("最终答案：**21**。", Some(21)),
            ("因此，最少需要取出 **21 个糖果**，才能保证。", Some(21)),
            ("答案是：21个。", Some(21)),
            ("答案是 $\\boxed{21}$。", Some(21)),
            ("最终答案是 33。", Some(33)),
            ("推导中出现 21，但暂时无法得出结论。", None),
            ("如果答案是 21，那么可以尝试证明。", None),
            ("答案不是 21。", None),
            ("答案是 21。最终答案是 33。", None),
            ("答案是 21 或 33。", None),
            ("不是21，最终答案是29。", Some(29)),
            ("推导中使用29作为反例，最终答案是21。", Some(21)),
            ("二十一", Some(21)),
            ("答案：二十一颗", Some(21)),
            ("答案：三十三个", Some(33)),
            ("最少取出多少个糖果？21 是否正确？", None),
        ] {
            assert_eq!(logic_answer(output), expected, "{output}");
        }
        assert_eq!(logic_assessment(Some("答案是21"))["verdict"], "pass");
        assert_eq!(logic_assessment(Some("答案是33"))["verdict"], "fail");
        assert_eq!(logic_assessment(None)["verdict"], "unknown");
    }
}
