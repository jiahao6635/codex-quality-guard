//! Durable batches; each maintenance call performs at most one charged model request.
use crate::{
    Config, engine,
    host::{self, fault},
};
use gateway_plugin_sdk::{PluginFault, client::HostClient};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Duration};

const NAMESPACE: &str = "jobs";
const INDEX: &str = "index";
const HISTORY_LIMIT: usize = 100;
const MAX_RESULT_BYTES: usize = 128 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnqueueRequest {
    submission_id: String,
    account_ids: Vec<String>,
    kind: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    reasoning_effort: Option<String>,
    #[serde(default = "one")]
    repetitions: u8,
}
fn one() -> u8 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdRequest {
    id: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Item {
    id: String,
    account_id: String,
    status: String,
    completed: usize,
    total: usize,
    error: Option<String>,
    started_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
    attempts: usize,
    attempt_id: String,
    incarnation: String,
    lease_until_ms: i64,
}
impl Item {
    fn active(&self) -> bool {
        matches!(self.status.as_str(), "queued" | "running")
    }
    fn finish(&mut self, status: &str, error: Option<&str>) {
        self.status = status.into();
        self.error = error.map(str::to_owned);
        self.completed_at_ms = Some(host::now());
        self.lease_until_ms = 0;
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Batch {
    id: String,
    request_hash: String,
    kind: String,
    model: String,
    reasoning_effort: String,
    repetitions: u8,
    created_at_ms: i64,
    config_tag: String,
    cancel_requested: bool,
    items: Vec<Item>,
}
impl Batch {
    fn active(&self) -> bool {
        self.items.iter().any(Item::active)
    }
    fn public(&self) -> Value {
        let status = if self.items.iter().any(|item| item.status == "running") {
            "running"
        } else if self.active() {
            "queued"
        } else if self.cancel_requested {
            "cancelled"
        } else {
            "completed"
        };
        json!({"id":self.id,"kind":self.kind,"model":self.model,"reasoning_effort":self.reasoning_effort,"repetitions":self.repetitions,"created_at_ms":self.created_at_ms,"status":status,"items":self.items})
    }
}
#[derive(Default, Serialize, Deserialize)]
struct Queue {
    batches: Vec<Batch>,
    #[serde(default)]
    garbage: Vec<String>,
    #[serde(default)]
    last_started_at_ms: i64,
    #[serde(default)]
    legacy_lease: String,
    #[serde(default)]
    legacy_until_ms: i64,
}
#[derive(Default, Serialize, Deserialize)]
struct Results {
    attempt_ids: Vec<String>,
    results: Vec<Value>,
}

async fn read(host: &HostClient) -> Result<(Queue, Option<u64>), PluginFault> {
    let stored = host::get_in::<Queue>(host, NAMESPACE, INDEX).await?;
    let version = stored.as_ref().map(|record| record.1);
    Ok((stored.map(|record| record.0).unwrap_or_default(), version))
}
async fn write(host: &HostClient, queue: &Queue, version: Option<u64>) -> Result<(), PluginFault> {
    host::put_in(host, NAMESPACE, INDEX, queue, version)
        .await
        .map(|_| ())
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn result_key(id: &str) -> String {
    format!("result.{id}")
}

// The old synchronous entry points share this fence with enqueue, so a page racing
// an existing request cannot reserve a second budget slot before the probe Key rejects it.
pub(crate) async fn begin_legacy(
    host: &HostClient,
    timeout: Duration,
) -> Result<Option<String>, PluginFault> {
    let (mut queue, version) = read(host).await?;
    let now = host::now();
    if queue.batches.iter().any(Batch::active) || queue.legacy_until_ms > now {
        return Ok(None);
    }
    let lease = format!(
        "legacy-{now}-{}-{}",
        std::process::id(),
        version.unwrap_or(0)
    );
    queue.legacy_lease = lease.clone();
    queue.legacy_until_ms = now.saturating_add(
        i64::try_from(timeout.as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(40000),
    );
    write(host, &queue, version).await?;
    Ok(Some(lease))
}
pub(crate) async fn release_legacy(host: &HostClient, lease: &str) -> Result<(), PluginFault> {
    let (mut queue, version) = read(host).await?;
    if queue.legacy_lease == lease {
        queue.legacy_lease.clear();
        queue.legacy_until_ms = 0;
        write(host, &queue, version).await?;
    }
    Ok(())
}

pub async fn enqueue(
    host: &HostClient,
    config: &Config,
    input: EnqueueRequest,
) -> Result<Value, PluginFault> {
    if !valid_id(&input.submission_id)
        || input.account_ids.is_empty()
        || input.account_ids.len() > HISTORY_LIMIT
        || input.account_ids.iter().collect::<BTreeSet<_>>().len() != input.account_ids.len()
        || !["fingerprint", "visual", "logic"].contains(&input.kind.as_str())
        || !(1..=4).contains(&input.repetitions)
        || (input.kind == "fingerprint" && input.repetitions != 1)
    {
        return Err(fault("invalid_job_request"));
    }
    let id = format!("batch-{:x}", Sha256::digest(input.submission_id.as_bytes()));
    let request_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&input).map_err(|_| fault("invalid_job_request"))?)
    );
    let (mut queue, version) = read(host).await?;
    if let Some(existing) = queue.batches.iter().find(|batch| batch.id == id) {
        if existing.request_hash != request_hash {
            return Err(fault("job_submission_conflict"));
        }
        return Ok(
            json!({"status":"queued","job_id":id,"batch":existing.public(),"replayed":true}),
        );
    }
    if !config.enabled {
        return Err(fault("disabled"));
    }
    // ponytail: one active batch matches the probe Key's concurrency=1; add a
    // parallel scheduler only when the underlying Key can safely run concurrently.
    if queue.batches.iter().any(Batch::active) || queue.legacy_until_ms > host::now() {
        return Err(fault("queue_active"));
    }
    if input
        .account_ids
        .iter()
        .any(|id| !config.account_ids.contains(id))
    {
        return Err(fault("account_not_managed"));
    }
    let model = input.model.clone().unwrap_or_else(|| config.model.clone());
    let effort = if input.kind == "fingerprint" {
        "low".into()
    } else {
        input
            .reasoning_effort
            .clone()
            .unwrap_or_else(|| "medium".into())
    };
    if (input.kind == "fingerprint" && model != config.model)
        || !engine::visual_models(config).contains(&model)
        || !["low", "medium", "high"].contains(&effort.as_str())
    {
        return Err(fault("invalid_job_model_or_effort"));
    }
    let accounts = host::accounts(host).await?;
    if input.account_ids.iter().any(|id| {
        !accounts.iter().any(|account| {
            account.account_id == *id
                && account.enabled
                && account.provider_id == crate::config::PROVIDER
        })
    }) {
        return Err(fault("account_not_available_in_probe_group"));
    }
    while queue
        .batches
        .iter()
        .map(|batch| batch.items.len())
        .sum::<usize>()
        + input.account_ids.len()
        > HISTORY_LIMIT
    {
        let removed = queue.batches.remove(0);
        queue
            .garbage
            .extend(removed.items.into_iter().map(|item| result_key(&item.id)));
    }
    let batch = Batch {
        id: id.clone(),
        request_hash,
        kind: input.kind.clone(),
        model,
        reasoning_effort: effort,
        repetitions: input.repetitions,
        created_at_ms: host::now(),
        config_tag: config.tag(),
        cancel_requested: false,
        items: input
            .account_ids
            .into_iter()
            .map(|account_id| Item {
                id: format!(
                    "task-{:x}",
                    Sha256::digest(format!("{id}:{account_id}").as_bytes())
                ),
                account_id,
                status: "queued".into(),
                completed: 0,
                total: if input.kind == "fingerprint" {
                    3
                } else {
                    usize::from(input.repetitions)
                },
                error: None,
                started_at_ms: None,
                completed_at_ms: None,
                attempts: 0,
                attempt_id: String::new(),
                incarnation: String::new(),
                lease_until_ms: 0,
            })
            .collect(),
    };
    let reply = json!({"status":"queued","job_id":id,"batch":batch.public(),"replayed":false});
    queue.batches.push(batch);
    write(host, &queue, version).await?;
    Ok(reply)
}
pub async fn list(host: &HostClient) -> Result<Value, PluginFault> {
    let queue = read(host).await?.0;
    Ok(
        json!({"batches":queue.batches.iter().rev().map(Batch::public).collect::<Vec<_>>(),"history_limit":HISTORY_LIMIT}),
    )
}
pub async fn detail(host: &HostClient, input: IdRequest) -> Result<Value, PluginFault> {
    if !valid_id(&input.id) {
        return Err(fault("invalid_job_id"));
    }
    let queue = read(host).await?.0;
    let (batch, item) = queue
        .batches
        .iter()
        .find_map(|batch| {
            batch
                .items
                .iter()
                .find(|item| item.id == input.id)
                .map(|item| (batch, item))
        })
        .ok_or_else(|| fault("job_not_found"))?;
    let results = host::get_in::<Results>(host, NAMESPACE, &result_key(&item.id))
        .await?
        .map(|record| record.0)
        .unwrap_or_default();
    Ok(
        json!({"item":item,"kind":batch.kind,"model":batch.model,"reasoning_effort":batch.reasoning_effort,"results":results.results}),
    )
}
pub async fn cancel(host: &HostClient, input: IdRequest) -> Result<Value, PluginFault> {
    if !valid_id(&input.id) {
        return Err(fault("invalid_job_id"));
    }
    let (mut queue, version) = read(host).await?;
    let batch = queue
        .batches
        .iter_mut()
        .find(|batch| batch.id == input.id)
        .ok_or_else(|| fault("job_not_found"))?;
    if batch.active() {
        batch.cancel_requested = true;
    }
    for item in &mut batch.items {
        if item.status == "queued" {
            item.finish("cancelled", Some("job_cancelled"));
        }
    }
    let result = json!({"status":"cancelled","batch":batch.public()});
    write(host, &queue, version).await?;
    Ok(result)
}

async fn collect_garbage(host: &HostClient) -> Result<(), PluginFault> {
    let (mut queue, version) = read(host).await?;
    if queue.garbage.is_empty() {
        return Ok(());
    }
    for key in &queue.garbage {
        if let Some((_, record_version)) = host::get_in::<Value>(host, NAMESPACE, key).await? {
            host::delete_in(host, NAMESPACE, key, record_version).await?;
        }
    }
    queue.garbage.clear();
    write(host, &queue, version).await
}

fn extract_result(kind: &str, reply: &Value) -> Result<Value, PluginFault> {
    if kind == "fingerprint" {
        return Ok(reply.clone());
    }
    reply
        .get(format!("{kind}_sample"))
        .cloned()
        .ok_or_else(|| fault("job_result_invalid"))
}
async fn save_result(
    host: &HostClient,
    kind: &str,
    item: &Item,
    reply: &Value,
) -> Result<Results, PluginFault> {
    let key = result_key(&item.id);
    let old = host::get_in::<Results>(host, NAMESPACE, &key).await?;
    let version = old.as_ref().map(|record| record.1);
    let mut result = old.map(|record| record.0).unwrap_or_default();
    if !result.attempt_ids.contains(&item.attempt_id) {
        let current = if kind == "visual" {
            engine::completed_job_attempt(host, &item.account_id, kind, &item.attempt_id).await?
        } else {
            None
        };
        let value = extract_result(kind, current.as_ref().unwrap_or(reply))?;
        if kind == "fingerprint" {
            result.results = vec![value];
        } else {
            result.results.push(value);
        }
        result.attempt_ids.push(item.attempt_id.clone());
        if serde_json::to_vec(&result)
            .map_err(|_| fault("job_result_invalid"))?
            .len()
            > MAX_RESULT_BYTES
        {
            return Err(fault("job_result_too_large"));
        }
        host::put_in(host, NAMESPACE, &key, &result, version).await?;
    }
    Ok(result)
}
fn update_item(item: &mut Item, kind: &str, results: &Results, cancel_requested: bool) {
    item.error = None;
    item.lease_until_ms = 0;
    if kind == "fingerprint" {
        let reply = results.results.last().unwrap_or(&Value::Null);
        let batch = &reply["batch"];
        item.completed = batch["attempts"].as_array().map_or(0, |attempts| {
            attempts
                .iter()
                .filter(|attempt| attempt["error"].is_null() && attempt["number_count"].is_number())
                .count()
        });
        if !batch["completed_at_ms"].is_null() {
            item.finish(
                if batch["verdict"] == "unknown" {
                    "unknown"
                } else {
                    "completed"
                },
                batch["error"].as_str(),
            );
            return;
        }
    } else {
        item.completed = results.results.len();
        if item.completed >= item.total {
            let last_error = results
                .results
                .iter()
                .find_map(|sample| sample["error"].as_str());
            item.finish(
                if last_error.is_some() {
                    "error"
                } else {
                    "completed"
                },
                last_error,
            );
            return;
        }
    }
    if cancel_requested {
        item.finish("cancelled", Some("job_cancelled"));
    } else {
        item.status = "queued".into();
    }
}
async fn complete_attempt(
    host: &HostClient,
    task_id: &str,
    attempt_id: &str,
    results: &Results,
) -> Result<(), PluginFault> {
    let (mut queue, version) = read(host).await?;
    let batch = queue
        .batches
        .iter_mut()
        .find(|batch| batch.items.iter().any(|item| item.id == task_id))
        .ok_or_else(|| fault("job_not_found"))?;
    let item = batch
        .items
        .iter_mut()
        .find(|item| item.id == task_id)
        .ok_or_else(|| fault("job_not_found"))?;
    if item.status != "running" || item.attempt_id != attempt_id {
        return Err(fault("job_attempt_replaced"));
    }
    update_item(item, &batch.kind, results, batch.cancel_requested);
    write(host, &queue, version).await
}
async fn fail_attempt(
    host: &HostClient,
    task_id: &str,
    attempt_id: &str,
    status: &str,
    error: &str,
    stop_batch: bool,
) -> Result<(), PluginFault> {
    let (mut queue, version) = read(host).await?;
    let batch = queue
        .batches
        .iter_mut()
        .find(|batch| batch.items.iter().any(|item| item.id == task_id))
        .ok_or_else(|| fault("job_not_found"))?;
    for item in &mut batch.items {
        if item.id == task_id && item.status == "running" && item.attempt_id == attempt_id {
            item.finish(status, Some(error));
        } else if stop_batch && item.status == "queued" {
            item.finish("skipped", Some(error));
        }
    }
    write(host, &queue, version).await
}

pub async fn run_one(
    host: &HostClient,
    config: &Config,
    incarnation: &str,
    timeout: Duration,
) -> Result<bool, PluginFault> {
    collect_garbage(host).await?;
    let (mut queue, version) = read(host).await?;
    let Some(batch_index) = queue.batches.iter().position(Batch::active) else {
        return Ok(false);
    };
    let now = host::now();
    let batch = &mut queue.batches[batch_index];
    if let Some(item) = batch
        .items
        .iter()
        .find(|item| item.status == "running")
        .cloned()
    {
        let stored = host::get_in::<Results>(host, NAMESPACE, &result_key(&item.id))
            .await?
            .map(|record| record.0)
            .filter(|result| result.attempt_ids.contains(&item.attempt_id));
        if let Some(result) = stored {
            complete_attempt(host, &item.id, &item.attempt_id, &result).await?;
            return Ok(true);
        }
        if item.incarnation == incarnation && item.lease_until_ms > now {
            return Ok(true);
        }
        // No automatic replay across a lost parent call: a charged request is not transactional.
        let restored = if let Some(reply) =
            engine::completed_job_attempt(host, &item.account_id, &batch.kind, &item.attempt_id)
                .await?
        {
            Some(save_result(host, &batch.kind, &item, &reply).await?)
        } else {
            None
        };
        if let Some(result) = restored {
            complete_attempt(host, &item.id, &item.attempt_id, &result).await?;
        } else {
            engine::interrupt_job_attempt(
                host,
                config,
                &item.account_id,
                &batch.kind,
                &item.attempt_id,
            )
            .await?;
            fail_attempt(
                host,
                &item.id,
                &item.attempt_id,
                "unknown",
                "job_interrupted_not_replayed",
                false,
            )
            .await?;
        }
        return Ok(true);
    }
    if !config.enabled || batch.config_tag != config.tag() {
        let error = if config.enabled {
            "job_configuration_changed"
        } else {
            "disabled"
        };
        for item in &mut batch.items {
            if item.status == "queued" {
                item.finish("cancelled", Some(error));
            }
        }
        write(host, &queue, version).await?;
        return Ok(true);
    }
    let Some(item_index) = batch.items.iter().position(|item| item.status == "queued") else {
        return Ok(true);
    };
    let item = &mut batch.items[item_index];
    if !config.account_ids.contains(&item.account_id) {
        item.finish("cancelled", Some("account_not_managed"));
        write(host, &queue, version).await?;
        return Ok(true);
    }
    // The native maintenance cadence is 30s; this also fences concurrent/early callbacks.
    if now < queue.last_started_at_ms.saturating_add(10000) {
        return Ok(true);
    }
    if timeout < Duration::from_secs(1) {
        return Err(fault("insufficient_probe_deadline"));
    }
    item.status = "running".into();
    item.started_at_ms.get_or_insert(now);
    item.attempts += 1;
    item.attempt_id = format!("{}-{}", item.id, item.attempts);
    item.incarnation = incarnation.into();
    item.lease_until_ms = now.saturating_add(
        i64::try_from(timeout.as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(40000),
    );
    let item = item.clone();
    let kind = batch.kind.clone();
    let model = batch.model.clone();
    let effort = batch.reasoning_effort.clone();
    queue.last_started_at_ms = now;
    write(host, &queue, version).await?;
    let result = if kind == "fingerprint" {
        engine::tick_for_job(
            host,
            config,
            Some(&item.account_id),
            timeout,
            Some(&item.attempt_id),
        )
        .await
    } else {
        engine::manual_test_for_job(
            host,
            config,
            engine::ManualRequest {
                account_id: item.account_id.clone(),
                model,
                reasoning_effort: effort,
            },
            if kind == "visual" {
                engine::ManualCase::Visual
            } else {
                engine::ManualCase::Logic
            },
            timeout,
            Some(&item.attempt_id),
        )
        .await
    };
    match result {
        Ok(reply)
            if [
                "visual_recorded",
                "logic_recorded",
                "batch_completed",
                "challenge_recorded",
            ]
            .contains(&reply["status"].as_str().unwrap_or("")) =>
        {
            let results = save_result(host, &kind, &item, &reply).await?;
            complete_attempt(host, &item.id, &item.attempt_id, &results).await?;
        }
        Ok(reply) => {
            let status = reply["status"].as_str().unwrap_or("job_result_invalid");
            fail_attempt(
                host,
                &item.id,
                &item.attempt_id,
                "skipped",
                status,
                status == "daily_budget_exhausted" || status == "disabled",
            )
            .await?;
        }
        Err(error) => {
            if let Some(reply) =
                engine::completed_job_attempt(host, &item.account_id, &kind, &item.attempt_id)
                    .await?
            {
                let results = save_result(host, &kind, &item, &reply).await?;
                complete_attempt(host, &item.id, &item.attempt_id, &results).await?;
            } else {
                fail_attempt(
                    host,
                    &item.id,
                    &item.attempt_id,
                    "error",
                    &error.message,
                    false,
                )
                .await?;
            }
        }
    }
    Ok(true)
}

pub(crate) async fn visual_review(
    host: &HostClient,
    account: &str,
    sample_id: &str,
    verdict: &str,
) -> Result<Option<Value>, PluginFault> {
    let queue = read(host).await?.0;
    for item in queue
        .batches
        .iter()
        .rev()
        .filter(|batch| batch.kind == "visual")
        .flat_map(|batch| batch.items.iter())
        .filter(|item| item.account_id == account)
    {
        let key = result_key(&item.id);
        let Some((mut results, version)) = host::get_in::<Results>(host, NAMESPACE, &key).await?
        else {
            continue;
        };
        let Some(sample) = results
            .results
            .iter_mut()
            .find(|sample| sample["id"] == sample_id)
        else {
            continue;
        };
        if sample["status"] != "completed" || !sample["output"].is_string() {
            return Err(fault("visual_sample_not_completed"));
        }
        sample["assessment"] = json!({"verdict":verdict,"source":"manual"});
        let sample = sample.clone();
        host::put_in(host, NAMESPACE, &key, &results, Some(version)).await?;
        return Ok(Some(sample));
    }
    Ok(None)
}
