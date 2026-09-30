use crate::{Config, config::PROVIDER, host, scorer};
use gateway_plugin_sdk::{
    PluginFault,
    call::{
        data::{AccountFacts, AccountFactsQuery},
        middleware::{MiddlewareHeader, http::Version},
    },
    client::{HostClient, HttpBody, HttpFrame, HttpRequest},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Instance {
    id: String,
    name: String,
    artifact_sha256: String,
    enabled: bool,
    configuration: Value,
    bindings: Value,
    revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveSettings {
    expected_revision: u64,
    enabled: bool,
    auto_probe: bool,
    account_ids: Vec<String>,
    model: String,
    max_daily_attempts: u32,
    max_output_tokens: u32,
}

async fn admin(host: &HostClient, path: &str, body: Option<Value>) -> Result<Value, PluginFault> {
    let saving = body.is_some();
    let mut response = host
        .dispatch_http(HttpRequest {
            settings: Value::Null,
            method: if saving { "POST" } else { "GET" }.into(),
            uri: path.into(),
            version: Version::Http11,
            headers: if saving {
                vec![MiddlewareHeader {
                    name: "content-type".into(),
                    value: b"application/json".to_vec(),
                }]
            } else {
                vec![]
            },
            timeout_ms: Some(30000),
            body: match body {
                Some(body) => HttpBody::from_bytes(
                    serde_json::to_vec(&body).map_err(|_| host::fault("settings_encode"))?,
                ),
                None => HttpBody::empty(),
            },
        })
        .await?;
    if response.status != 200 {
        let _ = response.body.close().await;
        return Err(host::fault(if response.status == 409 {
            "settings_conflict"
        } else if saving {
            "settings_save_failed"
        } else {
            "settings_read_failed"
        }));
    }
    let mut bytes = Vec::new();
    while let Some(frame) = response.body.read().await? {
        if let HttpFrame::Data(data) = frame {
            if bytes.len().saturating_add(data.len()) > 4 * 1024 * 1024 {
                let _ = response.body.close().await;
                return Err(host::fault("settings_response_invalid"));
            }
            bytes.extend(data);
        }
    }
    #[derive(Deserialize)]
    struct Envelope {
        code: u32,
        data: Value,
    }
    let envelope: Envelope =
        serde_json::from_slice(&bytes).map_err(|_| host::fault("settings_response_invalid"))?;
    if envelope.code != 200 {
        return Err(host::fault("settings_response_invalid"));
    }
    Ok(envelope.data)
}

async fn instance(host: &HostClient, instance_id: &str) -> Result<Instance, PluginFault> {
    let instances: Vec<Instance> =
        serde_json::from_value(admin(host, "/api/admin/plugins/instances", None).await?)
            .map_err(|_| host::fault("settings_response_invalid"))?;
    let mut own = instances.into_iter().filter(|item| item.id == instance_id);
    let instance = own
        .next()
        .ok_or_else(|| host::fault("settings_instance_missing"))?;
    if own.next().is_some() {
        return Err(host::fault("settings_response_invalid"));
    }
    Ok(instance)
}

async fn accounts(host: &HostClient) -> Result<Vec<AccountFacts>, PluginFault> {
    let mut all = Vec::new();
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    loop {
        let page = host
            .account_facts(AccountFactsQuery {
                provider_id: Some(PROVIDER.into()),
                cursor,
                limit: 200,
            })
            .await?;
        if page.schema_version != 1 {
            return Err(host::fault("account_schema_mismatch"));
        }
        all.extend(
            page.accounts
                .into_iter()
                .filter(|a| a.provider_id == PROVIDER),
        );
        if all.len() > 10000 {
            return Err(host::fault("too_many_accounts"));
        }
        match page.next_cursor {
            None => return Ok(all),
            Some(next) if seen.insert(next.clone()) => cursor = Some(next),
            _ => return Err(host::fault("account_pagination_invalid")),
        }
    }
}

fn config(value: Value) -> Result<Config, PluginFault> {
    let config: Config =
        serde_json::from_value(value).map_err(|_| host::fault("invalid_configuration"))?;
    config.validate().map_err(host::fault)?;
    Ok(config)
}

pub async fn read(host: &HostClient, instance_id: &str) -> Result<Value, PluginFault> {
    let instance = instance(host, instance_id).await?;
    let c = config(instance.configuration)?;
    Ok(json!({
        "revision": instance.revision,
        "config": {
            "enabled": c.enabled, "auto_probe": c.auto_probe, "account_ids": c.account_ids,
            "model": c.model, "max_daily_attempts": c.max_daily_attempts,
            "max_output_tokens": c.max_output_tokens
        },
        "accounts": accounts(host).await?.into_iter().map(|a| json!({
            "account_id": a.account_id, "name": a.name, "email": a.email, "enabled": a.enabled
        })).collect::<Vec<_>>(),
        "models": scorer::supported_models().into_iter().filter(|id| id.starts_with("gpt-")).collect::<Vec<_>>(),
        "fixed": {
            "confidence_threshold": c.confidence_threshold, "max_daily_output_tokens": c.max_daily_output_tokens,
            "probe_daily_usd": c.probe_daily_usd, "probe_weekly_usd": c.probe_weekly_usd,
            "max_quarantined_percent": c.max_quarantined_percent, "policy": c.policy,
            "business_key_ids": c.business_key_ids
        }
    }))
}

fn compact(c: &Config) -> Result<Value, PluginFault> {
    let mut value = serde_json::to_value(c).map_err(|_| host::fault("settings_encode"))?;
    let defaults = serde_json::to_value(Config::default()).expect("serializable config");
    let fields = value.as_object_mut().expect("config object");
    if let Some(policy) = fields.get_mut("policy").and_then(Value::as_object_mut) {
        policy.retain(|key, value| defaults["policy"].get(key) != Some(value));
        if policy.is_empty() {
            fields.remove("policy");
        }
    }
    fields.retain(|key, value| {
        [
            "enabled",
            "auto_probe",
            "account_ids",
            "model",
            "max_daily_attempts",
            "max_output_tokens",
        ]
        .contains(&key.as_str())
            || defaults.get(key) != Some(value)
    });
    Ok(value)
}

pub async fn save(
    host: &HostClient,
    instance_id: &str,
    input: SaveSettings,
) -> Result<Value, PluginFault> {
    let instance = instance(host, instance_id).await?;
    if instance.revision != input.expected_revision {
        return Err(host::fault("settings_conflict"));
    }
    let previous = config(instance.configuration)?;
    let mut next = previous.clone();
    next.enabled = input.enabled;
    next.auto_probe = input.auto_probe;
    next.account_ids = input.account_ids;
    next.model = input.model;
    next.max_daily_attempts = input.max_daily_attempts;
    next.max_output_tokens = input.max_output_tokens;
    if next.max_daily_attempts != previous.max_daily_attempts
        || next.max_output_tokens != previous.max_output_tokens
    {
        next.max_daily_output_tokens =
            u64::from(next.max_daily_attempts) * u64::from(next.max_output_tokens);
    }
    next.validate().map_err(host::fault)?;
    if !next.model.starts_with("gpt-") || !scorer::supports_model(&next.model) {
        return Err(host::fault("model_not_in_bank_or_no_accounts"));
    }
    let available = accounts(host).await?;
    if next.account_ids.iter().any(|id| {
        !available
            .iter()
            .any(|a| a.account_id == *id && (a.enabled || previous.account_ids.contains(id)))
    }) {
        return Err(host::fault("settings_account_invalid"));
    }
    #[derive(Deserialize)]
    struct LeasedAccount {
        quality: Lease,
    }
    #[derive(Deserialize)]
    struct Lease {
        lease_until_ms: i64,
    }
    for id in previous
        .account_ids
        .iter()
        .chain(&next.account_ids)
        .collect::<BTreeSet<_>>()
    {
        if let Some((state, _)) = host::get::<LeasedAccount>(host, &host::account_key(id)).await?
            && state.quality.lease_until_ms > host::now()
        {
            return Err(host::fault("settings_busy"));
        }
    }
    let response = admin(
        host,
        "/api/admin/plugins/instances/update",
        Some(json!({
            "id": instance.id,
            "instance": {
                "expectedRevision": input.expected_revision, "name": instance.name,
                "artifactSha256": instance.artifact_sha256, "enabled": instance.enabled,
                "configuration": compact(&next)?, "bindings": instance.bindings
            }
        })),
    )
    .await?;
    let revision = response["configRevision"]
        .as_u64()
        .ok_or_else(|| host::fault("settings_response_invalid"))?;
    if response["id"] != instance_id || revision <= input.expected_revision {
        return Err(host::fault("settings_response_invalid"));
    }
    Ok(json!({"status": "settings_saved", "revision": revision}))
}
