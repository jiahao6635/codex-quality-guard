use gateway_plugin_sdk::{
    ErrorCode, PluginFault,
    call::{
        data::{AccountFacts, AccountFactsQuery},
        host::{StateGetRequest, StateGetResult, StatePutRequest, StatePutResult},
    },
    client::HostClient,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub fn fault(message: &'static str) -> PluginFault {
    PluginFault::new(ErrorCode::Fault, message)
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}
pub fn account_key(id: &str) -> String {
    format!("account.{:x}", Sha256::digest(id.as_bytes()))
}
pub async fn get<T: DeserializeOwned>(
    host: &HostClient,
    key: &str,
) -> Result<Option<(T, u64)>, PluginFault> {
    let reply = host
        .call(
            "host.state.get",
            serde_json::to_value(StateGetRequest {
                namespace: "quality".into(),
                key: key.into(),
            })
            .map_err(|_| fault("state_encode"))?,
            Vec::new(),
        )
        .await
        .map_err(|_| fault("state_read_failed"))?;
    if !reply.payload.is_empty() {
        return Err(fault("state_reply_invalid"));
    }
    let result: StateGetResult =
        serde_json::from_value(reply.result).map_err(|_| fault("state_reply_invalid"))?;
    result
        .record
        .map(|r| {
            if r.schema_version != 1 {
                return Err(fault("state_schema_mismatch"));
            }
            Ok((
                serde_json::from_value(r.value).map_err(|_| fault("state_value_invalid"))?,
                r.version,
            ))
        })
        .transpose()
}
pub async fn put<T: Serialize>(
    host: &HostClient,
    key: &str,
    value: &T,
    version: Option<u64>,
) -> Result<u64, PluginFault> {
    let input = StatePutRequest {
        namespace: "quality".into(),
        key: key.into(),
        value: serde_json::to_value(value).map_err(|_| fault("state_encode"))?,
        expected_version: version,
    };
    let reply = host
        .call(
            "host.state.put",
            serde_json::to_value(input).map_err(|_| fault("state_encode"))?,
            Vec::new(),
        )
        .await
        .map_err(|_| fault("state_write_failed_or_conflict"))?;
    if !reply.payload.is_empty() {
        return Err(fault("state_reply_invalid"));
    }
    let result: StatePutResult =
        serde_json::from_value(reply.result).map_err(|_| fault("state_reply_invalid"))?;
    Ok(result.version)
}
pub async fn accounts(host: &HostClient) -> Result<Vec<AccountFacts>, PluginFault> {
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    let mut all = Vec::new();
    loop {
        let page = host
            .account_facts(AccountFactsQuery {
                provider_id: None,
                cursor,
                limit: 200,
            })
            .await?;
        if page.schema_version != 1 {
            return Err(fault("account_schema_mismatch"));
        }
        all.extend(page.accounts);
        if all.len() > 10000 {
            return Err(fault("too_many_accounts"));
        }
        match page.next_cursor {
            None => return Ok(all),
            Some(c) if seen.insert(c.clone()) => cursor = Some(c),
            _ => return Err(fault("account_pagination_invalid")),
        }
    }
}

pub async fn delete(host: &HostClient, key: &str, version: u64) -> Result<(), PluginFault> {
    let reply = host
        .call(
            "host.state.delete",
            serde_json::to_value(gateway_plugin_sdk::call::host::StateDeleteRequest {
                namespace: "quality".into(),
                key: key.into(),
                expected_version: version,
            })
            .map_err(|_| fault("state_encode"))?,
            Vec::new(),
        )
        .await
        .map_err(|_| fault("state_delete_failed_or_conflict"))?;
    let _: gateway_plugin_sdk::call::host::StateDeleteResult =
        serde_json::from_value(reply.result).map_err(|_| fault("state_reply_invalid"))?;
    Ok(())
}
