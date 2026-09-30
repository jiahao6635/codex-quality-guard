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
            None => break,
            Some(c) if seen.insert(c.clone()) => cursor = Some(c),
            _ => return Err(fault("account_pagination_invalid")),
        }
    }
    let mut groups = account_groups(host).await?;
    for account in &mut all {
        account.group_ids = groups
            .remove(&account.account_id)
            .ok_or_else(|| fault("account_membership_changed_retry"))?;
    }
    Ok(all)
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

// CPR 3.18 的基础事实未填充分组；复用公开账号列表，拒绝把缺失数据当作空成员。
async fn account_groups(
    host: &HostClient,
) -> Result<std::collections::BTreeMap<String, Vec<String>>, PluginFault> {
    use gateway_plugin_sdk::{
        call::middleware::http::Version,
        client::{HttpBody, HttpFrame, HttpRequest},
    };
    #[derive(serde::Deserialize)]
    struct Envelope {
        code: u32,
        data: Page,
    }
    #[derive(serde::Deserialize)]
    struct Page {
        items: Vec<Account>,
        page: Paging,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Paging {
        page: u32,
        total_pages: u32,
    }
    #[derive(serde::Deserialize)]
    struct Account {
        id: String,
        groups: Vec<Group>,
    }
    #[derive(serde::Deserialize)]
    struct Group {
        id: String,
    }
    let mut groups = std::collections::BTreeMap::new();
    for page in 1..=1000 {
        let mut response = host
            .dispatch_http(HttpRequest {
                settings: serde_json::Value::Null,
                method: "GET".into(),
                uri: format!("/api/admin/accounts?page={page}&pageSize=100"),
                version: Version::Http11,
                headers: vec![],
                timeout_ms: Some(5000),
                body: HttpBody::empty(),
            })
            .await?;
        if response.status != 200 {
            let _ = response.body.close().await;
            return Err(fault("account_membership_read_failed"));
        }
        let mut bytes = Vec::new();
        while let Some(frame) = response.body.read().await? {
            if let HttpFrame::Data(data) = frame {
                if bytes.len().saturating_add(data.len()) > 4 * 1024 * 1024 {
                    let _ = response.body.close().await;
                    return Err(fault("account_membership_response_too_large"));
                }
                bytes.extend(data);
            }
        }
        let result: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| fault("account_membership_invalid"))?;
        if result.code != 200 || result.data.page.page != page {
            return Err(fault("account_membership_invalid"));
        }
        for account in result.data.items {
            if groups
                .insert(
                    account.id,
                    account.groups.into_iter().map(|g| g.id).collect(),
                )
                .is_some()
            {
                return Err(fault("account_membership_changed_retry"));
            }
        }
        if page >= result.data.page.total_pages {
            return Ok(groups);
        }
    }
    Err(fault("account_membership_page_limit"))
}
