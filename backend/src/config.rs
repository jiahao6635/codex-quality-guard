use crate::{scorer, state::Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub account_ids: Vec<String>,
    pub model: String,
    pub provider: String,
    pub business_key_ids: Vec<String>,
    pub confidence_threshold: f64,
    pub max_daily_attempts: u32,
    pub max_output_tokens: u32,
    pub max_daily_output_tokens: u64,
    pub probe_daily_usd: String,
    pub probe_weekly_usd: String,
    pub max_quarantined_percent: u8,
    pub policy: Policy,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            account_ids: Vec::new(),
            model: "gpt-6-astra".into(),
            provider: "openai".into(),
            business_key_ids: Vec::new(),
            confidence_threshold: 0.99,
            max_daily_attempts: 100,
            max_output_tokens: 4096,
            max_daily_output_tokens: 409600,
            probe_daily_usd: "5".into(),
            probe_weekly_usd: "25".into(),
            max_quarantined_percent: 50,
            policy: Policy::default(),
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.account_ids.len() > 100
            || self.business_key_ids.len() > 20
            || self
                .account_ids
                .iter()
                .chain(&self.business_key_ids)
                .any(|s| {
                    s.is_empty()
                        || s.len() > 128
                        || !s
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                })
            || self.account_ids.iter().collect::<BTreeSet<_>>().len() != self.account_ids.len()
            || self.model.is_empty()
            || self.model.len() > 128
            || self.provider != "openai"
            || !(0.9..=1.0).contains(&self.confidence_threshold)
            || !(1..=10000).contains(&self.max_daily_attempts)
            || !(2048..=16384).contains(&self.max_output_tokens)
            || self.max_daily_output_tokens < u64::from(self.max_output_tokens)
            || !(1..=100).contains(&self.max_quarantined_percent)
        {
            return Err("invalid_configuration");
        }
        for budget in [&self.probe_daily_usd, &self.probe_weekly_usd] {
            let n = budget.parse::<f64>().map_err(|_| "invalid_budget")?;
            if !n.is_finite()
                || n <= 0.0
                || n > 10000.0
                || !budget.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            {
                return Err("invalid_budget");
            }
        }
        let p = &self.policy;
        if !(3..=10).contains(&p.samples_per_round)
            || !(2..=10).contains(&p.anomaly_rounds)
            || !(2..=10).contains(&p.recovery_rounds)
            || p.anomaly_spacing_ms < 300000
            || p.recovery_spacing_ms < 600000
            || p.healthy_interval_ms < 60000
            || p.unknown_retry_ms < 60000
            || p.cooldown_initial_ms < 60000
            || p.cooldown_max_ms < p.cooldown_initial_ms
            || p.cooldown_max_ms > 86400000
            || [
                p.anomaly_spacing_ms,
                p.recovery_spacing_ms,
                p.healthy_interval_ms,
                p.unknown_retry_ms,
            ]
            .iter()
            .any(|v| *v > 86400000)
        {
            return Err("invalid_policy");
        }
        if self.enabled && (self.account_ids.is_empty() || !scorer::supports_model(&self.model)) {
            return Err("model_not_in_bank_or_no_accounts");
        }
        Ok(())
    }
    pub fn tag(&self) -> String {
        // 检测协议或阈值变化后重新准入；预算和纳管列表变化不抹去既有证据。
        let bytes = serde_json::to_vec(&(
            scorer::VERSION,
            &self.model,
            &self.provider,
            self.confidence_threshold,
            &self.policy,
        ))
        .expect("serializable config");
        format!("{:x}", Sha256::digest(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_unbounded_budget_and_unknown_enabled_model() {
        assert!(Config::default().validate().is_ok());
        let config = Config {
            enabled: true,
            account_ids: vec!["acct_test".into()],
            ..Config::default()
        };
        assert!(config.validate().is_ok());
        for budget in ["0", "NaN", "inf", "-1", "10001"] {
            let mut bad = config.clone();
            bad.probe_daily_usd = budget.into();
            assert!(bad.validate().is_err());
        }
        let mut unknown = config.clone();
        unknown.model = "unregistered-model".into();
        assert!(unknown.validate().is_err());
        assert!(serde_json::from_str::<Config>(r#"{"policy":{"unknown":1}}"#).is_err());
    }
}
