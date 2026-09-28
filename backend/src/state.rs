//! 只保留有界探测证据并判定资格；租约和持久化由宿主适配层管理。

use serde::{Deserialize, Serialize};

const MINUTE_MS: i64 = 60_000;
const MAX_CANDIDATE_BYTES: usize = 128;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Healthy,
    Anomaly,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Pending,
    Healthy,
    Suspect,
    Cooling,
    Recovering,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub samples_per_round: usize,
    pub anomaly_rounds: u32,
    pub recovery_rounds: u32,
    pub anomaly_spacing_ms: i64,
    pub recovery_spacing_ms: i64,
    pub healthy_interval_ms: i64,
    pub unknown_retry_ms: i64,
    pub cooldown_initial_ms: i64,
    pub cooldown_max_ms: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            samples_per_round: 3,
            anomaly_rounds: 2,
            recovery_rounds: 2,
            anomaly_spacing_ms: 5 * MINUTE_MS,
            recovery_spacing_ms: 10 * MINUTE_MS,
            healthy_interval_ms: 30 * MINUTE_MS,
            unknown_retry_ms: 5 * MINUTE_MS,
            cooldown_initial_ms: 60 * MINUTE_MS,
            cooldown_max_ms: 6 * 60 * MINUTE_MS,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    pub phase: Phase,
    pub next_probe_at_ms: i64,
    pub lease_until_ms: i64,
    pub lease_id: String,
    pub config_tag: String,
    pub last_error: Option<String>,
    pub last_request_id: Option<String>,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub ever_healthy: bool,
    #[serde(default)]
    pub last_verdict: Option<Verdict>,
    #[serde(default)]
    pub last_candidate: String,
    #[serde(default)]
    pub sample_counter: u64,
    #[serde(default)]
    round_verdict: Option<Verdict>,
    #[serde(default)]
    round_samples: usize,
    #[serde(default)]
    anomaly_round_count: u32,
    #[serde(default)]
    anomaly_candidate: String,
    #[serde(default)]
    last_anomaly_round_at_ms: Option<i64>,
    #[serde(default)]
    recovery_round_count: u32,
    #[serde(default)]
    last_recovery_round_at_ms: Option<i64>,
    #[serde(default)]
    cooldown_ms: i64,
}

impl Record {
    pub fn new(config_tag: String, now: i64) -> Self {
        Self {
            phase: Phase::Pending,
            next_probe_at_ms: now,
            lease_until_ms: 0,
            lease_id: String::new(),
            config_tag,
            last_error: None,
            last_request_id: None,
            updated_at_ms: now,
            ever_healthy: false,
            last_verdict: None,
            last_candidate: String::new(),
            sample_counter: 0,
            round_verdict: None,
            round_samples: 0,
            anomaly_round_count: 0,
            anomaly_candidate: String::new(),
            last_anomaly_round_at_ms: None,
            recovery_round_count: 0,
            last_recovery_round_at_ms: None,
            cooldown_ms: 0,
        }
    }

    /// 新配置重新收集证据，保留租约、题号和已进入的冷却档位。
    pub fn reset_for_config(&self, tag: String, now: i64) -> Self {
        let mut next = Self::new(tag, now);
        next.ever_healthy = self.ever_healthy;
        next.lease_id = self.lease_id.clone();
        next.lease_until_ms = self.lease_until_ms;
        next.sample_counter = self.sample_counter;
        next.cooldown_ms = self.cooldown_ms;
        if matches!(self.phase, Phase::Cooling | Phase::Recovering) {
            next.phase = Phase::Cooling;
            next.next_probe_at_ms = self.next_probe_at_ms.max(now);
        }
        next
    }

    pub fn eligible(&self) -> bool {
        matches!(self.phase, Phase::Healthy | Phase::Suspect)
    }

    /// 接收一次新探针响应。尚未到期或时钟回拨时只递增题号，不累计证据。
    pub fn observe(&mut self, verdict: Verdict, candidate: &str, now: i64, policy: &Policy) {
        self.sample_counter = self.sample_counter.saturating_add(1);
        if now < self.updated_at_ms || now < self.next_probe_at_ms {
            return;
        }
        self.updated_at_ms = now;
        let candidate = candidate.trim();
        let verdict = if candidate.len() > MAX_CANDIDATE_BYTES
            || (verdict == Verdict::Anomaly && candidate.is_empty())
        {
            Verdict::Unknown
        } else {
            verdict
        };
        self.last_verdict = Some(verdict);
        self.last_candidate = if candidate.len() <= MAX_CANDIDATE_BYTES {
            candidate.to_owned()
        } else {
            String::new()
        };

        // 冷却到期只允许复测，不放行业务流量。
        if self.phase == Phase::Cooling {
            self.phase = Phase::Recovering;
        }
        if verdict == Verdict::Unknown {
            self.clear_round();
            self.clear_streaks();
            if self.phase == Phase::Recovering {
                self.cool(now, policy, true);
            } else {
                if self.phase == Phase::Suspect {
                    self.phase = Phase::Healthy;
                }
                self.next_probe_at_ms = after(now, policy.unknown_retry_ms);
            }
            return;
        }

        // 恢复轮出现一个异常样本，就已经不满足整轮正常的要求。
        if self.phase == Phase::Recovering && verdict == Verdict::Anomaly {
            self.cool(now, policy, true);
            return;
        }

        if verdict == Verdict::Healthy {
            self.clear_anomalies();
        } else {
            if self.anomaly_candidate != candidate {
                self.clear_round();
                self.clear_anomalies();
                self.anomaly_candidate = candidate.to_owned();
            }
            if self.phase == Phase::Healthy {
                self.phase = Phase::Suspect;
            }
        }

        let same_round = self.round_verdict == Some(verdict);
        if !same_round {
            self.clear_round();
            self.round_verdict = Some(verdict);
        }
        self.round_samples = self.round_samples.saturating_add(1);
        self.next_probe_at_ms = now;
        if self.round_samples < policy.samples_per_round.max(1) {
            return;
        }
        self.clear_round();

        match verdict {
            Verdict::Healthy if self.phase == Phase::Recovering => {
                if let Some(previous) = self.last_recovery_round_at_ms {
                    let due = after(previous, policy.recovery_spacing_ms);
                    if now.saturating_sub(previous) < policy.recovery_spacing_ms.max(0) {
                        self.next_probe_at_ms = due;
                        return;
                    }
                }
                self.recovery_round_count = self.recovery_round_count.saturating_add(1);
                self.last_recovery_round_at_ms = Some(now);
                if self.recovery_round_count >= policy.recovery_rounds.max(1) {
                    self.admit(now, policy);
                } else {
                    self.next_probe_at_ms = after(now, policy.recovery_spacing_ms);
                }
            }
            Verdict::Healthy => self.admit(now, policy),
            Verdict::Anomaly => {
                if let Some(previous) = self.last_anomaly_round_at_ms {
                    let due = after(previous, policy.anomaly_spacing_ms);
                    if now.saturating_sub(previous) < policy.anomaly_spacing_ms.max(0) {
                        self.next_probe_at_ms = due;
                        return;
                    }
                }
                self.anomaly_round_count = self.anomaly_round_count.saturating_add(1);
                self.last_anomaly_round_at_ms = Some(now);
                if self.anomaly_round_count >= policy.anomaly_rounds.max(1) {
                    self.cool(now, policy, false);
                } else {
                    self.next_probe_at_ms = after(now, policy.anomaly_spacing_ms);
                }
            }
            Verdict::Unknown => unreachable!("unknown verdicts do not form rounds"),
        }
    }

    fn admit(&mut self, now: i64, policy: &Policy) {
        self.phase = Phase::Healthy;
        self.ever_healthy = true;
        self.cooldown_ms = 0;
        self.clear_streaks();
        self.next_probe_at_ms = after(now, policy.healthy_interval_ms);
    }

    fn cool(&mut self, now: i64, policy: &Policy, backoff: bool) {
        let initial = policy.cooldown_initial_ms.max(0);
        let maximum = policy.cooldown_max_ms.max(0);
        self.cooldown_ms = if backoff {
            self.cooldown_ms.max(initial).saturating_mul(2)
        } else {
            initial
        }
        .min(maximum);
        self.phase = Phase::Cooling;
        self.clear_round();
        self.clear_streaks();
        self.next_probe_at_ms = after(now, self.cooldown_ms);
    }

    fn clear_round(&mut self) {
        self.round_verdict = None;
        self.round_samples = 0;
    }

    fn clear_anomalies(&mut self) {
        self.anomaly_round_count = 0;
        self.anomaly_candidate.clear();
        self.last_anomaly_round_at_ms = None;
    }

    fn clear_streaks(&mut self) {
        self.clear_anomalies();
        self.recovery_round_count = 0;
        self.last_recovery_round_at_ms = None;
    }
}

fn after(now: i64, delay: i64) -> i64 {
    now.saturating_add(delay.max(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(record: &mut Record, verdict: Verdict, candidate: &str, now: i64, policy: &Policy) {
        for _ in 0..policy.samples_per_round {
            record.observe(verdict, candidate, now, policy);
        }
    }

    fn admitted(policy: &Policy) -> Record {
        let mut record = Record::new("v1".to_owned(), 0);
        round(&mut record, Verdict::Healthy, "astra", 0, policy);
        record
    }

    fn cooled(policy: &Policy) -> Record {
        let mut record = admitted(policy);
        let first = record.next_probe_at_ms;
        round(&mut record, Verdict::Anomaly, "luna", first, policy);
        let second = record.next_probe_at_ms;
        round(&mut record, Verdict::Anomaly, "luna", second, policy);
        assert_eq!(record.phase, Phase::Cooling);
        record
    }

    #[test]
    fn admission_requires_a_complete_clean_round() {
        let policy = Policy::default();
        let mut record = Record::new("v1".to_owned(), 0);
        for _ in 0..2 {
            record.observe(Verdict::Healthy, "astra", 0, &policy);
            assert!(!record.eligible());
        }
        record.observe(Verdict::Healthy, "astra", 0, &policy);
        assert!(record.eligible());
        assert!(record.ever_healthy);
        assert_eq!(record.next_probe_at_ms, policy.healthy_interval_ms);
    }

    #[test]
    fn mixed_samples_and_changed_candidates_cannot_be_combined() {
        let policy = Policy::default();
        let mut record = admitted(&policy);
        let now = record.next_probe_at_ms;
        record.observe(Verdict::Anomaly, "luna", now, &policy);
        record.observe(Verdict::Anomaly, "luna", now, &policy);
        let mut legacy = serde_json::to_value(&record).unwrap();
        legacy["round_candidate"] = serde_json::json!("luna");
        record = serde_json::from_value(legacy).unwrap();
        record.observe(Verdict::Healthy, "astra", now, &policy);
        record.observe(Verdict::Anomaly, "luna", now, &policy);
        record.observe(Verdict::Anomaly, "other", now, &policy);
        record.observe(Verdict::Anomaly, "other", now, &policy);
        assert_eq!(record.anomaly_round_count, 0);
        record.observe(Verdict::Anomaly, "other", now, &policy);
        assert_eq!(record.anomaly_round_count, 1);
        let later = record.next_probe_at_ms;
        round(&mut record, Verdict::Anomaly, "luna", later, &policy);
        assert_eq!(record.anomaly_round_count, 1);
        assert!(record.eligible());
    }

    #[test]
    fn two_independent_anomaly_rounds_are_needed_for_cooling() {
        let policy = Policy::default();
        let mut record = admitted(&policy);
        let now = record.next_probe_at_ms;
        round(&mut record, Verdict::Anomaly, "luna", now, &policy);
        assert_eq!(record.phase, Phase::Suspect);
        assert!(record.eligible());
        round(&mut record, Verdict::Anomaly, "luna", now + 1, &policy);
        assert_eq!(record.anomaly_round_count, 1);
        let later = record.next_probe_at_ms;
        round(&mut record, Verdict::Anomaly, "luna", later, &policy);
        assert_eq!(record.phase, Phase::Cooling);
        assert!(!record.eligible());
        assert_eq!(record.next_probe_at_ms, later + policy.cooldown_initial_ms);
    }

    #[test]
    fn unknown_clears_partial_samples_and_consecutive_anomaly_rounds() {
        let policy = Policy::default();
        let mut record = admitted(&policy);
        let now = record.next_probe_at_ms;
        round(&mut record, Verdict::Anomaly, "luna", now, &policy);
        let now = record.next_probe_at_ms;
        record.observe(Verdict::Anomaly, "luna", now, &policy);
        record.observe(Verdict::Unknown, "", now, &policy);
        assert!(record.eligible());
        assert_eq!(record.anomaly_round_count, 0);
        assert_eq!(record.round_samples, 0);
        let now = record.next_probe_at_ms;
        round(&mut record, Verdict::Anomaly, "luna", now, &policy);
        assert!(record.eligible());
        assert_eq!(record.anomaly_round_count, 1);
    }

    #[test]
    fn expiry_only_starts_two_spaced_recovery_rounds() {
        let policy = Policy::default();
        let mut record = cooled(&policy);
        let due = record.next_probe_at_ms;
        round(&mut record, Verdict::Healthy, "astra", due - 1, &policy);
        assert_eq!(record.phase, Phase::Cooling);
        assert!(!record.eligible());
        round(&mut record, Verdict::Healthy, "astra", due, &policy);
        assert_eq!(record.phase, Phase::Recovering);
        assert!(!record.eligible());
        round(&mut record, Verdict::Healthy, "astra", due + 1, &policy);
        assert_eq!(record.recovery_round_count, 1);
        let later = record.next_probe_at_ms;
        round(&mut record, Verdict::Healthy, "astra", later, &policy);
        assert_eq!(record.phase, Phase::Healthy);
        assert!(record.eligible());
        assert!(record.ever_healthy);
    }

    #[test]
    fn failed_recovery_resets_evidence_and_backs_off_until_capped() {
        let policy = Policy::default();
        let mut record = cooled(&policy);
        let due = record.next_probe_at_ms;
        round(&mut record, Verdict::Healthy, "astra", due, &policy);
        let due = record.next_probe_at_ms;
        record.observe(Verdict::Unknown, "", due, &policy);
        assert_eq!(record.recovery_round_count, 0);
        assert_eq!(record.next_probe_at_ms, due + 120 * MINUTE_MS);
        for (verdict, expected) in [
            (Verdict::Anomaly, 240 * MINUTE_MS),
            (Verdict::Unknown, 360 * MINUTE_MS),
            (Verdict::Anomaly, 360 * MINUTE_MS),
        ] {
            let due = record.next_probe_at_ms;
            record.observe(verdict, "luna", due, &policy);
            assert_eq!(record.phase, Phase::Cooling);
            assert_eq!(record.next_probe_at_ms, due + expected);
            assert!(!record.eligible());
            assert!(record.ever_healthy);
        }
        let due = record.next_probe_at_ms;
        round(&mut record, Verdict::Healthy, "astra", due, &policy);
        assert!(!record.eligible());
    }

    #[test]
    fn clock_rollback_cannot_consume_or_join_round_evidence() {
        let policy = Policy::default();
        let mut record = admitted(&policy);
        let now = record.next_probe_at_ms;
        record.observe(Verdict::Anomaly, "luna", now, &policy);
        let count = record.sample_counter;
        round(&mut record, Verdict::Anomaly, "luna", now - 1, &policy);
        assert_eq!(record.round_samples, 1);
        assert_eq!(record.updated_at_ms, now);
        assert_eq!(record.sample_counter, count + 3);
    }

    #[test]
    fn round_spacing_is_enforced_even_if_due_time_was_rescheduled() {
        let policy = Policy::default();
        let mut record = admitted(&policy);
        let now = record.next_probe_at_ms;
        round(&mut record, Verdict::Anomaly, "luna", now, &policy);
        record.next_probe_at_ms = now;
        round(&mut record, Verdict::Anomaly, "luna", now + 1, &policy);
        assert_eq!(record.anomaly_round_count, 1);
        assert_eq!(record.next_probe_at_ms, now + policy.anomaly_spacing_ms);
    }

    #[test]
    fn restart_preserves_cooling_and_partial_recovery_without_touching_lease() {
        let policy = Policy::default();
        let mut record = cooled(&policy);
        record.lease_id = "owner".to_owned();
        record.lease_until_ms = i64::MAX;
        let due = record.next_probe_at_ms;
        record.observe(Verdict::Healthy, "astra", due, &policy);
        let json = serde_json::to_string(&record).unwrap();
        let mut restored: Record = serde_json::from_str(&json).unwrap();
        assert!(!restored.eligible());
        restored.observe(Verdict::Healthy, "astra", due, &policy);
        restored.observe(Verdict::Healthy, "astra", due, &policy);
        assert_eq!(restored.recovery_round_count, 1);
        assert_eq!(restored.lease_id, "owner");
        assert_eq!(restored.lease_until_ms, i64::MAX);
        assert_eq!(restored.config_tag, "v1");
    }

    #[test]
    fn invalid_anomaly_label_cannot_complete_a_round() {
        let policy = Policy::default();
        let mut record = Record::new("v1".to_owned(), 0);
        record.observe(Verdict::Healthy, "astra", 0, &policy);
        record.observe(Verdict::Healthy, "astra", 0, &policy);
        record.observe(Verdict::Anomaly, "", 0, &policy);
        assert_eq!(record.last_verdict, Some(Verdict::Unknown));
        assert_eq!(record.round_samples, 0);
        assert!(!record.eligible());
    }

    #[test]
    fn config_reset_preserves_cooldown_lease_and_challenge_sequence() {
        let policy = Policy::default();
        let mut record = cooled(&policy);
        let due = record.next_probe_at_ms;
        record.observe(Verdict::Unknown, "", due, &policy);
        record.lease_id = "old-worker".to_owned();
        record.lease_until_ms = due + 150_000;
        record.last_error = Some("old-error".to_owned());
        record.last_request_id = Some("old-request".to_owned());
        let next = record.next_probe_at_ms;
        let mut reset = record.reset_for_config("v2".to_owned(), due + 1);
        assert_eq!(reset.phase, Phase::Cooling);
        assert!(!reset.eligible());
        assert!(reset.ever_healthy);
        assert_eq!(reset.next_probe_at_ms, next);
        assert_eq!(reset.lease_id, record.lease_id);
        assert_eq!(reset.lease_until_ms, record.lease_until_ms);
        assert_eq!(reset.sample_counter, record.sample_counter);
        assert_eq!(reset.config_tag, "v2");
        assert_eq!(reset.last_verdict, None);
        assert!(reset.last_candidate.is_empty());
        assert_eq!(reset.last_error, None);
        assert_eq!(reset.last_request_id, None);
        reset.observe(Verdict::Unknown, "", next, &policy);
        assert_eq!(reset.next_probe_at_ms, next + 240 * MINUTE_MS);
    }

    #[test]
    fn config_reset_requires_fresh_admission_and_restarts_recovery_rounds() {
        let policy = Policy::default();
        let healthy = admitted(&policy);
        let pending = healthy.reset_for_config("v2".to_owned(), 1);
        assert_eq!(pending.phase, Phase::Pending);
        assert!(!pending.eligible());
        assert!(pending.ever_healthy);
        assert_eq!(pending.next_probe_at_ms, 1);

        let mut record = cooled(&policy);
        let due = record.next_probe_at_ms;
        round(&mut record, Verdict::Healthy, "astra", due, &policy);
        assert_eq!(record.recovery_round_count, 1);
        let now = record.next_probe_at_ms + 1;
        let mut reset = record.reset_for_config("v2".to_owned(), now);
        assert_eq!(reset.phase, Phase::Cooling);
        assert_eq!(reset.next_probe_at_ms, now);
        round(&mut reset, Verdict::Healthy, "astra", now, &policy);
        assert!(!reset.eligible());
        let later = reset.next_probe_at_ms;
        round(&mut reset, Verdict::Healthy, "astra", later, &policy);
        assert!(reset.eligible());
    }
}
