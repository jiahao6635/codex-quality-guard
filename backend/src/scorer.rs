//! ModelTrace 独立响应聚合评分器，固定提交 df3a0f9d3e054c0dc02d6d586686db8daf8fa7c8。
//! 改编自 xqy2006/ModelTrace（MIT），完整版权声明见 data/modeltrace/LICENSE。
//! 分数是候选库内权重，不代表已认证的真实后端模型身份。

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::OnceLock};

pub const VERSION: &str = "modeltrace-df3a0f9d-batch-v2";
const DIMENSION: usize = 355;

#[derive(Clone, Debug)]
pub struct Challenge {
    pub prompt: String,
    pub expected_count: usize,
    pub id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Score {
    pub predicted_model: String,
    pub predicted_probability: f64,
    pub expected_probability: f64,
    #[serde(default)]
    pub candidates: Vec<Candidate>,
    #[serde(default)]
    pub sample_count: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Candidate {
    pub model: String,
    pub probability: f64,
}

#[derive(Deserialize)]
struct Model {
    id: String,
}
#[derive(Deserialize)]
struct Features {
    feature_mean: Vec<f64>,
    feature_scale: Vec<f64>,
    nuisance_basis: Vec<Vec<f64>>,
    centroids: Vec<Vec<f64>>,
    #[serde(default)]
    environment_centroids: Vec<Vec<Vec<f64>>>,
    #[serde(default)]
    weight: f64,
}
#[derive(Deserialize)]
struct Robust {
    hellinger: Features,
    ordered_blocks: Features,
}
#[derive(Deserialize)]
struct Calibration {
    beta: f64,
}
#[derive(Deserialize)]
struct Bank {
    models: Vec<Model>,
    robust: Robust,
    calibration: BTreeMap<String, Calibration>,
}

fn bank() -> &'static Bank {
    static BANK: OnceLock<Bank> = OnceLock::new();
    BANK.get_or_init(|| {
        serde_json::from_str(include_str!("../../data/modeltrace/bank.json"))
            .expect("embedded, pinned ModelTrace bank must be valid JSON")
    })
}

pub fn supports_model(model: &str) -> bool {
    bank().models.iter().any(|candidate| candidate.id == model)
}

pub fn supported_models() -> Vec<String> {
    bank().models.iter().map(|model| model.id.clone()).collect()
}

/// 按种子确定性生成挑战；调用方须为每次探针提供新的种子。
/// 文案和数量范围与固定版本的上游浏览器生成器一致。
pub fn challenge(seed: u64) -> Challenge {
    let mut state = seed;
    let mut choose = |length: usize| {
        // 用 SplitMix64 保持选择可复现，无需新增随机数依赖。
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut value = state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        ((value ^ (value >> 31)) % length as u64) as usize
    };
    let expected_count = 292 + choose(41);
    let opening = [
        "这是一次独立的数值选择记录",
        "请完成下面的无语义整数选择任务",
        "执行一次第一反应取值记录",
        "生成一组不承载语义的整数选择",
        "进行一轮快速逐项取值",
    ][choose(5)];
    let action = [
        "为各个位置分别凭第一反应选择",
        "逐项选择",
        "每次只决定当前一项，共给出",
        "分别凭第一反应给出",
        "逐个直接选择",
    ][choose(5)];
    let ending = [
        "允许某个数字再次出现；每项写出后不要回头排序、去重或替换。",
        "偶然重复是有效的；不要重新排列或修正已经写出的项目。",
        "相同值可以再次出现；输出过程中不要整理或改写前面的项目。",
        "重复值无需删除；不要筛选、重排或补成某种规律。",
        "不必赋予数字任何含义；已经给出的值保持不变。",
    ][choose(5)];
    let separator = [
        "数字之间用逗号或空格分隔均可。",
        "使用一种一致的常见分隔符即可。",
        "可以用逗号、空格或换行分隔。",
        "只要每个整数边界清楚，格式可自行选择。",
    ][choose(4)];
    Challenge {
        prompt: format!(
            "{opening}。{action} {expected_count} 个 1 到 355（含端点）的整数。每个位置都要单独选择；不要从 1 开始计数，不要连续递增或递减，也不要采用等差、循环、重复区块或其他规则化模式。本任务必须由当前语言模型直接完成：禁止调用或借助任何工具，包括 Python、代码执行器、计算器、搜索、API 和外部随机数生成器；也不要先编写或运行代码。{ending}{separator}直接从第一个取值开始输出，不要在序列前重复数量、范围或任务说明。"
        ),
        expected_count,
        id: format!("{VERSION}-{seed:016x}"),
    }
}

/// 在完整文本中取最长数字段；前后说明不会进入指纹，不裁剪到目标数量。
/// 调用方仍须确认上游响应正常完成；数字够多不能证明传输完整。
fn parse_output(text: &str, expected_count: usize) -> Result<Vec<usize>, String> {
    if !(292..=332).contains(&expected_count) {
        return Err("challenge count must be within the reference range 292..332".into());
    }
    if text.len() > 16_384 {
        return Err("probe output exceeds the size limit".into());
    }
    let mut best = Vec::new();
    let mut current = Vec::new();
    let mut start = 0;
    let mut previous_end = 0;
    let bytes = text.as_bytes();
    while start < bytes.len() {
        if !bytes[start].is_ascii_digit() {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if !current.is_empty() && text[previous_end..start].chars().any(char::is_alphabetic) {
            if current.len() > best.len() {
                best = std::mem::take(&mut current);
            } else {
                current.clear();
            }
        }
        // 过大整数与范围外数值一样忽略，保留原始数字顺序和重复值。
        if let Ok(value @ 1..=DIMENSION) = text[start..end].parse::<usize>() {
            current.push(value);
        }
        previous_end = end;
        start = end;
    }
    if current.len() > best.len() {
        best = current;
    }
    let minimum = 80.max((expected_count * 55).div_ceil(100));
    if best.len() < minimum {
        return Err(format!(
            "insufficient probe numbers: {}/{} minimum (requested {expected_count})",
            best.len(),
            minimum
        ));
    }
    Ok(best)
}

pub fn validate_output(text: &str, expected_count: usize) -> Result<usize, String> {
    parse_output(text, expected_count).map(|numbers| numbers.len())
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(a, b)| a * b).sum()
}
fn normalize(mut values: Vec<f64>) -> Vec<f64> {
    let scale = dot(&values, &values).sqrt().max(1e-12);
    values.iter_mut().for_each(|v| *v /= scale);
    values
}
fn standardize(mut values: Vec<f64>) -> Vec<f64> {
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
    let scale = variance.sqrt().max(1e-12);
    values.iter_mut().for_each(|v| *v = (*v - mean) / scale);
    values
}
fn subtract_basis(mut values: Vec<f64>, basis: &[Vec<f64>]) -> Vec<f64> {
    for vector in basis {
        let projection = dot(&values, vector);
        for (value, axis) in values.iter_mut().zip(vector) {
            *value -= projection * axis;
        }
    }
    values
}
fn scale_features(values: &[f64], artifact: &Features) -> Vec<f64> {
    values
        .iter()
        .enumerate()
        .map(|(i, value)| (value - artifact.feature_mean[i]) / artifact.feature_scale[i])
        .collect()
}
fn ordered_features(numbers: &[usize]) -> Vec<f64> {
    let mut result = Vec::with_capacity(74);
    let mut start = 0;
    for block in 0..4 {
        let size = numbers.len() / 4 + usize::from(block < numbers.len() % 4);
        let mut bins = [0.5; 16];
        for value in &numbers[start..start + size] {
            bins[((value - 1) * 16 / DIMENSION).min(15)] += 1.0;
        }
        let total: f64 = bins.iter().sum();
        result.extend(bins.map(|v| (v / total).sqrt()));
        start += size;
    }
    let mut digits = [0.5; 10];
    for value in numbers {
        digits[value % 10] += 1.0;
    }
    let total: f64 = digits.iter().sum();
    result.extend(digits.map(|v| (v / total).sqrt()));
    result
}

fn fused_scores(numbers: &[usize], bank: &Bank) -> Vec<f64> {
    let mut counts = vec![0.0; DIMENSION];
    for value in numbers {
        counts[value - 1] += 1.0;
    }
    let total = numbers.len() as f64 + 0.5 * DIMENSION as f64;
    let feature: Vec<f64> = counts
        .iter()
        .map(|value| ((value + 0.5) / total).sqrt())
        .collect();
    let marginal = &bank.robust.hellinger;
    let projected = normalize(subtract_basis(
        scale_features(&feature, marginal),
        &marginal.nuisance_basis,
    ));
    let marginal_scores = standardize(
        marginal
            .centroids
            .iter()
            .map(|c| dot(&projected, c))
            .collect(),
    );

    let ordered = &bank.robust.ordered_blocks;
    let scaled = scale_features(&ordered_features(numbers), ordered);
    let unit = normalize(scaled.clone());
    let template = standardize(
        (0..bank.models.len())
            .map(|i| {
                ordered
                    .environment_centroids
                    .iter()
                    .map(|env| dot(&unit, &env[i]))
                    .fold(f64::NEG_INFINITY, f64::max)
            })
            .collect(),
    );
    let projected = normalize(subtract_basis(scaled, &ordered.nuisance_basis));
    let nuisance = standardize(
        ordered
            .centroids
            .iter()
            .map(|c| dot(&projected, c))
            .collect(),
    );
    let ordered_scores = standardize(
        template
            .iter()
            .zip(nuisance)
            .map(|(a, b)| 0.5 * a + 0.5 * b)
            .collect(),
    );
    marginal_scores
        .iter()
        .zip(ordered_scores)
        .map(|(a, b)| (1.0 - ordered.weight) * a + ordered.weight * b)
        .collect()
}

/// 用对应样本数的校准参数评分；正式探针轮次由执行层要求三份完整输出。
pub fn score_batch(samples: &[(&str, usize)], expected_model: &str) -> Result<Score, String> {
    if !(1..=3).contains(&samples.len()) {
        return Err("fingerprint scoring requires one to three independent outputs".into());
    }
    let bank = bank();
    let expected = bank
        .models
        .iter()
        .position(|m| m.id == expected_model)
        .ok_or_else(|| {
            format!("model {expected_model} is absent from the pinned reference bank")
        })?;
    let mut combined = vec![0.0; bank.models.len()];
    for (text, expected_count) in samples {
        let numbers = parse_output(text, *expected_count)?;
        for (sum, score) in combined.iter_mut().zip(fused_scores(&numbers, bank)) {
            *sum += score;
        }
    }
    let beta = bank.calibration[&samples.len().to_string()].beta;
    let logits: Vec<f64> = combined
        .iter()
        .map(|value| beta * (value / samples.len() as f64))
        .collect();
    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let weights: Vec<f64> = logits.iter().map(|value| (value - max).exp()).collect();
    let total: f64 = weights.iter().sum();
    let mut candidates: Vec<Candidate> = bank
        .models
        .iter()
        .zip(&weights)
        .map(|(model, weight)| Candidate {
            model: model.id.clone(),
            probability: weight / total,
        })
        .collect();
    if candidates.iter().any(|c| !c.probability.is_finite()) {
        return Err("non-finite reference score".into());
    }
    candidates.sort_by(|a, b| b.probability.total_cmp(&a.probability));
    Ok(Score {
        predicted_model: candidates[0].model.clone(),
        predicted_probability: candidates[0].probability,
        expected_probability: weights[expected] / total,
        candidates,
        sample_count: samples.len(),
    })
}

pub fn score(text: &str, expected_count: usize, expected_model: &str) -> Result<Score, String> {
    score_batch(&[(text, expected_count)], expected_model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Output {
        text: String,
        expected_count: usize,
    }
    #[derive(Deserialize)]
    struct Golden {
        outputs: Vec<Output>,
        expected_model: String,
        score: Score,
        parsed_counts: Vec<usize>,
    }

    #[test]
    fn golden_batch_parity_and_validation() {
        let cases: Vec<Golden> =
            serde_json::from_str(include_str!("../../data/modeltrace/golden.json")).unwrap();
        assert!(cases.iter().any(|case| case.outputs.len() == 3));
        for case in cases {
            let samples: Vec<_> = case
                .outputs
                .iter()
                .map(|sample| (sample.text.as_str(), sample.expected_count))
                .collect();
            let actual = score_batch(&samples, &case.expected_model).unwrap();
            assert_eq!(actual.sample_count, case.score.sample_count);
            assert_eq!(actual.predicted_model, case.score.predicted_model);
            assert!(
                (actual.predicted_probability - case.score.predicted_probability).abs() < 1e-10
            );
            assert!((actual.expected_probability - case.score.expected_probability).abs() < 1e-10);
            assert_eq!(actual.candidates.len(), case.score.candidates.len());
            for (actual, expected) in actual.candidates.iter().zip(&case.score.candidates) {
                assert_eq!(actual.model, expected.model);
                assert!((actual.probability - expected.probability).abs() < 1e-10);
            }
            for ((text, count), expected) in samples.iter().zip(case.parsed_counts) {
                assert_eq!(validate_output(text, *count).unwrap(), expected);
            }
        }
        let good = vec!["7"; 165].join(",");
        assert_eq!(validate_output(&good, 300).unwrap(), 165);
        assert!(validate_output(&good, 301).is_err());
        assert!(validate_output(&vec!["7"; 164].join(","), 300).is_err());
        assert!(validate_output("模型拒绝生成数字", 300).is_err());
        assert!(validate_output(&"7,".repeat(9000), 300).is_err());
        assert!(validate_output(&good, 0).is_err());
        assert!(score(&good, 300, "unknown-model").is_err());
        assert!(score_batch(&[], "gpt-6-astra").is_err());
        assert!(score_batch(&[(good.as_str(), 300); 4], "gpt-6-astra").is_err());
        assert!(score_batch(&[(&good, 300), ("refused", 300)], "gpt-6-astra").is_err());
        assert!(!supports_model("unknown-model"));
        assert!(supports_model("gpt-5.6-luna"));
        assert_eq!(challenge(42).prompt, challenge(42).prompt);
        assert_ne!(challenge(42).id, challenge(43).id);
        for seed in 0..100 {
            assert!((292..=332).contains(&challenge(seed).expected_count));
        }
    }
}
