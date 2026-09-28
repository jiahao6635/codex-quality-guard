//! ModelTrace 单响应评分器，固定提交 df3a0f9d3e054c0dc02d6d586686db8daf8fa7c8。
//! 改编自 xqy2006/ModelTrace（MIT），完整版权声明见 data/modeltrace/LICENSE。
//! 分数是候选库内权重，不代表已认证的真实后端模型身份。

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::OnceLock};

pub const VERSION: &str = "modeltrace-df3a0f9d-strict-v1";
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

/// 只接受完整整数列表，不从解释正文中提取数字。
/// 调用此函数前，由探针执行层检查传输完成状态。
fn parse_strict(text: &str, expected_count: usize) -> Result<Vec<usize>, String> {
    if !(292..=332).contains(&expected_count) {
        return Err("challenge count must be within the reference range 292..332".into());
    }
    if text.len() > 16_384 {
        return Err("probe output exceeds the size limit".into());
    }
    let mut body = text.trim();
    let array = body.starts_with('[');
    if array {
        body = body
            .strip_prefix('[')
            .unwrap()
            .strip_suffix(']')
            .ok_or("incomplete JSON array")?
            .trim();
    }
    let bytes = body.as_bytes();
    let mut i = 0;
    let mut numbers = Vec::with_capacity(expected_count);
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start || (i - start > 1 && bytes[start] == b'0') {
            return Err("output must contain only literal integers and separators".into());
        }
        let value: usize = body[start..i].parse().map_err(|_| "invalid integer")?;
        if !(1..=DIMENSION).contains(&value) {
            return Err("number outside 1..355".into());
        }
        numbers.push(value);
        if numbers.len() > expected_count {
            return Err("too many integers; output was not truncated".into());
        }
        let end = i;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == bytes.len() {
            break;
        }
        if bytes[i] == b',' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i == bytes.len() {
                return Err("trailing comma".into());
            }
        } else if array || i == end {
            return Err("invalid separator or surrounding prose".into());
        }
    }
    if numbers.len() != expected_count {
        return Err(format!(
            "expected {expected_count} integers, received {}",
            numbers.len()
        ));
    }
    Ok(numbers)
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

pub fn score(text: &str, expected_count: usize, expected_model: &str) -> Result<Score, String> {
    let bank = bank();
    let expected = bank
        .models
        .iter()
        .position(|m| m.id == expected_model)
        .ok_or_else(|| {
            format!("model {expected_model} is absent from the pinned reference bank")
        })?;
    let numbers = parse_strict(text, expected_count)?;
    let mut counts = vec![0.0; DIMENSION];
    for value in &numbers {
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
    let scaled = scale_features(&ordered_features(&numbers), ordered);
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
    // 此接口每次只评一份响应，不能使用多响应校准系数。
    let beta = bank.calibration["1"].beta;
    let logits: Vec<f64> = marginal_scores
        .iter()
        .zip(ordered_scores)
        .map(|(a, b)| beta * ((1.0 - ordered.weight) * a + ordered.weight * b))
        .collect();
    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let weights: Vec<f64> = logits.iter().map(|value| (value - max).exp()).collect();
    let total: f64 = weights.iter().sum();
    let mut best = 0;
    for i in 1..weights.len() {
        if weights[i] > weights[best] {
            best = i;
        }
    }
    let result = Score {
        predicted_model: bank.models[best].id.clone(),
        predicted_probability: weights[best] / total,
        expected_probability: weights[expected] / total,
    };
    if !result.predicted_probability.is_finite() || !result.expected_probability.is_finite() {
        return Err("non-finite reference score".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Golden {
        text: String,
        expected_count: usize,
        expected_model: String,
        score: Score,
    }

    #[test]
    fn golden_parity_and_strict_validation() {
        let cases: Vec<Golden> =
            serde_json::from_str(include_str!("../../data/modeltrace/golden.json")).unwrap();
        assert!(cases.len() >= 6);
        for case in cases {
            let actual = score(&case.text, case.expected_count, &case.expected_model).unwrap();
            assert_eq!(actual.predicted_model, case.score.predicted_model);
            assert!(
                (actual.predicted_probability - case.score.predicted_probability).abs() < 1e-10
            );
            assert!((actual.expected_probability - case.score.expected_probability).abs() < 1e-10);
        }
        let good = vec!["7"; 300].join(",");
        assert!(score(&good, 300, "gpt-6-astra").is_ok());
        assert!(score(&format!("[{good}]"), 300, "gpt-6-astra").is_ok());
        for bad in [
            format!("answer: {good}"),
            format!("{good},7"),
            format!("{good},"),
            format!("[{good}"),
            good.replacen('7', "-7", 1),
            good.replacen('7', "7.0", 1),
            good.replacen('7', "7e0", 1),
            good.replacen('7', "356", 1),
            good.replacen('7', "0", 1),
            good.replacen('7', "07", 1),
            format!("```json\n[{good}]\n```"),
            format!("[{}]", vec!["7"; 300].join(" ")),
        ] {
            assert!(
                score(&bad, 300, "gpt-6-astra").is_err(),
                "accepted malformed sample"
            );
        }
        assert!(score(&good, 299, "gpt-6-astra").is_err());
        assert!(score(&good, 301, "gpt-6-astra").is_err());
        assert!(score(&good, 300, "unknown-model").is_err());
        assert!(!supports_model("unknown-model"));
        assert!(supports_model("gpt-5.6-luna"));
        assert_eq!(challenge(42).prompt, challenge(42).prompt);
        assert_ne!(challenge(42).id, challenge(43).id);
        for seed in 0..100 {
            assert!((292..=332).contains(&challenge(seed).expected_count));
        }
    }
}
