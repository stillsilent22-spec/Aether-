use crate::policy_executor::{RuleCondition, RuleDefinition};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SWARM_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeKpiReport {
    pub schema_version: u16,
    pub node_id: String,
    pub epoch_minute: u64,
    pub kpis: BTreeMap<String, f64>,
    pub rule_feedback: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNodeKpiReport {
    pub report: NodeKpiReport,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedRuleSet {
    pub version: u64,
    pub generated_at_epoch: u64,
    pub checksum_hex: String,
    pub rules: Vec<RuleDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalAggregationSnapshot {
    pub schema_version: u16,
    pub epoch_minute: u64,
    pub accepted_nodes: usize,
    pub rejected_nodes: usize,
    pub aggregated_kpis: BTreeMap<String, f64>,
    pub optimized_ruleset: OptimizedRuleSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDistributionItem {
    pub node_id: String,
    pub ruleset_version: u64,
    pub checksum_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScalingProof {
    pub samples: usize,
    pub latency_ms_slope: f64,
    pub throughput_ops_slope: f64,
    pub noise_ratio_slope: f64,
    pub efficiency_index: f64,
    pub scaling_claim: bool,
}

pub struct SwarmLearningLoop {
    history: Vec<GlobalAggregationSnapshot>,
    history_limit: usize,
    aggregate_log_path: PathBuf,
    proof_log_path: PathBuf,
}

impl SwarmLearningLoop {
    pub fn new(history_limit: usize) -> Self {
        Self {
            history: Vec::new(),
            history_limit: history_limit.max(3),
            aggregate_log_path: PathBuf::from("logs").join("swarm_aggregate.jsonl"),
            proof_log_path: PathBuf::from("logs").join("swarm_scaling_proof.jsonl"),
        }
    }

    pub fn ingest_batch(
        &mut self,
        batch: &[SignedNodeKpiReport],
        allowed_pubkeys_by_node: &BTreeMap<String, String>,
        known_nodes: &[String],
    ) -> Result<(GlobalAggregationSnapshot, ScalingProof, Vec<RuleDistributionItem>), String> {
        let snapshot = aggregate_signed_reports(batch, allowed_pubkeys_by_node)?;
        append_jsonl(&self.aggregate_log_path, &snapshot)?;

        self.history.push(snapshot.clone());
        if self.history.len() > self.history_limit {
            self.history.remove(0);
        }

        let proof = compute_scaling_proof(&self.history);
        append_jsonl(&self.proof_log_path, &proof)?;

        let distribution = build_distribution_plan(known_nodes, &snapshot.optimized_ruleset);
        Ok((snapshot, proof, distribution))
    }

    pub fn history(&self) -> &[GlobalAggregationSnapshot] {
        &self.history
    }
}

pub fn aggregate_signed_reports(
    batch: &[SignedNodeKpiReport],
    allowed_pubkeys_by_node: &BTreeMap<String, String>,
) -> Result<GlobalAggregationSnapshot, String> {
    if batch.is_empty() {
        return Err("Batch darf nicht leer sein".to_owned());
    }

    let mut accepted_reports = Vec::new();
    let mut rejected_nodes = 0usize;

    for item in batch {
        let expected_pubkey = allowed_pubkeys_by_node
            .get(&item.report.node_id)
            .ok_or_else(|| format!("Node {} ist nicht zugelassen", item.report.node_id))?;
        if expected_pubkey != &item.public_key_hex {
            rejected_nodes += 1;
            continue;
        }

        if verify_signed_report(item).is_err() || validate_report(&item.report).is_err() {
            rejected_nodes += 1;
            continue;
        }

        accepted_reports.push(item.report.clone());
    }

    if accepted_reports.is_empty() {
        return Err("Kein gueltiger signierter Report im Batch".to_owned());
    }

    let epoch_minute = accepted_reports
        .iter()
        .map(|report| report.epoch_minute)
        .max()
        .unwrap_or_default();

    let aggregated_kpis = aggregate_kpis_median(&accepted_reports);
    let optimized_ruleset = derive_optimized_ruleset(&aggregated_kpis, epoch_minute);

    Ok(GlobalAggregationSnapshot {
        schema_version: SWARM_SCHEMA_VERSION,
        epoch_minute,
        accepted_nodes: accepted_reports.len(),
        rejected_nodes,
        aggregated_kpis,
        optimized_ruleset,
    })
}

pub fn verify_signed_report(item: &SignedNodeKpiReport) -> Result<(), String> {
    let message = canonical_report_bytes(&item.report)?;
    let key_bytes = decode_hex_exact(&item.public_key_hex, 32)?;
    let sig_bytes = decode_hex_exact(&item.signature_hex, 64)?;

    let key = VerifyingKey::from_bytes(
        &key_bytes
            .try_into()
            .map_err(|_| "Public-Key-Format ungueltig".to_owned())?,
    )
    .map_err(|err| format!("Public-Key ungueltig: {err}"))?;
    let signature = Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| "Signatur-Format ungueltig".to_owned())?,
    );

    key.verify(&message, &signature)
        .map_err(|err| format!("Signaturpruefung fehlgeschlagen: {err}"))
}

pub fn validate_report(report: &NodeKpiReport) -> Result<(), String> {
    if report.schema_version != SWARM_SCHEMA_VERSION {
        return Err(format!(
            "Ungueltige Schema-Version: {}",
            report.schema_version
        ));
    }
    validate_id("node_id", &report.node_id)?;
    if report.epoch_minute == 0 {
        return Err("epoch_minute darf nicht 0 sein".to_owned());
    }
    if report.kpis.is_empty() {
        return Err("kpis duerfen nicht leer sein".to_owned());
    }
    validate_metric_map("kpis", &report.kpis, -1_000_000.0, 1_000_000.0)?;
    validate_metric_map("rule_feedback", &report.rule_feedback, -10_000.0, 10_000.0)?;
    Ok(())
}

pub fn build_distribution_plan(
    known_nodes: &[String],
    ruleset: &OptimizedRuleSet,
) -> Vec<RuleDistributionItem> {
    let mut unique_nodes = BTreeSet::new();
    for node in known_nodes {
        if validate_id("node_id", node).is_ok() {
            unique_nodes.insert(node.clone());
        }
    }

    unique_nodes
        .into_iter()
        .map(|node_id| RuleDistributionItem {
            node_id,
            ruleset_version: ruleset.version,
            checksum_hex: ruleset.checksum_hex.clone(),
        })
        .collect()
}

pub fn compute_scaling_proof(history: &[GlobalAggregationSnapshot]) -> ScalingProof {
    let samples = history.len();
    if samples < 3 {
        return ScalingProof {
            samples,
            scaling_claim: false,
            ..ScalingProof::default()
        };
    }

    let mut latency = Vec::new();
    let mut throughput = Vec::new();
    let mut noise = Vec::new();

    for snapshot in history {
        latency.push(*snapshot.aggregated_kpis.get("latency_ms").unwrap_or(&0.0));
        throughput.push(
            *snapshot
                .aggregated_kpis
                .get("throughput_ops")
                .unwrap_or(&0.0),
        );
        noise.push(*snapshot.aggregated_kpis.get("noise_ratio").unwrap_or(&0.0));
    }

    let latency_ms_slope = linear_slope(&latency);
    let throughput_ops_slope = linear_slope(&throughput);
    let noise_ratio_slope = linear_slope(&noise);

    let latest_latency = *latency.last().unwrap_or(&0.0);
    let latest_throughput = *throughput.last().unwrap_or(&0.0);
    let latest_noise = *noise.last().unwrap_or(&0.0);

    let efficiency_index = if latest_latency <= 0.0 {
        0.0
    } else {
        latest_throughput / (latest_latency * (1.0 + latest_noise.max(0.0)))
    };

    let scaling_claim = throughput_ops_slope > 0.0 && latency_ms_slope < 0.0 && noise_ratio_slope <= 0.0;

    ScalingProof {
        samples,
        latency_ms_slope,
        throughput_ops_slope,
        noise_ratio_slope,
        efficiency_index,
        scaling_claim,
    }
}

fn derive_optimized_ruleset(aggregated_kpis: &BTreeMap<String, f64>, epoch_minute: u64) -> OptimizedRuleSet {
    let trust_mean = *aggregated_kpis.get("trust_score").unwrap_or(&0.70);
    let entropy_mean = *aggregated_kpis.get("entropy_mean").unwrap_or(&6.5);
    let compression_gain = *aggregated_kpis
        .get("compression_gain_percent")
        .unwrap_or(&18.0);

    let trust_floor = trust_mean.clamp(0.45, 0.90);
    let entropy_ceiling = entropy_mean.clamp(4.0, 8.0);
    let promote_floor = compression_gain.clamp(10.0, 40.0);

    let mut rules = vec![
        RuleDefinition {
            id: "swarm_low_trust_quarantine".to_owned(),
            priority: 10,
            conditions: vec![RuleCondition {
                metric: "trust_score".to_owned(),
                op: "<".to_owned(),
                value: trust_floor,
            }],
            action: "quarantine".to_owned(),
            ttl_seconds: Some(1800),
        },
        RuleDefinition {
            id: "swarm_high_entropy_flag".to_owned(),
            priority: 20,
            conditions: vec![RuleCondition {
                metric: "entropy_mean".to_owned(),
                op: ">".to_owned(),
                value: entropy_ceiling,
            }],
            action: "flag".to_owned(),
            ttl_seconds: Some(900),
        },
        RuleDefinition {
            id: "swarm_promote_signal".to_owned(),
            priority: 30,
            conditions: vec![
                RuleCondition {
                    metric: "trust_score".to_owned(),
                    op: ">=".to_owned(),
                    value: trust_floor,
                },
                RuleCondition {
                    metric: "compression_gain_percent".to_owned(),
                    op: ">=".to_owned(),
                    value: promote_floor,
                },
            ],
            action: "promote".to_owned(),
            ttl_seconds: Some(1800),
        },
    ];

    rules.sort_by_key(|rule| (rule.priority, rule.id.clone()));

    let generated_at_epoch = now_epoch();
    let serialized = serde_json::to_vec(&rules).unwrap_or_default();
    let checksum_hex = sha256_hex(&serialized);

    OptimizedRuleSet {
        version: epoch_minute,
        generated_at_epoch,
        checksum_hex,
        rules,
    }
}

fn aggregate_kpis_median(reports: &[NodeKpiReport]) -> BTreeMap<String, f64> {
    let mut buckets: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for report in reports {
        for (key, value) in &report.kpis {
            buckets.entry(key.clone()).or_default().push(*value);
        }
    }

    let mut aggregated = BTreeMap::new();
    for (key, mut values) in buckets {
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let middle = values.len() / 2;
        let median = if values.len() % 2 == 0 {
            (values[middle - 1] + values[middle]) / 2.0
        } else {
            values[middle]
        };
        aggregated.insert(key, median);
    }
    aggregated
}

fn canonical_report_bytes(report: &NodeKpiReport) -> Result<Vec<u8>, String> {
    serde_json::to_vec(report).map_err(|err| format!("Report konnte nicht serialisiert werden: {err}"))
}

fn validate_metric_map(
    label: &str,
    map: &BTreeMap<String, f64>,
    min: f64,
    max: f64,
) -> Result<(), String> {
    for (key, value) in map {
        validate_id(label, key)?;
        if !value.is_finite() {
            return Err(format!("{label}.{key} ist nicht endlich"));
        }
        if *value < min || *value > max {
            return Err(format!("{label}.{key} ausserhalb der Grenzen"));
        }
    }
    Ok(())
}

fn validate_id(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} darf nicht leer sein"));
    }
    if value.len() > 128 {
        return Err(format!("{label} ist zu lang"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!("{label} enthaelt unzulaessige Zeichen"));
    }
    Ok(())
}

fn decode_hex_exact(input: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    if input.len() != expected_len * 2 {
        return Err(format!("Hex-Laenge ungueltig: erwartet {}", expected_len * 2));
    }
    let bytes = input
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hi = (chunk[0] as char)
                .to_digit(16)
                .ok_or_else(|| "Hex-Decode fehlgeschlagen".to_owned())?;
            let lo = (chunk[1] as char)
                .to_digit(16)
                .ok_or_else(|| "Hex-Decode fehlgeschlagen".to_owned())?;
            Ok(((hi << 4) + lo) as u8)
        })
        .collect::<Result<Vec<u8>, String>>()?;
    Ok(bytes)
}

fn linear_slope(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let n = values.len() as f64;
    let xs: Vec<f64> = (0..values.len()).map(|idx| idx as f64).collect();
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = values.iter().sum::<f64>() / n;
    let numerator = xs
        .iter()
        .zip(values.iter())
        .map(|(x, y)| (x - mean_x) * (y - mean_y))
        .sum::<f64>();
    let denominator = xs.iter().map(|x| (x - mean_x).powi(2)).sum::<f64>();
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Log-Verzeichnis fehlt: {err}"))?;
    }
    let raw = serde_json::to_string(value)
        .map_err(|err| format!("Log-Zeile konnte nicht serialisiert werden: {err}"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("Log-Datei konnte nicht geoeffnet werden: {err}"))?;
    writeln!(file, "{raw}").map_err(|err| format!("Log-Datei konnte nicht geschrieben werden: {err}"))
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn report(node: &str, latency_ms: f64, throughput_ops: f64, noise_ratio: f64) -> NodeKpiReport {
        NodeKpiReport {
            schema_version: SWARM_SCHEMA_VERSION,
            node_id: node.to_owned(),
            epoch_minute: 10,
            kpis: BTreeMap::from([
                ("latency_ms".to_owned(), latency_ms),
                ("throughput_ops".to_owned(), throughput_ops),
                ("noise_ratio".to_owned(), noise_ratio),
                ("trust_score".to_owned(), 0.78),
                ("entropy_mean".to_owned(), 6.2),
                ("compression_gain_percent".to_owned(), 26.0),
            ]),
            rule_feedback: BTreeMap::from([("flag_precision".to_owned(), 0.82)]),
        }
    }

    fn sign_report(report: NodeKpiReport, signing_key: &SigningKey) -> SignedNodeKpiReport {
        let payload = serde_json::to_vec(&report).unwrap();
        let signature = signing_key.sign(&payload);
        SignedNodeKpiReport {
            report,
            public_key_hex: signing_key
                .verifying_key()
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            signature_hex: signature
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }

    #[test]
    fn verifies_signed_report() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = sign_report(report("node_a", 12.0, 90.0, 0.2), &signing_key);
        assert!(verify_signed_report(&signed).is_ok());
    }

    #[test]
    fn deterministic_aggregation_and_distribution() {
        let key_a = SigningKey::from_bytes(&[7u8; 32]);
        let key_b = SigningKey::from_bytes(&[9u8; 32]);

        let signed_a = sign_report(report("node_a", 12.0, 90.0, 0.2), &key_a);
        let signed_b = sign_report(report("node_b", 10.0, 110.0, 0.1), &key_b);

        let allowed = BTreeMap::from([
            ("node_a".to_owned(), signed_a.public_key_hex.clone()),
            ("node_b".to_owned(), signed_b.public_key_hex.clone()),
        ]);

        let snapshot = aggregate_signed_reports(&[signed_b.clone(), signed_a.clone()], &allowed).unwrap();
        assert_eq!(snapshot.accepted_nodes, 2);
        assert_eq!(snapshot.aggregated_kpis.get("latency_ms").copied(), Some(11.0));
        assert_eq!(snapshot.aggregated_kpis.get("throughput_ops").copied(), Some(100.0));

        let plan = build_distribution_plan(
            &["node_b".to_owned(), "node_a".to_owned(), "node_a".to_owned()],
            &snapshot.optimized_ruleset,
        );
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].node_id, "node_a");
        assert_eq!(plan[1].node_id, "node_b");
    }

    #[test]
    fn scaling_proof_detects_improving_trend() {
        let mut history = Vec::new();
        for index in 0..5u64 {
            let mut kpis = BTreeMap::new();
            kpis.insert("latency_ms".to_owned(), 18.0 - index as f64);
            kpis.insert("throughput_ops".to_owned(), 200.0 + (index as f64 * 15.0));
            kpis.insert("noise_ratio".to_owned(), 0.30 - (index as f64 * 0.03));
            let ruleset = derive_optimized_ruleset(&kpis, index + 1);
            history.push(GlobalAggregationSnapshot {
                schema_version: SWARM_SCHEMA_VERSION,
                epoch_minute: index + 1,
                accepted_nodes: 3,
                rejected_nodes: 0,
                aggregated_kpis: kpis,
                optimized_ruleset: ruleset,
            });
        }

        let proof = compute_scaling_proof(&history);
        assert!(proof.scaling_claim);
        assert!(proof.throughput_ops_slope > 0.0);
        assert!(proof.latency_ms_slope < 0.0);
    }
}
