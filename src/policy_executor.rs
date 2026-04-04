use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleCondition {
    pub metric: String,
    pub op: String,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleDefinition {
    pub id: String,
    pub priority: i32,
    pub conditions: Vec<RuleCondition>,
    pub action: String,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleDecisionEntry {
    pub timestamp_epoch: u64,
    pub candidate_id: String,
    pub metrics: BTreeMap<String, f64>,
    pub rule_ids: Vec<String>,
    pub action: String,
    pub actor: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuleEngine {
    rules: Vec<RuleDefinition>,
    log_path: Option<PathBuf>,
}

impl RuleEngine {
    pub fn new(mut rules: Vec<RuleDefinition>, log_path: Option<PathBuf>) -> Result<Self, String> {
        for rule in &rules {
            validate_rule(rule)?;
        }
        rules.sort_by_key(|rule| rule.priority);
        Ok(Self { rules, log_path })
    }

    pub fn evaluate(
        &self,
        metrics: &BTreeMap<String, f64>,
        candidate_id: &str,
        actor: &str,
        evidence_refs: &[String],
        write_log: bool,
    ) -> Option<RuleDecisionEntry> {
        let rule = self.rules.iter().find(|rule| rule_matches(rule, metrics))?;
        let entry = build_entry(rule, metrics, candidate_id, actor, evidence_refs);
        if write_log {
            let _ = write_decision_log(&entry, self.log_path.as_deref());
        }
        Some(entry)
    }

    pub fn evaluate_all(
        &self,
        metrics: &BTreeMap<String, f64>,
        candidate_id: &str,
        actor: &str,
        evidence_refs: &[String],
        write_log: bool,
    ) -> Vec<RuleDecisionEntry> {
        let results: Vec<RuleDecisionEntry> = self
            .rules
            .iter()
            .filter(|rule| rule_matches(rule, metrics))
            .map(|rule| build_entry(rule, metrics, candidate_id, actor, evidence_refs))
            .collect();
        if write_log {
            for entry in &results {
                let _ = write_decision_log(entry, self.log_path.as_deref());
            }
        }
        results
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

pub fn default_analysis_rules() -> Vec<RuleDefinition> {
    vec![
        RuleDefinition {
            id: "eicar_detected_quarantine".to_owned(),
            priority: 5,
            conditions: vec![RuleCondition {
                metric: "eicar_hit".to_owned(),
                op: ">=".to_owned(),
                value: 1.0,
            }],
            action: "quarantine".to_owned(),
            ttl_seconds: Some(24 * 3600),
        },
        RuleDefinition {
            id: "low_trust_quarantine".to_owned(),
            priority: 10,
            conditions: vec![RuleCondition {
                metric: "trust_score".to_owned(),
                op: "<".to_owned(),
                value: 0.55,
            }],
            action: "quarantine".to_owned(),
            ttl_seconds: Some(3600),
        },
        RuleDefinition {
            id: "high_entropy_flag".to_owned(),
            priority: 20,
            conditions: vec![RuleCondition {
                metric: "entropy_mean".to_owned(),
                op: ">".to_owned(),
                value: 7.0,
            }],
            action: "flag".to_owned(),
            ttl_seconds: None,
        },
        RuleDefinition {
            id: "high_obfuscation_flag".to_owned(),
            priority: 21,
            conditions: vec![RuleCondition {
                metric: "obfuscation_score".to_owned(),
                op: ">=".to_owned(),
                value: 0.55,
            }],
            action: "flag".to_owned(),
            ttl_seconds: Some(7200),
        },
        RuleDefinition {
            id: "low_ethics_dampen".to_owned(),
            priority: 25,
            conditions: vec![RuleCondition {
                metric: "ethics_score".to_owned(),
                op: "<".to_owned(),
                value: 0.45,
            }],
            action: "dampen".to_owned(),
            ttl_seconds: Some(1800),
        },
        RuleDefinition {
            id: "strong_signal_promote".to_owned(),
            priority: 30,
            conditions: vec![
                RuleCondition {
                    metric: "trust_score".to_owned(),
                    op: ">=".to_owned(),
                    value: 0.80,
                },
                RuleCondition {
                    metric: "compression_gain_percent".to_owned(),
                    op: ">=".to_owned(),
                    value: 25.0,
                },
            ],
            action: "promote".to_owned(),
            ttl_seconds: None,
        },
    ]
}

pub fn load_rules_from_file(path: &Path) -> Result<Vec<RuleDefinition>, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("Rules-Datei konnte nicht gelesen werden: {err}"))?;
    let rules: Vec<RuleDefinition> =
        serde_json::from_str(&raw).map_err(|err| format!("Rules-JSON ungueltig: {err}"))?;
    for rule in &rules {
        validate_rule(rule)?;
    }
    Ok(rules)
}

pub fn write_decision_log(
    entry: &RuleDecisionEntry,
    log_path: Option<&Path>,
) -> Result<(), String> {
    let path = log_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_log_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Decision-Log-Verzeichnis fehlt: {err}"))?;
    }
    let serialized = serde_json::to_string(entry)
        .map_err(|err| format!("Decision-Log konnte nicht serialisiert werden: {err}"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| format!("Decision-Log konnte nicht geoeffnet werden: {err}"))?;
    writeln!(file, "{serialized}")
        .map_err(|err| format!("Decision-Log konnte nicht geschrieben werden: {err}"))?;
    Ok(())
}

fn build_entry(
    rule: &RuleDefinition,
    metrics: &BTreeMap<String, f64>,
    candidate_id: &str,
    actor: &str,
    evidence_refs: &[String],
) -> RuleDecisionEntry {
    RuleDecisionEntry {
        timestamp_epoch: now_epoch(),
        candidate_id: candidate_id.to_owned(),
        metrics: metrics.clone(),
        rule_ids: vec![rule.id.clone()],
        action: rule.action.clone(),
        actor: actor.to_owned(),
        evidence_refs: evidence_refs.to_vec(),
    }
}

fn default_log_path() -> PathBuf {
    PathBuf::from("logs").join("decisions.jsonl")
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn validate_rule(rule: &RuleDefinition) -> Result<(), String> {
    if rule.id.trim().is_empty() {
        return Err("Rule ohne ID ist ungueltig".to_owned());
    }
    if !matches!(
        rule.action.as_str(),
        "quarantine" | "dampen" | "persist" | "flag" | "mutate" | "promote"
    ) {
        return Err(format!("Rule {} hat ungueltige Aktion {}", rule.id, rule.action));
    }
    for condition in &rule.conditions {
        if condition.metric.trim().is_empty() {
            return Err(format!("Rule {} hat Bedingung ohne Metric", rule.id));
        }
        if !matches!(condition.op.as_str(), "<" | "<=" | ">" | ">=" | "==" | "!=") {
            return Err(format!("Rule {} hat ungueltigen Operator {}", rule.id, condition.op));
        }
    }
    Ok(())
}

fn rule_matches(rule: &RuleDefinition, metrics: &BTreeMap<String, f64>) -> bool {
    rule.conditions.iter().all(|condition| {
        let Some(value) = metrics.get(&condition.metric) else {
            return false;
        };
        compare(*value, &condition.op, condition.value)
    })
}

fn compare(left: f64, op: &str, right: f64) -> bool {
    match op {
        "<" => left < right,
        "<=" => left <= right,
        ">" => left > right,
        ">=" => left >= right,
        "==" => left == right,
        "!=" => left != right,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_match_uses_priority() {
        let engine = RuleEngine::new(
            vec![
                RuleDefinition {
                    id: "later".to_owned(),
                    priority: 20,
                    conditions: vec![RuleCondition {
                        metric: "entropy_mean".to_owned(),
                        op: ">".to_owned(),
                        value: 6.0,
                    }],
                    action: "flag".to_owned(),
                    ttl_seconds: None,
                },
                RuleDefinition {
                    id: "earlier".to_owned(),
                    priority: 10,
                    conditions: vec![RuleCondition {
                        metric: "entropy_mean".to_owned(),
                        op: ">".to_owned(),
                        value: 6.0,
                    }],
                    action: "quarantine".to_owned(),
                    ttl_seconds: None,
                },
            ],
            None,
        )
        .unwrap();
        let metrics = BTreeMap::from([("entropy_mean".to_owned(), 7.2)]);
        let result = engine
            .evaluate(&metrics, "candidate-a", "tests", &[], false)
            .unwrap();
        assert_eq!(result.rule_ids, vec!["earlier".to_owned()]);
        assert_eq!(result.action, "quarantine");
    }

    #[test]
    fn evaluate_all_collects_all_matches() {
        let engine = RuleEngine::new(default_analysis_rules(), None).unwrap();
        let metrics = BTreeMap::from([
            ("entropy_mean".to_owned(), 7.5),
            ("trust_score".to_owned(), 0.91),
            ("compression_gain_percent".to_owned(), 31.0),
        ]);
        let results = engine.evaluate_all(&metrics, "candidate-b", "tests", &[], false);
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|entry| entry.action == "flag"));
        assert!(results.iter().any(|entry| entry.action == "promote"));
    }

    #[test]
    fn writes_jsonl_decision_log() {
        let log_path = PathBuf::from("target").join("policy_executor_test.jsonl");
        let _ = fs::remove_file(&log_path);
        let engine = RuleEngine::new(default_analysis_rules(), Some(log_path.clone())).unwrap();
        let metrics = BTreeMap::from([
            ("entropy_mean".to_owned(), 7.5),
            ("trust_score".to_owned(), 0.42),
            ("compression_gain_percent".to_owned(), 10.0),
        ]);
        let results = engine.evaluate_all(&metrics, "candidate-c", "tests", &[], true);
        assert!(!results.is_empty());
        let raw = fs::read_to_string(&log_path).unwrap();
        assert!(raw.contains("candidate-c"));
        let _ = fs::remove_file(&log_path);
    }
}