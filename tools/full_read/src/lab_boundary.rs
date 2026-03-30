use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const LAB_SCHEMA_VERSION: u16 = 1;

const ALLOWED_MODELS: &[&str] = &["h_lambda", "bayes", "observer", "graph", "beauty"];
const ALLOWED_METRICS: &[&str] = &[
    "h_lambda",
    "bayes_score",
    "observer_coherence",
    "graph_density",
    "beauty_score",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabRequest {
    pub schema_version: u16,
    pub request_id: String,
    pub session_id: String,
    pub consent_token: String,
    pub model: String,
    pub payload: LabPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabPayload {
    pub content_hash_hex: String,
    pub content_size: u64,
    pub features: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabResponse {
    pub schema_version: u16,
    pub request_id: String,
    pub model: String,
    pub metrics: BTreeMap<String, f64>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryAuditEntry {
    pub timestamp_epoch: u64,
    pub request_id: String,
    pub model: String,
    pub accepted: bool,
    pub reason: String,
    pub metric_keys: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct StableLabMetrics {
    pub h_lambda: Option<f64>,
    pub bayes_score: Option<f64>,
    pub observer_coherence: Option<f64>,
    pub graph_density: Option<f64>,
    pub beauty_score: Option<f64>,
}

pub fn validate_request(request: &LabRequest) -> Result<(), String> {
    if request.schema_version != LAB_SCHEMA_VERSION {
        return Err(format!(
            "Ungueltige Schema-Version: {}",
            request.schema_version
        ));
    }
    validate_id("request_id", &request.request_id)?;
    validate_id("session_id", &request.session_id)?;
    validate_id("consent_token", &request.consent_token)?;
    if !ALLOWED_MODELS.contains(&request.model.as_str()) {
        return Err(format!("Unbekanntes Modell: {}", request.model));
    }
    if request.payload.content_hash_hex.len() < 16 {
        return Err("content_hash_hex ist zu kurz".to_owned());
    }
    if request.payload.content_size == 0 {
        return Err("content_size darf nicht 0 sein".to_owned());
    }
    for (key, value) in &request.payload.features {
        if key.trim().is_empty() {
            return Err("Feature-Key darf nicht leer sein".to_owned());
        }
        if !value.is_finite() {
            return Err(format!("Feature {} ist nicht endlich", key));
        }
    }
    Ok(())
}

pub fn validate_response(response: &LabResponse) -> Result<(), String> {
    if response.schema_version != LAB_SCHEMA_VERSION {
        return Err(format!(
            "Ungueltige Schema-Version: {}",
            response.schema_version
        ));
    }
    validate_id("request_id", &response.request_id)?;
    if !ALLOWED_MODELS.contains(&response.model.as_str()) {
        return Err(format!("Unbekanntes Modell: {}", response.model));
    }
    for (metric, value) in &response.metrics {
        if !ALLOWED_METRICS.contains(&metric.as_str()) {
            return Err(format!("Metrik nicht erlaubt: {}", metric));
        }
        if !value.is_finite() {
            return Err(format!("Metrik {} ist nicht endlich", metric));
        }
        if *value < -1_000_000.0 || *value > 1_000_000.0 {
            return Err(format!("Metrik {} ausserhalb der Grenzen", metric));
        }
    }
    Ok(())
}

pub fn extract_stable_metrics(response: &LabResponse) -> StableLabMetrics {
    StableLabMetrics {
        h_lambda: response.metrics.get("h_lambda").copied(),
        bayes_score: response.metrics.get("bayes_score").copied(),
        observer_coherence: response.metrics.get("observer_coherence").copied(),
        graph_density: response.metrics.get("graph_density").copied(),
        beauty_score: response.metrics.get("beauty_score").copied(),
    }
}

pub fn audit_entry_for_response(response: &LabResponse, accepted: bool, reason: &str) -> BoundaryAuditEntry {
    BoundaryAuditEntry {
        timestamp_epoch: now_epoch(),
        request_id: response.request_id.clone(),
        model: response.model.clone(),
        accepted,
        reason: reason.to_owned(),
        metric_keys: response.metrics.keys().cloned().collect(),
    }
}

fn validate_id(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{} darf nicht leer sein", label));
    }
    if value.len() > 128 {
        return Err(format!("{} ist zu lang", label));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!("{} enthaelt unzulaessige Zeichen", label));
    }
    Ok(())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> LabRequest {
        LabRequest {
            schema_version: LAB_SCHEMA_VERSION,
            request_id: "req_123".to_owned(),
            session_id: "sess_123".to_owned(),
            consent_token: "consent_123".to_owned(),
            model: "bayes".to_owned(),
            payload: LabPayload {
                content_hash_hex: "0123456789abcdef0123456789abcdef".to_owned(),
                content_size: 128,
                features: BTreeMap::from([("entropy".to_owned(), 5.1)]),
            },
        }
    }

    fn valid_response() -> LabResponse {
        LabResponse {
            schema_version: LAB_SCHEMA_VERSION,
            request_id: "req_123".to_owned(),
            model: "bayes".to_owned(),
            metrics: BTreeMap::from([
                ("bayes_score".to_owned(), 0.81),
                ("h_lambda".to_owned(), 0.63),
            ]),
            diagnostics: vec!["ok".to_owned()],
        }
    }

    #[test]
    fn request_validation_accepts_valid_payload() {
        assert!(validate_request(&valid_request()).is_ok());
    }

    #[test]
    fn response_validation_rejects_unknown_metric() {
        let mut response = valid_response();
        response.metrics.insert("decision_action".to_owned(), 1.0);
        assert!(validate_response(&response).is_err());
    }

    #[test]
    fn extraction_returns_only_stable_metrics() {
        let response = valid_response();
        let metrics = extract_stable_metrics(&response);
        assert_eq!(metrics.bayes_score, Some(0.81));
        assert_eq!(metrics.h_lambda, Some(0.63));
        assert_eq!(metrics.graph_density, None);
    }
}