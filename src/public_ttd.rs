use chrono::Utc;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::runtime::Builder;
use uuid::Uuid;

pub const PUBLIC_TTD_POOL_SCHEMA: &str = "aether.public_ttd_anchor.pool.v2";
pub const PUBLIC_TTD_QUORUM_DEFAULT: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PublicTtdMetrics {
    pub residual: f32,
    pub symmetry: f32,
    pub i_obs_ratio: f32,
    pub delta_stability: f32,
    pub delta_i_obs_percent: f32,
    pub recursive_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTtdAnchorRecord {
    pub schema: String,
    pub ttd_hash: String,
    pub source_label: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub uploader_pseudonym: String,
    pub uploader_role: String,
    pub validation_pseudonyms: Vec<String>,
    pub validation_count: u32,
    pub signed_validation_count: u32,
    pub public_metrics: PublicTtdMetrics,
    pub latest_metrics: PublicTtdMetrics,
    pub raw_data_included: bool,
    pub deltas_included: bool,
    pub internal_only: bool,
    pub transport_hint: String,
    pub quorum_threshold: u32,
    pub admin_trusted: bool,
    pub quorum_met: bool,
    pub trust_state: String,
    pub trust_reason: String,
    pub trusted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTtdAnchorView {
    pub schema: String,
    pub ttd_hash: String,
    pub source_label: String,
    pub public_metrics: PublicTtdMetrics,
    pub validation_count: u32,
    pub quorum_threshold: u32,
    pub quorum_met: bool,
    pub trust_state: String,
    pub trust_reason: String,
    pub uploader_role: String,
    pub pseudonym: String,
    pub raw_data_included: bool,
    pub deltas_included: bool,
    pub internal_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTtdPoolSummary {
    pub schema: String,
    pub updated_at: String,
    pub anchor_records: Vec<PublicTtdAnchorRecord>,
    pub anchor_record_count: usize,
    pub public_anchors: Vec<PublicTtdAnchorView>,
    pub trusted_anchor_count: usize,
    pub candidate_anchors: Vec<PublicTtdAnchorView>,
    pub candidate_anchor_count: usize,
    pub quorum_validated_count: usize,
    pub admin_trusted_count: usize,
}

#[derive(Debug, Clone)]
pub struct PublicTtdSubmission {
    pub ttd_hash: String,
    pub source_label: String,
    pub public_metrics: PublicTtdMetrics,
    pub pseudonym: String,
    pub uploader_role: String,
    pub signature_included: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTtdCandidateValidation {
    pub valid: bool,
    pub reasons: Vec<String>,
    pub metrics: PublicTtdMetrics,
    pub hash_only: bool,
    pub raw_data_allowed: bool,
    pub deltas_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTtdNetworkSettings {
    pub enabled: bool,
    pub ipfs_api_url: String,
    pub ipfs_gateway_urls: String,
    pub mirror_publish_url: String,
    pub mirror_pull_urls: String,
    pub tracked_cids: String,
    pub timeout_seconds: String,
}

impl Default for PublicTtdNetworkSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            ipfs_api_url: "http://127.0.0.1:5001/api/v0/add?pin=true".to_owned(),
            ipfs_gateway_urls: "http://127.0.0.1:8080/ipfs/\nhttps://ipfs.io/ipfs/".to_owned(),
            mirror_publish_url: String::new(),
            mirror_pull_urls: String::new(),
            tracked_cids: String::new(),
            timeout_seconds: "12".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PublicTtdTransportResult {
    pub published: bool,
    pub network_used: bool,
    pub ipfs: Value,
    pub mirror: Value,
    pub errors: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PublicTtdPullResult {
    pub remote_bundles: Vec<Value>,
    pub errors: Vec<String>,
    pub network_used: bool,
}

pub struct PublicTtdPoolStore {
    records_path: PathBuf,
    summary_path: PathBuf,
}

pub struct PublicTtdTransport {
    settings_path: PathBuf,
}

impl PublicTtdPoolStore {
    pub fn new_default() -> Self {
        let base = PathBuf::from("data")
            .join("rust_shell")
            .join("public_ttd_anchor_pool");
        Self {
            records_path: base.join("anchor_records.json"),
            summary_path: base.join("pool_summary.json"),
        }
    }

    pub fn load_records(&self) -> Vec<PublicTtdAnchorRecord> {
        fs::read_to_string(&self.records_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<PublicTtdAnchorRecord>>(&raw).ok())
            .unwrap_or_default()
    }

    pub fn load_summary(&self) -> PublicTtdPoolSummary {
        if let Ok(raw) = fs::read_to_string(&self.summary_path) {
            if let Ok(summary) = serde_json::from_str::<PublicTtdPoolSummary>(&raw) {
                return summary;
            }
        }
        summarize_public_ttd_anchor_records(&self.load_records())
    }

    pub fn summary_line(&self) -> String {
        let summary = self.load_summary();
        format!(
            "Public TTD Pool | trusted {} | candidate {} | quorum {} | admin {}",
            summary.trusted_anchor_count,
            summary.candidate_anchor_count,
            summary.quorum_validated_count,
            summary.admin_trusted_count
        )
    }

    pub fn submit_validation(
        &self,
        submission: &PublicTtdSubmission,
    ) -> Result<PublicTtdPoolSummary, String> {
        let mut records = self.load_records();
        if let Some(existing) = records
            .iter_mut()
            .find(|record| record.ttd_hash == submission.ttd_hash)
        {
            *existing = merge_public_ttd_anchor_record(existing, submission);
        } else {
            records.push(build_public_ttd_anchor_record(submission));
        }
        self.persist(&records)
    }

    pub fn ingest_remote_bundles(&self, bundles: &[Value]) -> Result<PublicTtdPoolSummary, String> {
        let mut records = self.load_records();
        for bundle in bundles {
            let incoming = extract_records_from_bundle(bundle);
            for record in incoming {
                if let Some(existing) = records
                    .iter_mut()
                    .find(|item| item.ttd_hash == record.ttd_hash)
                {
                    let synthetic = PublicTtdSubmission {
                        ttd_hash: record.ttd_hash.clone(),
                        source_label: record.source_label.clone(),
                        public_metrics: record.latest_metrics.clone(),
                        pseudonym: record.uploader_pseudonym.clone(),
                        uploader_role: record.uploader_role.clone(),
                        signature_included: record.signed_validation_count > 0,
                    };
                    *existing = merge_public_ttd_anchor_record(existing, &synthetic);
                } else {
                    records.push(apply_trust_state(record));
                }
            }
        }
        self.persist(&records)
    }

    fn persist(&self, records: &[PublicTtdAnchorRecord]) -> Result<PublicTtdPoolSummary, String> {
        if let Some(parent) = self.records_path.parent() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let summary = summarize_public_ttd_anchor_records(records);
        fs::write(
            &self.records_path,
            serde_json::to_string_pretty(records).map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())?;
        fs::write(
            &self.summary_path,
            serde_json::to_string_pretty(&summary).map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())?;
        Ok(summary)
    }
}

impl PublicTtdTransport {
    pub fn new_default() -> Self {
        Self {
            settings_path: PathBuf::from("data")
                .join("rust_shell")
                .join("public_ttd_anchor_pool")
                .join("network_settings.json"),
        }
    }

    pub fn load_settings(&self) -> PublicTtdNetworkSettings {
        fs::read_to_string(&self.settings_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<PublicTtdNetworkSettings>(&raw).ok())
            .unwrap_or_default()
    }

    pub fn save_settings(&self, settings: &PublicTtdNetworkSettings) -> Result<(), String> {
        if let Some(parent) = self.settings_path.parent() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        fs::write(
            &self.settings_path,
            serde_json::to_string_pretty(settings).map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())
    }

    pub fn is_enabled(&self) -> bool {
        self.load_settings().enabled
    }

    pub fn publish_bundle(&self, bundle: &Value) -> PublicTtdTransportResult {
        let mut settings = self.load_settings();
        if !settings.enabled {
            return PublicTtdTransportResult {
                published: false,
                network_used: false,
                reason: "network_disabled".to_owned(),
                ..PublicTtdTransportResult::default()
            };
        }
        let timeout = timeout_secs(&settings);
        let mut result = PublicTtdTransportResult::default();

        if !settings.ipfs_api_url.trim().is_empty() {
            result.network_used = true;
            match self.publish_bundle_ipfs(bundle, &settings.ipfs_api_url, timeout) {
                Ok(payload) => {
                    let cid = payload
                        .get("cid")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    result.ipfs = payload;
                    result.published = true;
                    if !cid.is_empty() {
                        let mut tracked = normalized_lines(&settings.tracked_cids);
                        if !tracked.iter().any(|existing| existing == &cid) {
                            tracked.push(cid);
                            let truncated = tracked
                                .iter()
                                .rev()
                                .take(128)
                                .cloned()
                                .collect::<Vec<_>>()
                                .into_iter()
                                .rev()
                                .collect::<Vec<_>>();
                            settings.tracked_cids = truncated.join("\n");
                            let _ = self.save_settings(&settings);
                        }
                    }
                }
                Err(err) => result.errors.push(format!("ipfs: {err}")),
            }
        }

        if !settings.mirror_publish_url.trim().is_empty() {
            result.network_used = true;
            match self.publish_bundle_http(bundle, &settings.mirror_publish_url, timeout) {
                Ok(payload) => {
                    result.mirror = payload;
                    result.published = true;
                }
                Err(err) => result.errors.push(format!("mirror: {err}")),
            }
        }

        if !result.network_used {
            result.reason = "no_transport_configured".to_owned();
        }
        result
    }

    pub fn pull_remote_bundles(&self) -> PublicTtdPullResult {
        let settings = self.load_settings();
        if !settings.enabled {
            return PublicTtdPullResult::default();
        }
        let timeout = timeout_secs(&settings);
        let mut output = PublicTtdPullResult {
            network_used: false,
            ..PublicTtdPullResult::default()
        };

        for url in normalized_lines(&settings.mirror_pull_urls) {
            output.network_used = true;
            match request_json(&url, "GET", None, &[], timeout) {
                Ok(value) => output.remote_bundles.push(value),
                Err(err) => output.errors.push(format!("{url}: {err}")),
            }
        }

        let gateways = normalized_lines(&settings.ipfs_gateway_urls);
        for cid in normalized_lines(&settings.tracked_cids) {
            output.network_used = true;
            let mut loaded = false;
            for gateway in &gateways {
                let url = format!("{}/{}", gateway.trim_end_matches('/'), cid);
                match request_json(&url, "GET", None, &[], timeout) {
                    Ok(value) => {
                        output.remote_bundles.push(value);
                        loaded = true;
                        break;
                    }
                    Err(err) => output.errors.push(format!("{cid}: {err}")),
                }
            }
            if !loaded && gateways.is_empty() {
                output.errors.push(format!("{cid}: no_gateway_configured"));
            }
        }
        output
    }

    fn publish_bundle_http(
        &self,
        bundle: &Value,
        publish_url: &str,
        timeout: f32,
    ) -> Result<Value, String> {
        request_json(
            publish_url,
            "POST",
            Some(serde_json::to_vec(bundle).map_err(|err| err.to_string())?),
            &[("Content-Type", "application/json; charset=utf-8")],
            timeout,
        )
    }

    fn publish_bundle_ipfs(
        &self,
        bundle: &Value,
        ipfs_api_url: &str,
        timeout: f32,
    ) -> Result<Value, String> {
        let payload = serde_json::to_vec_pretty(bundle).map_err(|err| err.to_string())?;
        let boundary = format!("----AetherBoundary{}", Uuid::new_v4().simple());
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"file\"; filename=\"aether_public_ttd_anchor.json\"\r\n");
        body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
        body.extend_from_slice(&payload);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let content_type = format!("multipart/form-data; boundary={boundary}");
        let raw = request_raw(
            ipfs_api_url,
            "POST",
            Some(body),
            &[(CONTENT_TYPE.as_str(), content_type.as_str())],
            timeout,
        )?;
        let text = String::from_utf8_lossy(&raw);
        let json_line = text
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("{}");
        let decoded: Value = serde_json::from_str(json_line).map_err(|err| err.to_string())?;
        let cid = decoded
            .get("Hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if cid.is_empty() {
            return Err("ipfs_no_cid".to_owned());
        }
        Ok(json!({
            "ok": true,
            "transport": "ipfs_api",
            "cid": cid,
            "response": decoded,
        }))
    }
}

pub fn validate_public_ttd_candidate(
    metrics: PublicTtdMetrics,
    anomaly_count: u32,
    boundary: &str,
    lossless_verified: bool,
) -> PublicTtdCandidateValidation {
    let metrics = canonical_metrics(metrics);
    let mut reasons = Vec::new();
    if metrics.residual >= 0.05 {
        reasons.push(format!("residual {:.3} >= 0.050", metrics.residual));
    }
    if metrics.symmetry <= 0.90 {
        reasons.push(format!("symmetry {:.3} <= 0.900", metrics.symmetry));
    }
    if metrics.i_obs_ratio <= 0.90 {
        reasons.push(format!("i_obs_ratio {:.3} <= 0.900", metrics.i_obs_ratio));
    }
    if metrics.delta_stability <= 0.90 {
        reasons.push(format!(
            "delta_stability {:.3} <= 0.900",
            metrics.delta_stability
        ));
    }
    if metrics.recursive_count < 3 {
        reasons.push(format!("recursive_count {} < 3", metrics.recursive_count));
    }
    if boundary.eq_ignore_ascii_case("GOEDEL_LIMIT") {
        reasons.push("boundary GOEDEL_LIMIT".to_owned());
    }
    if anomaly_count > 0 {
        reasons.push(format!("anomaly_count {anomaly_count} > 0"));
    }
    if !lossless_verified {
        reasons.push("reconstruction_verification failed".to_owned());
    }
    PublicTtdCandidateValidation {
        valid: reasons.is_empty(),
        reasons,
        metrics,
        hash_only: true,
        raw_data_allowed: false,
        deltas_allowed: false,
    }
}

pub fn pseudonymous_network_identity(material: &str, purpose: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    hasher.update(b"|");
    hasher.update(purpose.as_bytes());
    let digest = hasher.finalize();
    digest[..12]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>()
}

pub fn summarize_public_ttd_anchor_records(
    records: &[PublicTtdAnchorRecord],
) -> PublicTtdPoolSummary {
    let normalized = records
        .iter()
        .cloned()
        .map(apply_trust_state)
        .collect::<Vec<_>>();
    let trusted_records = normalized
        .iter()
        .filter(|record| record.quorum_met)
        .cloned()
        .collect::<Vec<_>>();
    let candidate_records = normalized
        .iter()
        .filter(|record| !record.quorum_met)
        .cloned()
        .collect::<Vec<_>>();
    let public_anchors = trusted_records
        .iter()
        .map(public_ttd_anchor_view)
        .collect::<Vec<_>>();
    let candidate_anchors = candidate_records
        .iter()
        .map(public_ttd_anchor_view)
        .collect::<Vec<_>>();
    let quorum_validated_count = trusted_records
        .iter()
        .filter(|record| record.trust_reason == "peer_quorum_met")
        .count();
    let admin_trusted_count = trusted_records
        .iter()
        .filter(|record| record.admin_trusted)
        .count();
    PublicTtdPoolSummary {
        schema: PUBLIC_TTD_POOL_SCHEMA.to_owned(),
        updated_at: utc_now(),
        anchor_records: normalized.clone(),
        anchor_record_count: normalized.len(),
        public_anchors,
        trusted_anchor_count: trusted_records.len(),
        candidate_anchors,
        candidate_anchor_count: candidate_records.len(),
        quorum_validated_count,
        admin_trusted_count,
    }
}

fn build_public_ttd_anchor_record(submission: &PublicTtdSubmission) -> PublicTtdAnchorRecord {
    let validators = if submission.pseudonym.trim().is_empty() {
        Vec::new()
    } else {
        vec![submission.pseudonym.trim().to_owned()]
    };
    apply_trust_state(PublicTtdAnchorRecord {
        schema: "aether.public_ttd_anchor.record.v1".to_owned(),
        ttd_hash: submission.ttd_hash.clone(),
        source_label: submission.source_label.clone(),
        first_seen_at: utc_now(),
        last_seen_at: utc_now(),
        uploader_pseudonym: submission.pseudonym.clone(),
        uploader_role: normalize_public_role(&submission.uploader_role),
        validation_pseudonyms: validators.clone(),
        validation_count: validators.len() as u32,
        signed_validation_count: if submission.signature_included { 1 } else { 0 },
        public_metrics: canonical_metrics(submission.public_metrics.clone()),
        latest_metrics: canonical_metrics(submission.public_metrics.clone()),
        raw_data_included: false,
        deltas_included: false,
        internal_only: false,
        transport_hint: "ipfs_libp2p_bundle".to_owned(),
        quorum_threshold: quorum_threshold_for_role(&submission.uploader_role),
        admin_trusted: false,
        quorum_met: false,
        trust_state: "candidate".to_owned(),
        trust_reason: "peer_quorum_pending".to_owned(),
        trusted_at: None,
    })
}

fn merge_public_ttd_anchor_record(
    record: &PublicTtdAnchorRecord,
    submission: &PublicTtdSubmission,
) -> PublicTtdAnchorRecord {
    let mut validators = record.validation_pseudonyms.clone();
    let pseudonym = submission.pseudonym.trim();
    if !pseudonym.is_empty() && !validators.iter().any(|existing| existing == pseudonym) {
        validators.push(pseudonym.to_owned());
    }
    let previous_count = record.validation_count.max(1) as f32;
    let incoming = canonical_metrics(submission.public_metrics.clone());
    let current = canonical_metrics(record.public_metrics.clone());
    let merged_metrics = PublicTtdMetrics {
        residual: (((current.residual * previous_count) + incoming.residual)
            / (previous_count + 1.0))
            .clamp(0.0, 1.0),
        symmetry: (((current.symmetry * previous_count) + incoming.symmetry)
            / (previous_count + 1.0))
            .clamp(0.0, 1.0),
        i_obs_ratio: (((current.i_obs_ratio * previous_count) + incoming.i_obs_ratio)
            / (previous_count + 1.0))
            .clamp(0.0, 1.0),
        delta_stability: (((current.delta_stability * previous_count) + incoming.delta_stability)
            / (previous_count + 1.0))
            .clamp(0.0, 1.0),
        delta_i_obs_percent: (((current.delta_i_obs_percent * previous_count)
            + incoming.delta_i_obs_percent)
            / (previous_count + 1.0))
            .clamp(0.0, 100.0),
        recursive_count: current.recursive_count.max(incoming.recursive_count),
    };
    apply_trust_state(PublicTtdAnchorRecord {
        schema: record.schema.clone(),
        ttd_hash: record.ttd_hash.clone(),
        source_label: if submission.source_label.trim().is_empty() {
            record.source_label.clone()
        } else {
            submission.source_label.clone()
        },
        first_seen_at: record.first_seen_at.clone(),
        last_seen_at: utc_now(),
        uploader_pseudonym: if record.uploader_pseudonym.is_empty() {
            submission.pseudonym.clone()
        } else {
            record.uploader_pseudonym.clone()
        },
        uploader_role: normalize_public_role(&record.uploader_role),
        validation_pseudonyms: validators.clone(),
        validation_count: validators.len() as u32,
        signed_validation_count: record.signed_validation_count
            + u32::from(submission.signature_included && !pseudonym.is_empty()),
        public_metrics: canonical_metrics(merged_metrics),
        latest_metrics: incoming,
        raw_data_included: false,
        deltas_included: false,
        internal_only: false,
        transport_hint: record.transport_hint.clone(),
        quorum_threshold: quorum_threshold_for_role(&record.uploader_role),
        admin_trusted: false,
        quorum_met: false,
        trust_state: "candidate".to_owned(),
        trust_reason: "peer_quorum_pending".to_owned(),
        trusted_at: record.trusted_at.clone(),
    })
}

fn apply_trust_state(mut record: PublicTtdAnchorRecord) -> PublicTtdAnchorRecord {
    record.uploader_role = normalize_public_role(&record.uploader_role);
    record.quorum_threshold = quorum_threshold_for_role(&record.uploader_role);
    record.validation_count = record.validation_pseudonyms.len() as u32;
    record.admin_trusted = record.uploader_role == "admin";
    record.quorum_met = record.admin_trusted || record.validation_count >= record.quorum_threshold;
    record.trust_reason = if record.admin_trusted {
        "admin_auto_trust".to_owned()
    } else if record.quorum_met {
        "peer_quorum_met".to_owned()
    } else {
        "peer_quorum_pending".to_owned()
    };
    record.trust_state = if record.quorum_met {
        "trusted"
    } else {
        "candidate"
    }
    .to_owned();
    if record.quorum_met && record.trusted_at.as_deref().unwrap_or_default().is_empty() {
        record.trusted_at = Some(utc_now());
    }
    record.raw_data_included = false;
    record.deltas_included = false;
    record.internal_only = false;
    record.public_metrics = canonical_metrics(record.public_metrics);
    record.latest_metrics = canonical_metrics(record.latest_metrics);
    record
}

fn public_ttd_anchor_view(record: &PublicTtdAnchorRecord) -> PublicTtdAnchorView {
    PublicTtdAnchorView {
        schema: "aether.public_ttd_anchor.v1".to_owned(),
        ttd_hash: record.ttd_hash.clone(),
        source_label: record.source_label.clone(),
        public_metrics: canonical_metrics(record.public_metrics.clone()),
        validation_count: record.validation_count,
        quorum_threshold: record.quorum_threshold,
        quorum_met: record.quorum_met,
        trust_state: record.trust_state.clone(),
        trust_reason: record.trust_reason.clone(),
        uploader_role: record.uploader_role.clone(),
        pseudonym: record.uploader_pseudonym.clone(),
        raw_data_included: false,
        deltas_included: false,
        internal_only: false,
    }
}

fn extract_records_from_bundle(bundle: &Value) -> Vec<PublicTtdAnchorRecord> {
    if let Some(array) = bundle.get("anchor_records").and_then(Value::as_array) {
        return array
            .iter()
            .filter_map(|item| serde_json::from_value::<PublicTtdAnchorRecord>(item.clone()).ok())
            .collect::<Vec<_>>();
    }
    if let Ok(record) = serde_json::from_value::<PublicTtdAnchorRecord>(bundle.clone()) {
        return vec![record];
    }
    if let Some(anchor) = bundle.get("anchor") {
        if let Ok(view) = serde_json::from_value::<PublicTtdAnchorView>(anchor.clone()) {
            return vec![apply_trust_state(PublicTtdAnchorRecord {
                schema: "aether.public_ttd_anchor.record.v1".to_owned(),
                ttd_hash: view.ttd_hash,
                source_label: view.source_label,
                first_seen_at: utc_now(),
                last_seen_at: utc_now(),
                uploader_pseudonym: view.pseudonym,
                uploader_role: view.uploader_role,
                validation_pseudonyms: Vec::new(),
                validation_count: view.validation_count,
                signed_validation_count: 0,
                public_metrics: view.public_metrics.clone(),
                latest_metrics: view.public_metrics,
                raw_data_included: false,
                deltas_included: false,
                internal_only: false,
                transport_hint: "ipfs_libp2p_bundle".to_owned(),
                quorum_threshold: view.quorum_threshold,
                admin_trusted: false,
                quorum_met: view.quorum_met,
                trust_state: view.trust_state,
                trust_reason: view.trust_reason,
                trusted_at: None,
            })];
        }
    }
    Vec::new()
}

fn normalize_public_role(role: &str) -> String {
    if role.trim().eq_ignore_ascii_case("admin") {
        "admin".to_owned()
    } else {
        "operator".to_owned()
    }
}

fn quorum_threshold_for_role(role: &str) -> u32 {
    if normalize_public_role(role) == "admin" {
        1
    } else {
        PUBLIC_TTD_QUORUM_DEFAULT
    }
}

fn canonical_metrics(metrics: PublicTtdMetrics) -> PublicTtdMetrics {
    PublicTtdMetrics {
        residual: (metrics.residual * 1_000_000.0).round() / 1_000_000.0,
        symmetry: (metrics.symmetry * 1_000_000.0).round() / 1_000_000.0,
        i_obs_ratio: (metrics.i_obs_ratio * 1_000_000.0).round() / 1_000_000.0,
        delta_stability: (metrics.delta_stability * 1_000_000.0).round() / 1_000_000.0,
        delta_i_obs_percent: (metrics.delta_i_obs_percent * 1_000_000.0).round() / 1_000_000.0,
        recursive_count: metrics.recursive_count,
    }
}

fn utc_now() -> String {
    Utc::now().to_rfc3339()
}

fn normalized_lines(value: &str) -> Vec<String> {
    value
        .replace(',', "\n")
        .lines()
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn timeout_secs(settings: &PublicTtdNetworkSettings) -> f32 {
    settings
        .timeout_seconds
        .trim()
        .parse::<f32>()
        .ok()
        .map(|value| value.clamp(2.0, 60.0))
        .unwrap_or(12.0)
}

fn request_json(
    url: &str,
    method: &str,
    body: Option<Vec<u8>>,
    headers: &[(&str, &str)],
    timeout: f32,
) -> Result<Value, String> {
    let raw = request_raw(url, method, body, headers, timeout)?;
    serde_json::from_slice::<Value>(&raw).map_err(|err| err.to_string())
}

fn request_raw(
    url: &str,
    method: &str,
    body: Option<Vec<u8>>,
    headers: &[(&str, &str)],
    timeout: f32,
) -> Result<Vec<u8>, String> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs_f32(timeout.max(1.0)))
            .build()
            .map_err(|err| err.to_string())?;
        let mut request = client.request(method.parse().unwrap_or(reqwest::Method::GET), url);
        if let Some(payload) = body {
            request = request.body(payload);
        }
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        request
            .send()
            .await
            .map_err(|err| err.to_string())?
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|err| err.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_validation_rejects_unstable_metrics() {
        let validation = validate_public_ttd_candidate(
            PublicTtdMetrics {
                residual: 0.12,
                symmetry: 0.8,
                i_obs_ratio: 0.7,
                delta_stability: 0.5,
                delta_i_obs_percent: 0.0,
                recursive_count: 1,
            },
            1,
            "GOEDEL_LIMIT",
            false,
        );
        assert!(!validation.valid);
        assert!(!validation.reasons.is_empty());
    }

    #[test]
    fn quorum_promotes_operator_record_after_three_validations() {
        let submission = PublicTtdSubmission {
            ttd_hash: "abc".to_owned(),
            source_label: "demo".to_owned(),
            public_metrics: PublicTtdMetrics {
                residual: 0.01,
                symmetry: 0.95,
                i_obs_ratio: 0.95,
                delta_stability: 0.96,
                delta_i_obs_percent: 1.2,
                recursive_count: 4,
            },
            pseudonym: "P1".to_owned(),
            uploader_role: "operator".to_owned(),
            signature_included: false,
        };
        let first = build_public_ttd_anchor_record(&submission);
        assert!(!first.quorum_met);
        let second = merge_public_ttd_anchor_record(
            &first,
            &PublicTtdSubmission {
                pseudonym: "P2".to_owned(),
                ..submission.clone()
            },
        );
        assert!(!second.quorum_met);
        let third = merge_public_ttd_anchor_record(
            &second,
            &PublicTtdSubmission {
                pseudonym: "P3".to_owned(),
                ..submission
            },
        );
        assert!(third.quorum_met);
        assert_eq!(third.trust_state, "trusted");
    }
}
