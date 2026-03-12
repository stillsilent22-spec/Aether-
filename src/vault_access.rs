use crate::aef::{engine_flags, EnginePipeline, SignalType, VaultStore};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionSource {
    Local,
    GitHubPR,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawAnchorSubmission {
    pub anchor_id: Uuid,
    pub signal_type: SignalType,
    pub domain: String,
    pub pi_positions: Vec<u64>,
    pub frequency_signature: Vec<f32>,
    pub fractal_dimension: f64,
    pub entropy_profile: f64,
    pub benford_score: f32,
    pub zipf_alpha: f32,
    pub coherence_index: f64,
    pub lossless_confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustResult {
    pub score: f32,
    pub flags: u64,
    pub heisenberg_fail: bool,
    pub noether_fail: bool,
    pub coherence_index: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorCommitResult {
    pub anchor_id: Uuid,
    pub vault_ref: [u8; 32],
    pub trust_score: f32,
    pub engine_flags: u64,
    pub coherence_index: f64,
    pub lossless_confirmed: bool,
    pub record: PublicAnchorRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAnchor {
    pub vault_ref: [u8; 32],
    pub record: PublicAnchorRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicAnchorRecord {
    pub anchor_id: Uuid,
    pub vault_ref: String,
    pub signal_type: SignalType,
    pub domain: String,
    pub pi_positions: Vec<u64>,
    pub frequency_signature: Vec<f32>,
    pub fractal_dimension: f64,
    pub entropy_profile: f64,
    pub benford_score: f32,
    pub zipf_alpha: f32,
    pub coherence_index: f64,
    pub trust_score: f32,
    pub engine_flags: u64,
    pub lossless_confirmed: bool,
    pub created_at: u64,
    pub aether_version: String,
    pub shanway_signature: String,
    pub vault_version: u64,
    pub genesis_block_ref: String,
}

#[derive(Debug)]
pub enum VaultAccessError {
    HardFail(TrustResult),
    TrustScoreTooLow(f32),
    InvalidSignature,
    DatabaseError(String),
    PipelineError(String),
    PushError(String),
}

#[derive(Debug)]
pub enum PushError {
    Serialization(String),
    Io(String),
    Http(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub anchor_id: Uuid,
    pub signature_valid: bool,
    pub trust_score: f32,
    pub engine_flags: u64,
    pub bayes_consistent: bool,
    pub approved: bool,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSyncResult {
    pub anchors_synced: usize,
    pub anchors_rejected: usize,
    pub new_vault_size: usize,
    pub estimated_hit_rate_improvement: f32,
    pub estimated_compression_improvement: f32,
}

pub struct VaultAccessLayer {
    db: Arc<RwLock<VaultStore>>,
    engine_pipeline: Arc<EnginePipeline>,
}

impl VaultAccessLayer {
    pub fn new(db: Arc<RwLock<VaultStore>>, engine_pipeline: Arc<EnginePipeline>) -> Self {
        Self { db, engine_pipeline }
    }

    pub async fn submit_anchor(
        &self,
        anchor: RawAnchorSubmission,
        source: SubmissionSource,
    ) -> Result<AnchorCommitResult, VaultAccessError> {
        self.submit_anchor_sync(anchor, source)
    }

    pub fn submit_anchor_sync(
        &self,
        anchor: RawAnchorSubmission,
        source: SubmissionSource,
    ) -> Result<AnchorCommitResult, VaultAccessError> {
        let trust_result = self.run_all(&anchor)?;
        if trust_result.heisenberg_fail || trust_result.noether_fail {
            return Err(VaultAccessError::HardFail(trust_result));
        }
        if trust_result.score < 0.65 {
            return Err(VaultAccessError::TrustScoreTooLow(trust_result.score));
        }

        let (vault_version, genesis_block_ref) = {
            let vault = self
                .db
                .read()
                .map_err(|_| VaultAccessError::DatabaseError("Vault-Lock konnte nicht gelesen werden".to_owned()))?;
            (vault.version(), vault.genesis_block_ref())
        };
        let unsigned_record = PublicAnchorRecord {
            anchor_id: anchor.anchor_id,
            vault_ref: hex_encode(&sha256_bytes(&canonical_anchor_bytes(&anchor))),
            signal_type: anchor.signal_type,
            domain: anchor.domain.clone(),
            pi_positions: anchor.pi_positions.clone(),
            frequency_signature: anchor.frequency_signature.clone(),
            fractal_dimension: anchor.fractal_dimension,
            entropy_profile: anchor.entropy_profile,
            benford_score: anchor.benford_score,
            zipf_alpha: anchor.zipf_alpha,
            coherence_index: trust_result.coherence_index,
            trust_score: trust_result.score,
            engine_flags: trust_result.flags,
            lossless_confirmed: anchor.lossless_confirmed,
            created_at: Utc::now().timestamp() as u64,
            aether_version: "vera_aether_core_rust_shell".to_owned(),
            shanway_signature: String::new(),
            vault_version,
            genesis_block_ref: hex_encode(&genesis_block_ref),
        };
        let signed_record = self.sign_record(unsigned_record)?;
        let commit_bytes = serde_json::to_vec_pretty(&signed_record)
            .map_err(|err| VaultAccessError::DatabaseError(format!("Commit konnte nicht serialisiert werden: {err}")))?;
        let vault_ref = {
            let mut vault = self
                .db
                .write()
                .map_err(|_| VaultAccessError::DatabaseError("Vault-Lock konnte nicht geschrieben werden".to_owned()))?;
            vault
                .upsert(&commit_bytes, anchor.signal_type)
                .map_err(|err| VaultAccessError::DatabaseError(err.to_string()))?
        };

        let commit = AnchorCommitResult {
            anchor_id: signed_record.anchor_id,
            vault_ref,
            trust_score: signed_record.trust_score,
            engine_flags: signed_record.engine_flags,
            coherence_index: signed_record.coherence_index,
            lossless_confirmed: signed_record.lossless_confirmed,
            record: signed_record,
        };
        if source == SubmissionSource::Local {
            self.enqueue_github_push_sync(&commit)
                .map_err(|err| VaultAccessError::PushError(err.to_string()))?;
        }
        Ok(commit)
    }

    pub async fn lookup_anchor(&self, hash: &[u8; 32]) -> Result<Option<VaultAnchor>, VaultAccessError> {
        let raw = {
            let vault = self
                .db
                .read()
                .map_err(|_| VaultAccessError::DatabaseError("Vault-Lock konnte nicht gelesen werden".to_owned()))?;
            vault.get(hash)
        };
        let Some(raw) = raw else {
            return Ok(None);
        };
        let record: PublicAnchorRecord = serde_json::from_slice(&raw)
            .map_err(|err| VaultAccessError::DatabaseError(format!("Vault-Record ungueltig: {err}")))?;
        Ok(Some(VaultAnchor {
            vault_ref: *hash,
            record,
        }))
    }

    pub fn enqueue_github_push_sync(&self, commit: &AnchorCommitResult) -> Result<(), PushError> {
        let queue_dir = PathBuf::from("data").join("rust_shell").join("public_push_queue");
        fs::create_dir_all(&queue_dir).map_err(|err| PushError::Io(err.to_string()))?;
        let raw = serde_json::to_string_pretty(&commit.record)
            .map_err(|err| PushError::Serialization(err.to_string()))?;
        let file_path = queue_dir.join(format!("{}.json", commit.anchor_id));
        fs::write(file_path, raw).map_err(|err| PushError::Io(err.to_string()))?;
        Ok(())
    }

    fn sign_record(&self, mut record: PublicAnchorRecord) -> Result<PublicAnchorRecord, VaultAccessError> {
        let payload = serde_json::to_vec(&record)
            .map_err(|err| VaultAccessError::PipelineError(format!("Signatur-Payload ungueltig: {err}")))?;
        let signature = self.engine_pipeline.sign(&payload);
        record.shanway_signature = BASE64.encode(signature);
        Ok(record)
    }

    pub fn verify_record_signature(&self, record: &PublicAnchorRecord) -> Result<(), VaultAccessError> {
        let mut unsigned = record.clone();
        unsigned.shanway_signature.clear();
        let payload = serde_json::to_vec(&unsigned)
            .map_err(|err| VaultAccessError::PipelineError(format!("Signaturpruefung fehlgeschlagen: {err}")))?;
        let raw = BASE64
            .decode(&record.shanway_signature)
            .map_err(|_| VaultAccessError::InvalidSignature)?;
        if raw.len() != 64 {
            return Err(VaultAccessError::InvalidSignature);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw[..64]);
        self.engine_pipeline
            .verify(&payload, &signature)
            .map_err(|_| VaultAccessError::InvalidSignature)
    }

    pub fn verify_anchor_record(&self, record: &PublicAnchorRecord) -> Result<VerificationResult, VaultAccessError> {
        self.verify_record_signature(record)?;
        let submission = RawAnchorSubmission {
            anchor_id: record.anchor_id,
            signal_type: record.signal_type,
            domain: record.domain.clone(),
            pi_positions: record.pi_positions.clone(),
            frequency_signature: record.frequency_signature.clone(),
            fractal_dimension: record.fractal_dimension,
            entropy_profile: record.entropy_profile,
            benford_score: record.benford_score,
            zipf_alpha: record.zipf_alpha,
            coherence_index: record.coherence_index,
            lossless_confirmed: record.lossless_confirmed,
        };
        let trust = self.run_all(&submission)?;
        let bayes_consistent = trust.score + 0.05 >= record.trust_score;
        let hard_fail = trust.heisenberg_fail || trust.noether_fail;
        let approved = !hard_fail && trust.score >= 0.65 && bayes_consistent;
        Ok(VerificationResult {
            anchor_id: record.anchor_id,
            signature_valid: true,
            trust_score: trust.score,
            engine_flags: trust.flags,
            bayes_consistent,
            approved,
            rejection_reason: if approved {
                None
            } else if hard_fail {
                Some("Hard-Fail durch Heisenberg/Noether".to_owned())
            } else if !bayes_consistent {
                Some("Bayes-Widerspruch zum lokalen Vault".to_owned())
            } else {
                Some("Trust Score unter 0.65".to_owned())
            },
        })
    }

    fn run_all(&self, anchor: &RawAnchorSubmission) -> Result<TrustResult, VaultAccessError> {
        let symmetry_index = derive_symmetry_index(anchor);
        let heisenberg_fail = anchor.entropy_profile > 8.0 || anchor.fractal_dimension <= 0.0;
        let noether_fail = symmetry_index < 0.35;
        let mut flags = 0u64;
        if !heisenberg_fail {
            flags |= engine_flags::HEISENBERG;
        }
        if !noether_fail {
            flags |= engine_flags::NOETHER;
        }
        if anchor.benford_score >= 0.30 {
            flags |= engine_flags::BENFORD;
        }
        if anchor.fractal_dimension >= 1.10 && anchor.fractal_dimension <= 2.40 {
            flags |= engine_flags::MANDELBROT;
        }
        if anchor.entropy_profile > 0.0 && anchor.entropy_profile <= 8.0 {
            flags |= engine_flags::SHANNON;
        }
        if derive_fourier_score(anchor) >= 0.25 {
            flags |= engine_flags::FOURIER;
        }
        if derive_bayes_score(anchor) >= 0.40 {
            flags |= engine_flags::BAYES;
        }
        let score = ((0.22 * symmetry_index)
            + (0.12 * anchor.benford_score.clamp(0.0, 1.0))
            + (0.12 * derive_mandelbrot_score(anchor))
            + (0.12 * derive_fourier_score(anchor))
            + (0.18 * derive_bayes_score(anchor))
            + (0.24 * anchor.coherence_index.clamp(0.0, 1.0) as f32))
            .clamp(0.0, 1.0);
        Ok(TrustResult {
            score,
            flags,
            heisenberg_fail,
            noether_fail,
            coherence_index: anchor.coherence_index.clamp(0.0, 1.0),
        })
    }
}

pub struct GitHubPushPipeline {
    pub repo_url: String,
    pub branch: String,
    pub git_token: String,
    pub client: Client,
}

impl GitHubPushPipeline {
    pub fn new(repo_url: impl Into<String>, branch: impl Into<String>, git_token: impl Into<String>) -> Self {
        Self {
            repo_url: repo_url.into(),
            branch: branch.into(),
            git_token: git_token.into(),
            client: Client::new(),
        }
    }

    pub async fn push_anchor(&self, commit: &AnchorCommitResult) -> Result<(), PushError> {
        let record = commit.record.clone();
        let path = format!("vault/anchors/{}/{}.json", sanitize_domain(&record.domain), record.anchor_id);
        let json = serde_json::to_string_pretty(&record)
            .map_err(|err| PushError::Serialization(err.to_string()))?;
        self.github_put_file(
            &path,
            &json,
            &format!("anchor: add {} [trust={:.2}]", record.anchor_id, record.trust_score),
        )
        .await?;
        self.update_index(&record).await?;
        self.update_manifest(&record).await?;
        Ok(())
    }

    async fn github_put_file(&self, path: &str, raw_json: &str, message: &str) -> Result<(), PushError> {
        let Some((owner, repo)) = parse_repo(&self.repo_url) else {
            return Err(PushError::Http("repo_url ist ungueltig".to_owned()));
        };
        let url = format!("https://api.github.com/repos/{owner}/{repo}/contents/{path}");
        let body = serde_json::json!({
            "message": message,
            "branch": self.branch,
            "content": BASE64.encode(raw_json.as_bytes()),
        });
        let response = self
            .client
            .put(url)
            .bearer_auth(&self.git_token)
            .header("User-Agent", "Aether-Rust-Shell")
            .json(&body)
            .send()
            .await
            .map_err(|err| PushError::Http(err.to_string()))?;
        if !response.status().is_success() {
            return Err(PushError::Http(format!("GitHub PUT fehlgeschlagen: {}", response.status())));
        }
        Ok(())
    }

    async fn update_index(&self, record: &PublicAnchorRecord) -> Result<(), PushError> {
        let index_dir = PathBuf::from("data").join("rust_shell").join("github_preview");
        fs::create_dir_all(&index_dir).map_err(|err| PushError::Io(err.to_string()))?;
        let index_path = index_dir.join("index.json");
        let mut index: Vec<BTreeMap<String, String>> = if index_path.exists() {
            serde_json::from_str(&fs::read_to_string(&index_path).map_err(|err| PushError::Io(err.to_string()))?)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        index.push(BTreeMap::from([
            ("anchor_id".to_owned(), record.anchor_id.to_string()),
            ("vault_ref".to_owned(), record.vault_ref.clone()),
            ("domain".to_owned(), record.domain.clone()),
        ]));
        let raw = serde_json::to_string_pretty(&index).map_err(|err| PushError::Serialization(err.to_string()))?;
        fs::write(index_path, raw).map_err(|err| PushError::Io(err.to_string()))?;
        Ok(())
    }

    async fn update_manifest(&self, record: &PublicAnchorRecord) -> Result<(), PushError> {
        let manifest_dir = PathBuf::from("data").join("rust_shell").join("github_preview");
        fs::create_dir_all(&manifest_dir).map_err(|err| PushError::Io(err.to_string()))?;
        let manifest_path = manifest_dir.join("vault_manifest.json");
        let mut distribution: BTreeMap<String, usize> = BTreeMap::new();
        distribution.insert(record.domain.clone(), 1);
        let manifest = serde_json::json!({
            "vault_version": record.vault_version,
            "genesis_block_ref": record.genesis_block_ref,
            "anchor_count": 1,
            "domain_distribution": distribution,
            "last_updated": Utc::now().timestamp(),
            "aether_version": record.aether_version,
        });
        let raw = serde_json::to_string_pretty(&manifest).map_err(|err| PushError::Serialization(err.to_string()))?;
        fs::write(manifest_path, raw).map_err(|err| PushError::Io(err.to_string()))?;
        Ok(())
    }
}

pub async fn sync_public_vault(
    access_layer: &VaultAccessLayer,
    repo_root: &Path,
    since_vault_version: u64,
) -> Result<VaultSyncResult, VaultAccessError> {
    let anchor_root = repo_root.join("vault").join("anchors");
    if !anchor_root.exists() {
        return Ok(VaultSyncResult {
            anchors_synced: 0,
            anchors_rejected: 0,
            new_vault_size: access_layer.db.read().map_err(|_| VaultAccessError::DatabaseError("Vault-Lock konnte nicht gelesen werden".to_owned()))?.entry_count(),
            estimated_hit_rate_improvement: 0.0,
            estimated_compression_improvement: 0.0,
        });
    }
    let mut synced = 0usize;
    let mut rejected = 0usize;
    for file in walk_json_files(&anchor_root) {
        let raw = fs::read_to_string(&file)
            .map_err(|err| VaultAccessError::PipelineError(format!("Public-Anchor konnte nicht gelesen werden: {err}")))?;
        let record: PublicAnchorRecord = serde_json::from_str(&raw)
            .map_err(|err| VaultAccessError::PipelineError(format!("Public-Anchor JSON ungueltig: {err}")))?;
        if record.vault_version <= since_vault_version {
            continue;
        }
        match access_layer.verify_anchor_record(&record) {
            Ok(result) if result.approved => {
                let submission = RawAnchorSubmission {
                    anchor_id: record.anchor_id,
                    signal_type: record.signal_type,
                    domain: record.domain.clone(),
                    pi_positions: record.pi_positions.clone(),
                    frequency_signature: record.frequency_signature.clone(),
                    fractal_dimension: record.fractal_dimension,
                    entropy_profile: record.entropy_profile,
                    benford_score: record.benford_score,
                    zipf_alpha: record.zipf_alpha,
                    coherence_index: record.coherence_index,
                    lossless_confirmed: record.lossless_confirmed,
                };
                let _ = access_layer.submit_anchor_sync(submission, SubmissionSource::GitHubPR)?;
                synced += 1;
            }
            _ => rejected += 1,
        }
    }
    let new_size = access_layer
        .db
        .read()
        .map_err(|_| VaultAccessError::DatabaseError("Vault-Lock konnte nicht gelesen werden".to_owned()))?
        .entry_count();
    Ok(VaultSyncResult {
        anchors_synced: synced,
        anchors_rejected: rejected,
        new_vault_size: new_size,
        estimated_hit_rate_improvement: ((synced as f32 / new_size.max(1) as f32) * 100.0).clamp(0.0, 100.0),
        estimated_compression_improvement: ((synced as f32 / (new_size.max(1) as f32 * 2.0)) * 100.0).clamp(0.0, 100.0),
    })
}

fn walk_json_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walk_json_files(&path));
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                files.push(path);
            }
        }
    }
    files
}

fn canonical_anchor_bytes(anchor: &RawAnchorSubmission) -> Vec<u8> {
    serde_json::to_vec(anchor).unwrap_or_default()
}

fn derive_symmetry_index(anchor: &RawAnchorSubmission) -> f32 {
    let repeat_factor = (anchor.pi_positions.len() as f32 / 8.0).clamp(0.0, 1.0);
    let benford = anchor.benford_score.clamp(0.0, 1.0);
    let fractal = (1.0 - ((anchor.fractal_dimension as f32 - 1.5).abs() / 1.5)).clamp(0.0, 1.0);
    ((0.42 * benford) + (0.28 * fractal) + (0.30 * repeat_factor)).clamp(0.0, 1.0)
}

fn derive_fourier_score(anchor: &RawAnchorSubmission) -> f32 {
    if anchor.frequency_signature.is_empty() {
        return 0.0;
    }
    let mean = anchor.frequency_signature.iter().copied().sum::<f32>() / anchor.frequency_signature.len() as f32;
    let variance = anchor
        .frequency_signature
        .iter()
        .map(|value| {
            let delta = *value - mean;
            delta * delta
        })
        .sum::<f32>()
        / anchor.frequency_signature.len() as f32;
    (1.0 - variance.sqrt().min(1.0)).clamp(0.0, 1.0)
}

fn derive_mandelbrot_score(anchor: &RawAnchorSubmission) -> f32 {
    (1.0 - ((anchor.fractal_dimension as f32 - 1.5).abs() / 1.5)).clamp(0.0, 1.0)
}

fn derive_bayes_score(anchor: &RawAnchorSubmission) -> f32 {
    let pi = (anchor.pi_positions.len() as f32 / 16.0).clamp(0.0, 1.0);
    let frequency = (anchor.frequency_signature.len() as f32 / 16.0).clamp(0.0, 1.0);
    let coherence = anchor.coherence_index.clamp(0.0, 1.0) as f32;
    ((0.34 * pi) + (0.26 * frequency) + (0.40 * coherence)).clamp(0.0, 1.0)
}

fn parse_repo(repo_url: &str) -> Option<(String, String)> {
    let trimmed = repo_url.trim().trim_end_matches(".git");
    if let Some(rest) = trimmed.strip_prefix("https://github.com/") {
        let mut parts = rest.split('/');
        let owner = parts.next()?.to_owned();
        let repo = parts.next()?.to_owned();
        return Some((owner, repo));
    }
    None
}

fn sanitize_domain(domain: &str) -> String {
    let cleaned = domain
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' { ch } else { '_' })
        .collect::<String>();
    if cleaned.is_empty() {
        "unknown".to_owned()
    } else {
        cleaned
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest[..32]);
    output
}

fn hex_encode(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
