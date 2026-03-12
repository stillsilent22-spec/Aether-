use chrono::{DateTime, Utc};
use crc32fast::Hasher as Crc32Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const AEF_MAGIC: [u8; 4] = [0x41, 0x45, 0x46, 0x00];
pub const AEF_EOF_MARKER: [u8; 4] = [0x45, 0x4F, 0x46, 0x41];
pub const AEF_FORMAT_VERSION: u16 = 1;
pub const DEFAULT_CHUNK_SIZE: usize = 256;
const DEFAULT_SIGNING_CONTEXT: &[u8] = b"aether/aef/shanway/signing-key/v1";

pub mod engine_flags {
    pub const HEISENBERG: u64 = 1 << 0;
    pub const NOETHER: u64 = 1 << 1;
    pub const BENFORD: u64 = 1 << 2;
    pub const MANDELBROT: u64 = 1 << 3;
    pub const SHANNON: u64 = 1 << 4;
    pub const FOURIER: u64 = 1 << 5;
    pub const BAYES: u64 = 1 << 6;
    pub const ALL_CONFIRMED: u64 = 0x7F;
}

#[derive(Debug)]
pub enum AefError {
    Io(String),
    Format(String),
    Signature(String),
    Vault(String),
}

impl std::fmt::Display for AefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(value) => write!(f, "{value}"),
            Self::Format(value) => write!(f, "{value}"),
            Self::Signature(value) => write!(f, "{value}"),
            Self::Vault(value) => write!(f, "{value}"),
        }
    }
}

impl std::error::Error for AefError {}

impl From<std::io::Error> for AefError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(format!("I/O-Fehler: {value}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AefFile {
    pub header: AefHeader,
    pub anchor_map: AefAnchorMap,
    pub delta_layer: AefDeltaLayer,
    pub trust_metadata: AefTrustMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AefHeader {
    pub genesis_block_ref: [u8; 32],
    pub vault_version: u64,
    pub original_filetype: String,
    pub original_size: u64,
    pub original_hash: [u8; 32],
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AefAnchorMap {
    pub anchors: Vec<AefAnchorEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AefAnchorEntry {
    pub anchor_id: Uuid,
    pub vault_ref: [u8; 32],
    pub position: u64,
    pub weight: f32,
    pub signal_type: SignalType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignalType {
    PlainText = 0x01,
    Pdf = 0x02,
    Markdown = 0x03,
    Html = 0x04,
    CrawledWeb = 0x05,
    AudioTranscript = 0x06,
    Code = 0x07,
    Unknown = 0xFF,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AefDeltaLayer {
    pub original_size: u64,
    pub compression_algo: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AefTrustMetadata {
    pub coherence_index: f64,
    pub compression_rate: f32,
    pub lossless_confirmed: bool,
    pub trust_score: f32,
    pub engine_flags: u64,
    pub confirmed_at: u64,
    pub shanway_signature: [u8; 64],
}

#[derive(Debug, Clone)]
pub struct AefEncodeResult {
    pub original_size: u64,
    pub aef_size: u64,
    pub compression_rate: f32,
    pub coherence_index: f64,
    pub lossless_confirmed: bool,
    pub trust_score: f32,
    pub anchor_count: usize,
    pub delta_size: u64,
}

#[derive(Debug, Clone)]
pub struct AefDecodeResult {
    pub original_hash_verified: bool,
    pub reconstruction_complete: bool,
    pub coherence_index: f64,
    pub missing_vault_refs: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct AefReport {
    pub filename: String,
    pub original_filetype: String,
    pub original_size_bytes: u64,
    pub aef_size_bytes: u64,
    pub compression_rate_percent: f32,
    pub anchor_count: usize,
    pub delta_size_bytes: u64,
    pub delta_percent: f32,
    pub coherence_index: f64,
    pub trust_score: f32,
    pub lossless_confirmed: bool,
    pub engine_flags_readable: Vec<String>,
    pub confirmed_at: DateTime<Utc>,
    pub vault_coverage: f32,
}

#[derive(Debug, Clone)]
pub struct AefProjection {
    pub current_compression_rate: f32,
    pub projected_compression_rate: f32,
    pub current_delta_size: u64,
    pub projected_delta_size: u64,
    pub vault_size_needed_for_lossless: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredVaultEntry {
    vault_ref_hex: String,
    signal_type: SignalType,
    data_hex: String,
    created_at: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct StoredVaultState {
    version: u64,
    entries: Vec<StoredVaultEntry>,
}

#[derive(Debug, Clone)]
pub(crate) struct VaultStore {
    path: PathBuf,
    version: u64,
    entries: Vec<StoredVaultEntry>,
}

impl VaultStore {
    pub fn load_default() -> Result<Self, AefError> {
        Self::load_from(
            PathBuf::from("data")
                .join("rust_shell")
                .join("vault_store.json"),
        )
    }

    pub fn load_from(path: PathBuf) -> Result<Self, AefError> {
        if !path.exists() {
            return Ok(Self {
                path,
                version: 1,
                entries: Vec::new(),
            });
        }
        let raw = fs::read_to_string(&path)?;
        let stored: StoredVaultState = serde_json::from_str(&raw)
            .map_err(|err| AefError::Vault(format!("Vault-JSON ungueltig: {err}")))?;
        Ok(Self {
            path,
            version: stored.version.max(1),
            entries: stored.entries,
        })
    }

    pub fn save(&self) -> Result<(), AefError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let payload = StoredVaultState {
            version: self.version,
            entries: self.entries.clone(),
        };
        let raw = serde_json::to_string_pretty(&payload).map_err(|err| {
            AefError::Vault(format!("Vault konnte nicht serialisiert werden: {err}"))
        })?;
        fs::write(&self.path, raw)?;
        Ok(())
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn genesis_block_ref(&self) -> [u8; 32] {
        let mut parts = Vec::new();
        parts.extend_from_slice(b"AEF_GENESIS");
        parts.extend_from_slice(&self.version.to_le_bytes());
        for entry in self.entries.iter().take(32) {
            parts.extend_from_slice(entry.vault_ref_hex.as_bytes());
        }
        sha256_bytes(&parts)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn all_serialized_entries(&self) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .filter_map(|entry| hex_decode(&entry.data_hex).ok())
            .collect()
    }

    pub fn contains(&self, vault_ref: &[u8; 32]) -> bool {
        let target = hex_encode(vault_ref);
        self.entries
            .iter()
            .any(|entry| entry.vault_ref_hex == target)
    }

    pub fn get(&self, vault_ref: &[u8; 32]) -> Option<Vec<u8>> {
        let target = hex_encode(vault_ref);
        self.entries
            .iter()
            .find(|entry| entry.vault_ref_hex == target)
            .and_then(|entry| hex_decode(&entry.data_hex).ok())
    }

    pub fn upsert(&mut self, data: &[u8], signal_type: SignalType) -> Result<[u8; 32], AefError> {
        let vault_ref = sha256_bytes(data);
        let ref_hex = hex_encode(&vault_ref);
        if !self
            .entries
            .iter()
            .any(|entry| entry.vault_ref_hex == ref_hex)
        {
            self.entries.push(StoredVaultEntry {
                vault_ref_hex: ref_hex,
                signal_type,
                data_hex: hex_encode(data),
                created_at: now_epoch(),
            });
            self.version += 1;
            self.save()?;
        }
        Ok(vault_ref)
    }

    pub fn remove(&mut self, vault_ref: &[u8; 32]) -> Result<bool, AefError> {
        let target = hex_encode(vault_ref);
        let before = self.entries.len();
        self.entries.retain(|entry| entry.vault_ref_hex != target);
        let removed = self.entries.len() != before;
        if removed {
            self.version += 1;
            self.save()?;
        }
        Ok(removed)
    }
}

impl Default for VaultStore {
    fn default() -> Self {
        Self {
            path: PathBuf::from("data")
                .join("rust_shell")
                .join("vault_store.json"),
            version: 1,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnginePipeline {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

#[derive(Debug, Clone)]
struct EngineEvaluation {
    coherence_index: f64,
    trust_score: f32,
    engine_flags: u64,
}

impl EnginePipeline {
    pub fn new() -> Self {
        let seed = sha256_bytes(DEFAULT_SIGNING_CONTEXT);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn evaluate(
        &self,
        original: &[u8],
        delta_uncompressed: &[u8],
        anchor_count: usize,
    ) -> EngineEvaluation {
        let entropy = shannon_entropy(original);
        let symmetry = mirrored_symmetry(original);
        let delta_ratio = if original.is_empty() {
            0.0
        } else {
            delta_uncompressed.len() as f32 / original.len() as f32
        };
        let benford = benford_score(original);
        let mandelbrot = mandelbrot_score(original);
        let fourier = fourier_score(original);
        let bayes = ((anchor_count as f32 / ((anchor_count as f32) + 4.0)).clamp(0.0, 1.0)
            * (1.0 - delta_ratio.clamp(0.0, 1.0)))
        .clamp(0.0, 1.0);
        let h_lambda = entropy * (1.0 - symmetry).clamp(0.0, 1.0);
        let knowledge_ratio = (1.0 - delta_ratio.clamp(0.0, 1.0)).clamp(0.0, 1.0);
        let coherence_index = (1.0 - (h_lambda / entropy.max(0.0001))).clamp(0.0, 1.0) as f64;

        let mut flags = 0u64;
        if h_lambda <= 2.0 {
            flags |= engine_flags::HEISENBERG;
        }
        if symmetry >= 0.55 {
            flags |= engine_flags::NOETHER;
        }
        if benford >= 0.30 {
            flags |= engine_flags::BENFORD;
        }
        if mandelbrot >= 0.45 {
            flags |= engine_flags::MANDELBROT;
        }
        if entropy > 0.0 && entropy <= 8.0 {
            flags |= engine_flags::SHANNON;
        }
        if fourier >= 0.25 {
            flags |= engine_flags::FOURIER;
        }
        if bayes >= 0.40 && knowledge_ratio >= 0.40 {
            flags |= engine_flags::BAYES;
        }

        let trust_score = ((0.20 * symmetry)
            + (0.12 * benford)
            + (0.12 * mandelbrot)
            + (0.12 * fourier)
            + (0.20 * knowledge_ratio)
            + (0.24 * (coherence_index as f32)))
            .clamp(0.0, 1.0);

        EngineEvaluation {
            coherence_index,
            trust_score,
            engine_flags: flags,
        }
    }

    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.signing_key.sign(payload).to_bytes()
    }

    pub fn verify(&self, payload: &[u8], signature: &[u8; 64]) -> Result<(), AefError> {
        let signature = Signature::from_bytes(signature);
        self.verifying_key
            .verify(payload, &signature)
            .map_err(|err| AefError::Signature(format!("Shanway-Signatur ungueltig: {err}")))
    }
}

impl Default for EnginePipeline {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AefEncoder {
    pub vault: Arc<RwLock<VaultStore>>,
    pub engine_pipeline: Arc<EnginePipeline>,
}

impl AefEncoder {
    pub fn new(vault: Arc<RwLock<VaultStore>>, engine_pipeline: Arc<EnginePipeline>) -> Self {
        Self {
            vault,
            engine_pipeline,
        }
    }
}

pub struct AefDecoder {
    pub vault: Arc<RwLock<VaultStore>>,
}

impl AefDecoder {
    pub fn new(vault: Arc<RwLock<VaultStore>>) -> Self {
        Self { vault }
    }
}

pub struct AefInspector;

#[derive(Debug, Clone)]
struct AnchorCandidate {
    position: u64,
    data: Vec<u8>,
    weight: f32,
}

impl AefEncoder {
    pub fn encode_sync(
        &self,
        input_path: &Path,
        output_path: &Path,
    ) -> Result<AefEncodeResult, AefError> {
        let original = fs::read(input_path)?;
        let original_hash = sha256_bytes(&original);
        let signal_type = signal_type_from_path(input_path);
        let original_filetype = filetype_from_path(input_path);
        let created_at = now_epoch();

        let (genesis_block_ref, vault_version) = {
            let vault = self.vault.read().map_err(|_| {
                AefError::Vault("Vault-Lock konnte nicht gelesen werden".to_owned())
            })?;
            (vault.genesis_block_ref(), vault.version())
        };

        let chunk_candidates = extract_anchor_candidates(&original, signal_type);
        let mut anchors = Vec::new();
        let mut predicted = vec![0u8; original.len()];
        {
            let mut vault = self.vault.write().map_err(|_| {
                AefError::Vault("Vault-Lock konnte nicht geschrieben werden".to_owned())
            })?;
            for candidate in chunk_candidates {
                let vault_ref = vault.upsert(&candidate.data, signal_type)?;
                let start = candidate.position as usize;
                let end = (start + candidate.data.len()).min(predicted.len());
                let span = end.saturating_sub(start);
                if span > 0 {
                    predicted[start..end].copy_from_slice(&candidate.data[..span]);
                }
                anchors.push(AefAnchorEntry {
                    anchor_id: uuid_from_ref(&vault_ref, candidate.position),
                    vault_ref,
                    position: candidate.position,
                    weight: candidate.weight,
                    signal_type,
                });
            }
        }

        let delta_uncompressed = xor_bytes(&original, &predicted);
        let delta_compressed = zlib_compress(&delta_uncompressed)?;
        let evaluation =
            self.engine_pipeline
                .evaluate(&original, &delta_uncompressed, anchors.len());

        let mut file = AefFile {
            header: AefHeader {
                genesis_block_ref,
                vault_version,
                original_filetype,
                original_size: original.len() as u64,
                original_hash,
                created_at,
            },
            anchor_map: AefAnchorMap { anchors },
            delta_layer: AefDeltaLayer {
                original_size: delta_uncompressed.len() as u64,
                compression_algo: 0x01,
                data: delta_compressed,
            },
            trust_metadata: AefTrustMetadata {
                coherence_index: evaluation.coherence_index,
                compression_rate: 0.0,
                lossless_confirmed: false,
                trust_score: evaluation.trust_score,
                engine_flags: evaluation.engine_flags,
                confirmed_at: created_at,
                shanway_signature: [0u8; 64],
            },
        };

        let tentative_bytes = file.to_bytes()?;
        file.trust_metadata.compression_rate = if original.is_empty() {
            0.0
        } else {
            (tentative_bytes.len() as f32 / original.len() as f32).clamp(0.0, 1.0)
        };

        let probe_reconstruction = {
            let vault = self.vault.read().map_err(|_| {
                AefError::Vault("Vault-Lock konnte nicht gelesen werden".to_owned())
            })?;
            file.reconstruct_bytes(&vault)?
        };
        let lossless_confirmed = probe_reconstruction.1.is_empty()
            && probe_reconstruction.0 == original
            && evaluation.trust_score >= 0.65
            && evaluation.engine_flags == engine_flags::ALL_CONFIRMED;
        file.trust_metadata.lossless_confirmed = lossless_confirmed;
        file.trust_metadata.shanway_signature = self.engine_pipeline.sign(&file.signable_bytes()?);

        let output = file.to_bytes()?;
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output_path, &output)?;

        Ok(AefEncodeResult {
            original_size: original.len() as u64,
            aef_size: output.len() as u64,
            compression_rate: file.trust_metadata.compression_rate,
            coherence_index: file.trust_metadata.coherence_index,
            lossless_confirmed,
            trust_score: file.trust_metadata.trust_score,
            anchor_count: file.anchor_map.anchors.len(),
            delta_size: file.delta_layer.data.len() as u64,
        })
    }

    pub async fn encode(
        &self,
        input_path: &Path,
        output_path: &Path,
    ) -> Result<AefEncodeResult, AefError> {
        self.encode_sync(input_path, output_path)
    }
}

impl AefDecoder {
    pub fn decode_sync(
        &self,
        aef_path: &Path,
        output_path: &Path,
    ) -> Result<AefDecodeResult, AefError> {
        let file = AefFile::read_from_path(aef_path)?;
        let engine = EnginePipeline::new();
        engine.verify(
            &file.signable_bytes()?,
            &file.trust_metadata.shanway_signature,
        )?;

        let (reconstructed, missing_refs) = {
            let vault = self.vault.read().map_err(|_| {
                AefError::Vault("Vault-Lock konnte nicht gelesen werden".to_owned())
            })?;
            file.reconstruct_bytes(&vault)?
        };
        let original_hash_verified = sha256_bytes(&reconstructed) == file.header.original_hash;
        let reconstruction_complete = original_hash_verified && missing_refs.is_empty();
        if reconstruction_complete {
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(output_path, &reconstructed)?;
        }

        Ok(AefDecodeResult {
            original_hash_verified,
            reconstruction_complete,
            coherence_index: file.trust_metadata.coherence_index,
            missing_vault_refs: missing_refs,
        })
    }

    pub async fn decode(
        &self,
        aef_path: &Path,
        output_path: &Path,
    ) -> Result<AefDecodeResult, AefError> {
        self.decode_sync(aef_path, output_path)
    }
}

impl AefInspector {
    pub fn inspect(aef_path: &Path) -> Result<AefReport, AefError> {
        let file = AefFile::read_from_path(aef_path)?;
        let aef_size_bytes = fs::metadata(aef_path)?.len();
        let delta_size_bytes = file.delta_layer.data.len() as u64;
        let delta_percent = if file.header.original_size == 0 {
            0.0
        } else {
            (delta_size_bytes as f32 / file.header.original_size as f32).clamp(0.0, 1.0) * 100.0
        };
        let delta_contribution =
            ((file.delta_layer.original_size as f32 / DEFAULT_CHUNK_SIZE as f32).ceil() as usize)
                .max(1);
        let vault_coverage = (file.anchor_map.anchors.len() as f32
            / (file.anchor_map.anchors.len() as f32 + delta_contribution as f32))
            .clamp(0.0, 1.0);
        Ok(AefReport {
            filename: aef_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("unbekannt")
                .to_owned(),
            original_filetype: file.header.original_filetype.clone(),
            original_size_bytes: file.header.original_size,
            aef_size_bytes,
            compression_rate_percent: file.trust_metadata.compression_rate * 100.0,
            anchor_count: file.anchor_map.anchors.len(),
            delta_size_bytes,
            delta_percent,
            coherence_index: file.trust_metadata.coherence_index,
            trust_score: file.trust_metadata.trust_score,
            lossless_confirmed: file.trust_metadata.lossless_confirmed,
            engine_flags_readable: readable_engine_flags(file.trust_metadata.engine_flags),
            confirmed_at: DateTime::<Utc>::from_timestamp(
                file.trust_metadata.confirmed_at as i64,
                0,
            )
            .unwrap_or_else(Utc::now),
            vault_coverage,
        })
    }

    pub fn project_future_compression_sync(
        aef_path: &Path,
        vault: &VaultStore,
        projected_vault_size: usize,
    ) -> Result<AefProjection, AefError> {
        let file = AefFile::read_from_path(aef_path)?;
        let current_vault_size = vault.entry_count().max(1);
        let projected_scale = ((1.0 + projected_vault_size as f32).ln()
            / (1.0 + current_vault_size as f32).ln())
        .max(1.0);
        let reduction_factor = (1.0 / projected_scale).clamp(0.10, 1.0);
        let current_delta_size = file.delta_layer.data.len() as u64;
        let projected_delta_size = ((current_delta_size as f32) * reduction_factor).round() as u64;
        let projected_compression_rate =
            ((file.trust_metadata.compression_rate * reduction_factor).clamp(0.0, 1.0) * 10000.0)
                .round()
                / 10000.0;
        let vault_size_needed_for_lossless = if file.trust_metadata.lossless_confirmed {
            None
        } else {
            Some(
                current_vault_size
                    + ((file.delta_layer.original_size as usize / DEFAULT_CHUNK_SIZE).max(1) * 3),
            )
        };
        Ok(AefProjection {
            current_compression_rate: file.trust_metadata.compression_rate,
            projected_compression_rate,
            current_delta_size,
            projected_delta_size,
            vault_size_needed_for_lossless,
        })
    }

    pub async fn project_future_compression(
        aef_path: &Path,
        vault: &VaultStore,
        projected_vault_size: usize,
    ) -> Result<AefProjection, AefError> {
        Self::project_future_compression_sync(aef_path, vault, projected_vault_size)
    }
}

impl AefFile {
    pub fn read_from_path(path: &Path) -> Result<Self, AefError> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AefError> {
        let mut output = Vec::new();
        output.extend_from_slice(&AEF_MAGIC);
        output.extend_from_slice(&AEF_FORMAT_VERSION.to_le_bytes());

        let header_without_checksum = self.header_bytes_without_checksum();
        output.extend_from_slice(&header_without_checksum);
        output.extend_from_slice(&crc32(&header_without_checksum).to_le_bytes());

        let anchor_without_checksum = self.anchor_map_bytes_without_checksum();
        output.extend_from_slice(&anchor_without_checksum);
        output.extend_from_slice(&crc32(&anchor_without_checksum).to_le_bytes());

        let delta_without_checksum = self.delta_layer_bytes_without_checksum();
        output.extend_from_slice(&delta_without_checksum);
        output.extend_from_slice(&crc32(&delta_without_checksum).to_le_bytes());

        output.extend_from_slice(&self.trust_metadata_bytes(true));
        output.extend_from_slice(&AEF_EOF_MARKER);
        Ok(output)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AefError> {
        let mut cursor = std::io::Cursor::new(bytes);
        if read_exact_array::<4>(&mut cursor)? != AEF_MAGIC {
            return Err(AefError::Format("AEF Magic Bytes ungueltig".to_owned()));
        }
        let version = read_u16(&mut cursor)?;
        if version != AEF_FORMAT_VERSION {
            return Err(AefError::Format(format!(
                "AEF-Version nicht unterstuetzt: {version}"
            )));
        }
        let header = read_header(&mut cursor)?;
        let anchor_map = read_anchor_map(&mut cursor)?;
        let delta_layer = read_delta_layer(&mut cursor)?;
        let trust_metadata = read_trust_metadata(&mut cursor)?;
        if read_exact_array::<4>(&mut cursor)? != AEF_EOF_MARKER {
            return Err(AefError::Format("AEF EOF-Marker ungueltig".to_owned()));
        }
        let file = Self {
            header,
            anchor_map,
            delta_layer,
            trust_metadata,
        };
        EnginePipeline::new().verify(
            &file.signable_bytes()?,
            &file.trust_metadata.shanway_signature,
        )?;
        Ok(file)
    }

    pub fn signable_bytes(&self) -> Result<Vec<u8>, AefError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header_bytes_without_checksum());
        bytes.extend_from_slice(&self.anchor_map_bytes_without_checksum());
        bytes.extend_from_slice(&self.trust_metadata_bytes(false));
        Ok(bytes)
    }

    pub fn reconstruct_bytes(
        &self,
        vault: &VaultStore,
    ) -> Result<(Vec<u8>, Vec<[u8; 32]>), AefError> {
        let mut predicted = vec![0u8; self.header.original_size as usize];
        let mut missing = Vec::new();
        for anchor in &self.anchor_map.anchors {
            match vault.get(&anchor.vault_ref) {
                Some(data) => {
                    let start = anchor.position as usize;
                    let end = (start + data.len()).min(predicted.len());
                    let span = end.saturating_sub(start);
                    if span > 0 {
                        predicted[start..end].copy_from_slice(&data[..span]);
                    }
                }
                None => missing.push(anchor.vault_ref),
            }
        }
        let delta = zlib_decompress(&self.delta_layer.data)?;
        if delta.len() != self.delta_layer.original_size as usize || delta.len() != predicted.len()
        {
            return Err(AefError::Format(
                "Delta-Layer passt nicht zur erwarteten Originalgroesse".to_owned(),
            ));
        }
        Ok((xor_bytes(&predicted, &delta), missing))
    }

    fn header_bytes_without_checksum(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.genesis_block_ref);
        bytes.extend_from_slice(&self.header.vault_version.to_le_bytes());
        bytes.extend_from_slice(&fixed_type_field(&self.header.original_filetype));
        bytes.extend_from_slice(&self.header.original_size.to_le_bytes());
        bytes.extend_from_slice(&self.header.original_hash);
        bytes.extend_from_slice(&self.header.created_at.to_le_bytes());
        bytes
    }

    fn anchor_map_bytes_without_checksum(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.anchor_map.anchors.len() as u32).to_le_bytes());
        for anchor in &self.anchor_map.anchors {
            bytes.extend_from_slice(anchor.anchor_id.as_bytes());
            bytes.extend_from_slice(&anchor.vault_ref);
            bytes.extend_from_slice(&anchor.position.to_le_bytes());
            bytes.extend_from_slice(&anchor.weight.to_le_bytes());
            bytes.push(anchor.signal_type as u8);
        }
        bytes
    }

    fn delta_layer_bytes_without_checksum(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.delta_layer.data.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.delta_layer.original_size.to_le_bytes());
        bytes.push(self.delta_layer.compression_algo);
        bytes.extend_from_slice(&self.delta_layer.data);
        bytes
    }

    fn trust_metadata_bytes(&self, include_signature: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.trust_metadata.coherence_index.to_le_bytes());
        bytes.extend_from_slice(&self.trust_metadata.compression_rate.to_le_bytes());
        bytes.push(if self.trust_metadata.lossless_confirmed {
            0x01
        } else {
            0x00
        });
        bytes.extend_from_slice(&self.trust_metadata.trust_score.to_le_bytes());
        bytes.extend_from_slice(&self.trust_metadata.engine_flags.to_le_bytes());
        bytes.extend_from_slice(&self.trust_metadata.confirmed_at.to_le_bytes());
        if include_signature {
            bytes.extend_from_slice(&self.trust_metadata.shanway_signature);
        }
        bytes
    }
}

fn extract_anchor_candidates(original: &[u8], _signal_type: SignalType) -> Vec<AnchorCandidate> {
    let mut anchors = Vec::new();
    for (chunk_index, chunk) in original.chunks(DEFAULT_CHUNK_SIZE).enumerate() {
        let chunk_entropy = shannon_entropy(chunk);
        let chunk_drift = byte_drift(chunk);
        let qualifies = chunk_index % 3 == 0
            || chunk.len() < DEFAULT_CHUNK_SIZE
            || chunk_entropy <= 6.8
            || chunk_drift <= 18.0;
        if !qualifies {
            continue;
        }
        anchors.push(AnchorCandidate {
            position: (chunk_index * DEFAULT_CHUNK_SIZE) as u64,
            data: chunk.to_vec(),
            weight: (1.0 / (1.0 + chunk_entropy)).clamp(0.01, 1.0),
        });
    }
    if anchors.is_empty() && !original.is_empty() {
        anchors.push(AnchorCandidate {
            position: 0,
            data: original.iter().take(DEFAULT_CHUNK_SIZE).copied().collect(),
            weight: 0.5,
        });
    }
    anchors
}

fn read_header(cursor: &mut std::io::Cursor<&[u8]>) -> Result<AefHeader, AefError> {
    let start = cursor.position() as usize;
    let genesis_block_ref = read_exact_array::<32>(cursor)?;
    let vault_version = read_u64(cursor)?;
    let original_filetype = read_fixed_string(cursor, 16)?;
    let original_size = read_u64(cursor)?;
    let original_hash = read_exact_array::<32>(cursor)?;
    let created_at = read_u64(cursor)?;
    let end = cursor.position() as usize;
    if crc32(&cursor.get_ref()[start..end]) != read_u32(cursor)? {
        return Err(AefError::Format("Header-CRC32 ungueltig".to_owned()));
    }
    Ok(AefHeader {
        genesis_block_ref,
        vault_version,
        original_filetype,
        original_size,
        original_hash,
        created_at,
    })
}

fn read_anchor_map(cursor: &mut std::io::Cursor<&[u8]>) -> Result<AefAnchorMap, AefError> {
    let start = cursor.position() as usize;
    let anchor_count = read_u32(cursor)? as usize;
    let mut anchors = Vec::with_capacity(anchor_count);
    for _ in 0..anchor_count {
        anchors.push(AefAnchorEntry {
            anchor_id: Uuid::from_bytes(read_exact_array::<16>(cursor)?),
            vault_ref: read_exact_array::<32>(cursor)?,
            position: read_u64(cursor)?,
            weight: read_f32(cursor)?,
            signal_type: signal_type_from_u8(read_u8(cursor)?),
        });
    }
    let end = cursor.position() as usize;
    if crc32(&cursor.get_ref()[start..end]) != read_u32(cursor)? {
        return Err(AefError::Format("AnchorMap-CRC32 ungueltig".to_owned()));
    }
    Ok(AefAnchorMap { anchors })
}

fn read_delta_layer(cursor: &mut std::io::Cursor<&[u8]>) -> Result<AefDeltaLayer, AefError> {
    let start = cursor.position() as usize;
    let delta_size = read_u64(cursor)? as usize;
    let original_size = read_u64(cursor)?;
    let compression_algo = read_u8(cursor)?;
    let mut data = vec![0u8; delta_size];
    cursor.read_exact(&mut data)?;
    let end = cursor.position() as usize;
    if crc32(&cursor.get_ref()[start..end]) != read_u32(cursor)? {
        return Err(AefError::Format("Delta-CRC32 ungueltig".to_owned()));
    }
    Ok(AefDeltaLayer {
        original_size,
        compression_algo,
        data,
    })
}

fn read_trust_metadata(cursor: &mut std::io::Cursor<&[u8]>) -> Result<AefTrustMetadata, AefError> {
    Ok(AefTrustMetadata {
        coherence_index: read_f64(cursor)?,
        compression_rate: read_f32(cursor)?,
        lossless_confirmed: read_u8(cursor)? == 0x01,
        trust_score: read_f32(cursor)?,
        engine_flags: read_u64(cursor)?,
        confirmed_at: read_u64(cursor)?,
        shanway_signature: read_exact_array::<64>(cursor)?,
    })
}

fn read_exact_array<const N: usize>(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<[u8; N], AefError> {
    let mut data = [0u8; N];
    cursor.read_exact(&mut data)?;
    Ok(data)
}

fn read_u8(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u8, AefError> {
    Ok(read_exact_array::<1>(cursor)?[0])
}

fn read_u16(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u16, AefError> {
    Ok(u16::from_le_bytes(read_exact_array::<2>(cursor)?))
}

fn read_u32(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u32, AefError> {
    Ok(u32::from_le_bytes(read_exact_array::<4>(cursor)?))
}

fn read_u64(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u64, AefError> {
    Ok(u64::from_le_bytes(read_exact_array::<8>(cursor)?))
}

fn read_f32(cursor: &mut std::io::Cursor<&[u8]>) -> Result<f32, AefError> {
    Ok(f32::from_le_bytes(read_exact_array::<4>(cursor)?))
}

fn read_f64(cursor: &mut std::io::Cursor<&[u8]>) -> Result<f64, AefError> {
    Ok(f64::from_le_bytes(read_exact_array::<8>(cursor)?))
}

fn read_fixed_string(
    cursor: &mut std::io::Cursor<&[u8]>,
    length: usize,
) -> Result<String, AefError> {
    let mut bytes = vec![0u8; length];
    cursor.read_exact(&mut bytes)?;
    let trimmed = bytes
        .into_iter()
        .take_while(|byte| *byte != 0)
        .collect::<Vec<u8>>();
    Ok(String::from_utf8(trimmed).unwrap_or_else(|_| "unknown".to_owned()))
}

fn signal_type_from_path(path: &Path) -> SignalType {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "txt" => SignalType::PlainText,
        "pdf" => SignalType::Pdf,
        "md" => SignalType::Markdown,
        "html" | "htm" => SignalType::Html,
        "rs" | "py" | "js" | "ts" | "json" | "toml" => SignalType::Code,
        _ => SignalType::Unknown,
    }
}

fn signal_type_from_u8(value: u8) -> SignalType {
    match value {
        0x01 => SignalType::PlainText,
        0x02 => SignalType::Pdf,
        0x03 => SignalType::Markdown,
        0x04 => SignalType::Html,
        0x05 => SignalType::CrawledWeb,
        0x06 => SignalType::AudioTranscript,
        0x07 => SignalType::Code,
        _ => SignalType::Unknown,
    }
}

fn filetype_from_path(path: &Path) -> String {
    path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("bin")
        .to_ascii_lowercase()
}

fn fixed_type_field(value: &str) -> [u8; 16] {
    let mut output = [0u8; 16];
    let bytes = value.as_bytes();
    let span = bytes.len().min(16);
    output[..span].copy_from_slice(&bytes[..span]);
    output
}

fn uuid_from_ref(vault_ref: &[u8; 32], position: u64) -> Uuid {
    let mut seed = [0u8; 16];
    seed.copy_from_slice(&vault_ref[..16]);
    let position_bytes = position.to_le_bytes();
    for (index, byte) in position_bytes.iter().enumerate() {
        seed[index % 16] ^= *byte;
    }
    seed[6] = (seed[6] & 0x0F) | 0x40;
    seed[8] = (seed[8] & 0x3F) | 0x80;
    Uuid::from_bytes(seed)
}

fn readable_engine_flags(flags: u64) -> Vec<String> {
    let mut items = Vec::new();
    for (mask, label) in [
        (engine_flags::HEISENBERG, "HEISENBERG"),
        (engine_flags::NOETHER, "NOETHER"),
        (engine_flags::BENFORD, "BENFORD"),
        (engine_flags::MANDELBROT, "MANDELBROT"),
        (engine_flags::SHANNON, "SHANNON"),
        (engine_flags::FOURIER, "FOURIER"),
        (engine_flags::BAYES, "BAYES"),
    ] {
        items.push(format!(
            "{label} {}",
            if flags & mask != 0 { "✓" } else { "✗" }
        ));
    }
    items
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest[..32]);
    output
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = Crc32Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

fn xor_bytes(left: &[u8], right: &[u8]) -> Vec<u8> {
    let len = left.len().max(right.len());
    let mut output = vec![0u8; len];
    for index in 0..len {
        let lhs = left.get(index).copied().unwrap_or(0);
        let rhs = right.get(index).copied().unwrap_or(0);
        output[index] = lhs ^ rhs;
    }
    output
}

fn zlib_compress(data: &[u8]) -> Result<Vec<u8>, AefError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish().map_err(AefError::from)
}

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, AefError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn hex_encode(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>, AefError> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(AefError::Format(
            "Hex-String hat ungerade Laenge".to_owned(),
        ));
    }
    let mut output = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0usize;
    while index < bytes.len() {
        let pair = std::str::from_utf8(&bytes[index..index + 2])
            .map_err(|err| AefError::Format(format!("Hex-Dekodierung fehlgeschlagen: {err}")))?;
        let value = u8::from_str_radix(pair, 16)
            .map_err(|err| AefError::Format(format!("Hex-Dekodierung fehlgeschlagen: {err}")))?;
        output.push(value);
        index += 2;
    }
    Ok(output)
}

fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let total = data.len() as f32;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f32 / total;
            -(probability * probability.log2())
        })
        .sum()
}

fn mirrored_symmetry(data: &[u8]) -> f32 {
    if data.len() < 2 {
        return 1.0;
    }
    let mut total = 0.0f32;
    let mut count = 0usize;
    for index in 0..(data.len() / 2) {
        let left = data[index] as f32;
        let right = data[data.len() - 1 - index] as f32;
        total += 1.0 - ((left - right).abs() / 255.0).clamp(0.0, 1.0);
        count += 1;
    }
    if count == 0 {
        1.0
    } else {
        total / count as f32
    }
}

fn byte_drift(data: &[u8]) -> f32 {
    if data.len() < 2 {
        return 0.0;
    }
    let total: u64 = data
        .windows(2)
        .map(|window| (window[0] as i32 - window[1] as i32).unsigned_abs() as u64)
        .sum();
    total as f32 / data.len().saturating_sub(1) as f32
}

fn benford_score(data: &[u8]) -> f32 {
    let mut leading = [0usize; 10];
    for chunk in data.chunks(4) {
        let value = chunk
            .iter()
            .fold(0u32, |acc, byte| (acc << 8) | (*byte as u32));
        let mut current = value;
        while current >= 10 {
            current /= 10;
        }
        if current > 0 && current < 10 {
            leading[current as usize] += 1;
        }
    }
    let total: usize = leading.iter().sum();
    if total < 16 {
        return 0.5;
    }
    let expected = [
        0.0, 0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046,
    ];
    let mut deviation = 0.0f32;
    for digit in 1..10 {
        let observed = leading[digit] as f32 / total as f32;
        deviation += (observed - expected[digit] as f32).abs();
    }
    (1.0 - deviation.clamp(0.0, 1.0)).clamp(0.0, 1.0)
}

fn mandelbrot_score(data: &[u8]) -> f32 {
    let entropy = shannon_entropy(data);
    (1.0 - ((entropy - 4.5).abs() / 4.5)).clamp(0.0, 1.0)
}

fn fourier_score(data: &[u8]) -> f32 {
    if data.len() < 8 {
        return 0.5;
    }
    let average = data.iter().map(|byte| *byte as f32).sum::<f32>() / data.len() as f32;
    let variance = data
        .iter()
        .map(|byte| {
            let delta = *byte as f32 - average;
            delta * delta
        })
        .sum::<f32>()
        / data.len() as f32;
    (1.0 - (variance.sqrt() / 128.0)).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let base = PathBuf::from("target").join("aef_tests").join(name);
        let _ = fs::create_dir_all(&base);
        base
    }

    #[test]
    fn aef_roundtrip_sync_preserves_hash() {
        let base = temp_dir("roundtrip_sync");
        let input_path = base.join("probe.txt");
        let output_path = base.join("probe.aef");
        let decoded_path = base.join("decoded.txt");
        fs::write(
            &input_path,
            b"Aether test payload for roundtrip.\nSymmetry and drift.\n",
        )
        .unwrap();

        let vault = Arc::new(RwLock::new(
            VaultStore::load_from(base.join("vault.json")).unwrap_or_default(),
        ));
        let engine = Arc::new(EnginePipeline::new());
        let encoder = AefEncoder::new(Arc::clone(&vault), Arc::clone(&engine));
        let decoder = AefDecoder::new(Arc::clone(&vault));

        let encoded = encoder.encode_sync(&input_path, &output_path).unwrap();
        assert!(encoded.aef_size > 0);

        let decoded = decoder.decode_sync(&output_path, &decoded_path).unwrap();
        assert!(decoded.original_hash_verified);
        assert!(decoded.reconstruction_complete);

        let original = fs::read(&input_path).unwrap();
        let reconstructed = fs::read(&decoded_path).unwrap();
        assert_eq!(sha256_bytes(&original), sha256_bytes(&reconstructed));
    }

    #[test]
    fn aef_inspector_reports_metrics() {
        let base = temp_dir("inspect_sync");
        let input_path = base.join("inspect.md");
        let output_path = base.join("inspect.aef");
        fs::write(&input_path, b"# Aether\n\nInspector payload.\n").unwrap();

        let vault = Arc::new(RwLock::new(
            VaultStore::load_from(base.join("vault.json")).unwrap_or_default(),
        ));
        let engine = Arc::new(EnginePipeline::new());
        let encoder = AefEncoder::new(Arc::clone(&vault), Arc::clone(&engine));
        encoder.encode_sync(&input_path, &output_path).unwrap();

        let report = AefInspector::inspect(&output_path).unwrap();
        assert_eq!(report.original_filetype, "md");
        assert!(report.anchor_count >= 1);
        assert!(report.aef_size_bytes > 0);
        assert!(!report.engine_flags_readable.is_empty());
    }
}
