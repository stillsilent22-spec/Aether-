use crate::aef::{EnginePipeline, SignalType};
use crate::inter_layer_bus::{BusEvent, BusPublisher, PackDownloadEvent, PackRecommendedEvent};
use crate::vault_access::{
    PublicAnchorRecord, RawAnchorSubmission, SubmissionSource, VaultAccessError, VaultAccessLayer,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

pub const AEP_MAGIC: [u8; 4] = [0x41, 0x45, 0x50, 0x00];
pub const AEP_EOF_MARKER: [u8; 4] = [0x45, 0x50, 0x46, 0x41];
pub const AEP_FORMAT_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AepPack {
    pub magic: [u8; 4],
    pub version: u16,
    pub header: AepHeader,
    pub stats: AepStats,
    pub anchors: Vec<PublicAnchorRecord>,
    pub eof_marker: [u8; 4],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AepHeader {
    pub pack_id: Uuid,
    pub pack_name: String,
    pub pack_version: u64,
    pub domain: String,
    pub subdomain: Option<String>,
    pub pack_size_bytes: u64,
    pub created_at: u64,
    pub aether_version: String,
    pub curator: String,
    pub description: String,
    pub shanway_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AepStats {
    pub anchor_count: u32,
    pub avg_trust_score: f32,
    pub avg_coherence: f32,
    pub estimated_hit_rate_improvement: f32,
    pub estimated_compression_improvement: f32,
    pub compatible_signal_types: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackRegistryEntry {
    pub pack_id: Uuid,
    pub pack_name: String,
    pub pack_version: String,
    pub domain: String,
    pub subdomain: Option<String>,
    pub description: String,
    pub curator: String,
    pub download_url: String,
    pub size_bytes: u64,
    pub anchor_count: u32,
    pub avg_trust_score: f32,
    pub estimated_hit_rate_improvement: f32,
    pub estimated_compression_improvement: f32,
    pub shanway_verified: bool,
    pub created_at: u64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackRegistry {
    pub index_url: String,
    pub local_cache: PathBuf,
    pub last_updated: u64,
    pub entries: Vec<PackRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UsageProfile {
    pub dominant_domains: Vec<(String, f32)>,
    pub active_signal_types: Vec<SignalType>,
    pub current_hit_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPack {
    pub entry: PackRegistryEntry,
    pub installed_at: u64,
    pub anchor_ids_added: Vec<Uuid>,
    pub hit_rate_before: f32,
    pub hit_rate_after: f32,
}

#[derive(Debug, Clone)]
pub struct InstallResult {
    pub pack_id: Uuid,
    pub pack_name: String,
    pub anchors_added: usize,
    pub hit_rate_before: f32,
    pub hit_rate_after: f32,
}

#[derive(Debug, Clone)]
pub struct PackRecommendation {
    pub pack_id: Uuid,
    pub title: String,
    pub message: String,
    pub estimated_hit_rate_improvement: f32,
    pub estimated_compression_improvement: f32,
}

#[derive(Debug, Clone)]
pub struct GeneratedPack {
    pub pack_id: Uuid,
    pub path: PathBuf,
    pub anchor_count: usize,
    pub domain: String,
}

#[derive(Debug)]
pub enum PackError {
    UserConfirmationRequired,
    Io(String),
    Format(String),
    Signature(String),
    Vault(String),
    NotFound(String),
    Download(String),
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserConfirmationRequired => {
                write!(f, "Explizite Nutzerbestaetigung erforderlich")
            }
            Self::Io(value)
            | Self::Format(value)
            | Self::Signature(value)
            | Self::Vault(value)
            | Self::NotFound(value)
            | Self::Download(value) => write!(f, "{value}"),
        }
    }
}

impl std::error::Error for PackError {}

pub struct PackManager {
    vault: Arc<VaultAccessLayer>,
    registry: Arc<RwLock<PackRegistry>>,
    installed_packs: HashMap<Uuid, InstalledPack>,
    install_state_path: PathBuf,
    engine: EnginePipeline,
}

pub struct ShanwayPackAdvisor {
    registry: Arc<RwLock<PackRegistry>>,
    last_recommendation: HashMap<Uuid, u64>,
    cooldown_secs: u64,
    bus: BusPublisher,
}

pub struct AutoPackGenerator {
    vault: Arc<VaultAccessLayer>,
    output_dir: PathBuf,
    engine: EnginePipeline,
}

impl AepPack {
    pub fn new(
        pack_name: impl Into<String>,
        domain: impl Into<String>,
        subdomain: Option<String>,
        curator: impl Into<String>,
        description: impl Into<String>,
        anchors: Vec<PublicAnchorRecord>,
    ) -> Self {
        Self {
            magic: AEP_MAGIC,
            version: AEP_FORMAT_VERSION,
            header: AepHeader {
                pack_id: Uuid::new_v4(),
                pack_name: pack_name.into(),
                pack_version: 1,
                domain: sanitize(&domain.into()),
                subdomain: subdomain.map(|value| sanitize(&value)),
                pack_size_bytes: 0,
                created_at: Utc::now().timestamp() as u64,
                aether_version: "vera_aether_core_rust_shell".to_owned(),
                curator: curator.into(),
                description: description.into(),
                shanway_signature: String::new(),
            },
            stats: derive_stats(&anchors),
            anchors,
            eof_marker: AEP_EOF_MARKER,
        }
    }

    pub fn sign(&mut self, engine: &EnginePipeline) {
        self.stats = derive_stats(&self.anchors);
        let mut header = self.header.clone();
        header.shanway_signature.clear();
        let payload =
            serde_json::to_vec(&(self.magic, self.version, header, &self.stats, &self.anchors))
                .unwrap_or_default();
        self.header.shanway_signature = BASE64.encode(engine.sign(&payload));
    }

    pub fn verify(&self, engine: &EnginePipeline) -> Result<(), PackError> {
        if self.magic != AEP_MAGIC
            || self.eof_marker != AEP_EOF_MARKER
            || self.version != AEP_FORMAT_VERSION
        {
            return Err(PackError::Format(
                "AEP-Magic oder Version ungueltig".to_owned(),
            ));
        }
        let decoded = BASE64
            .decode(self.header.shanway_signature.as_bytes())
            .map_err(|err| {
                PackError::Signature(format!(
                    "Pack-Signatur konnte nicht dekodiert werden: {err}"
                ))
            })?;
        if decoded.len() != 64 {
            return Err(PackError::Signature(
                "Pack-Signatur hat nicht 64 Bytes".to_owned(),
            ));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&decoded);
        let mut header = self.header.clone();
        header.shanway_signature.clear();
        let payload =
            serde_json::to_vec(&(self.magic, self.version, header, &self.stats, &self.anchors))
                .unwrap_or_default();
        engine
            .verify(&payload, &signature)
            .map_err(|err| PackError::Signature(err.to_string()))
    }

    pub fn write_to_path(&mut self, path: &Path, engine: &EnginePipeline) -> Result<(), PackError> {
        self.sign(engine);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| PackError::Io(err.to_string()))?;
        }
        let raw =
            serde_json::to_string_pretty(self).map_err(|err| PackError::Format(err.to_string()))?;
        self.header.pack_size_bytes = raw.len() as u64;
        self.sign(engine);
        let raw =
            serde_json::to_string_pretty(self).map_err(|err| PackError::Format(err.to_string()))?;
        fs::write(path, raw).map_err(|err| PackError::Io(err.to_string()))
    }

    pub fn read_from_path(path: &Path, engine: &EnginePipeline) -> Result<Self, PackError> {
        let raw = fs::read_to_string(path).map_err(|err| PackError::Io(err.to_string()))?;
        let pack: AepPack =
            serde_json::from_str(&raw).map_err(|err| PackError::Format(err.to_string()))?;
        pack.verify(engine)?;
        Ok(pack)
    }
}

impl PackRegistry {
    pub fn load_default() -> Result<Self, PackError> {
        let local_cache = PathBuf::from("data")
            .join("rust_shell")
            .join("packs")
            .join("pack_registry.json");
        if !local_cache.exists() {
            let mut registry = Self {
                index_url: "github-releases://stillsilent22-spec/Aether-/anchor-packs".to_owned(),
                local_cache,
                last_updated: 0,
                entries: seed_entries(),
            };
            registry.save()?;
            return Ok(registry);
        }
        let raw = fs::read_to_string(&local_cache).map_err(|err| PackError::Io(err.to_string()))?;
        let mut registry: Self =
            serde_json::from_str(&raw).map_err(|err| PackError::Format(err.to_string()))?;
        registry.local_cache = local_cache;
        Ok(registry)
    }

    pub fn save(&mut self) -> Result<(), PackError> {
        self.last_updated = Utc::now().timestamp() as u64;
        if let Some(parent) = self.local_cache.parent() {
            fs::create_dir_all(parent).map_err(|err| PackError::Io(err.to_string()))?;
        }
        let raw =
            serde_json::to_string_pretty(self).map_err(|err| PackError::Format(err.to_string()))?;
        fs::write(&self.local_cache, raw).map_err(|err| PackError::Io(err.to_string()))
    }

    pub fn get(&self, pack_id: Uuid) -> Option<PackRegistryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.pack_id == pack_id)
            .cloned()
    }

    pub fn register_local_pack(&mut self, pack: &AepPack, path: &Path) -> Result<(), PackError> {
        let path_string = path.to_string_lossy().to_string();
        self.entries
            .retain(|entry| entry.pack_id != pack.header.pack_id);
        self.entries.push(PackRegistryEntry {
            pack_id: pack.header.pack_id,
            pack_name: pack.header.pack_name.clone(),
            pack_version: format!("{}.0.0", pack.header.pack_version),
            domain: pack.header.domain.clone(),
            subdomain: pack.header.subdomain.clone(),
            description: pack.header.description.clone(),
            curator: pack.header.curator.clone(),
            download_url: path_string,
            size_bytes: pack.header.pack_size_bytes,
            anchor_count: pack.stats.anchor_count,
            avg_trust_score: pack.stats.avg_trust_score,
            estimated_hit_rate_improvement: pack.stats.estimated_hit_rate_improvement,
            estimated_compression_improvement: pack.stats.estimated_compression_improvement,
            shanway_verified: true,
            created_at: pack.header.created_at,
            tags: vec![pack.header.domain.clone()],
        });
        self.save()
    }

    pub fn find_relevant_packs(
        &self,
        usage_profile: &UsageProfile,
        min_gain: f32,
    ) -> Vec<PackRegistryEntry> {
        let mut relevant = self
            .entries
            .iter()
            .filter(|entry| entry.estimated_hit_rate_improvement >= min_gain)
            .filter(|entry| {
                usage_profile
                    .dominant_domains
                    .iter()
                    .any(|(domain, _)| sanitize(domain).contains(&sanitize(&entry.domain)))
                    || usage_profile.active_signal_types.iter().any(|signal_type| {
                        entry
                            .tags
                            .iter()
                            .any(|tag| tag.eq_ignore_ascii_case(&format!("{:?}", signal_type)))
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        relevant.sort_by(|left, right| {
            right
                .estimated_hit_rate_improvement
                .partial_cmp(&left.estimated_hit_rate_improvement)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        relevant
    }
}

impl PackManager {
    pub fn new(vault: Arc<VaultAccessLayer>, registry: Arc<RwLock<PackRegistry>>) -> Self {
        let install_state_path = PathBuf::from("data")
            .join("rust_shell")
            .join("packs")
            .join("installed_packs.json");
        let installed_packs = if install_state_path.exists() {
            fs::read_to_string(&install_state_path)
                .ok()
                .and_then(|raw| serde_json::from_str::<HashMap<Uuid, InstalledPack>>(&raw).ok())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        Self {
            vault,
            registry,
            installed_packs,
            install_state_path,
            engine: EnginePipeline::new(),
        }
    }

    pub fn installed_packs(&self) -> &HashMap<Uuid, InstalledPack> {
        &self.installed_packs
    }

    pub async fn download_and_install(
        &mut self,
        pack_id: Uuid,
        user_confirmed: bool,
    ) -> Result<InstallResult, PackError> {
        if !user_confirmed {
            return Err(PackError::UserConfirmationRequired);
        }
        let entry = self
            .registry
            .read()
            .map_err(|_| PackError::Io("Pack-Registry konnte nicht gelesen werden".to_owned()))?
            .get(pack_id)
            .ok_or_else(|| {
                PackError::NotFound("Pack ist im Registry-Index nicht vorhanden".to_owned())
            })?;
        let before = self.vault.current_hit_rate().map_err(map_vault_error)?;
        let pack = self.load_pack(&entry)?;
        pack.verify(&self.engine)?;
        for anchor in &pack.anchors {
            let verification = self
                .vault
                .verify_anchor_record(anchor)
                .map_err(map_vault_error)?;
            if !verification.approved {
                return Err(PackError::Vault(
                    verification
                        .rejection_reason
                        .unwrap_or_else(|| "Pack-Anker wurde lokal abgelehnt".to_owned()),
                ));
            }
            let submission = RawAnchorSubmission {
                anchor_id: anchor.anchor_id,
                signal_type: anchor.signal_type,
                domain: anchor.domain.clone(),
                pattern_positions: anchor.pattern_positions.clone(),
                frequency_signature: anchor.frequency_signature.clone(),
                fractal_dimension: anchor.fractal_dimension,
                entropy_profile: anchor.entropy_profile,
                benford_score: anchor.benford_score,
                zipf_alpha: anchor.zipf_alpha,
                coherence_index: anchor.coherence_index,
                lossless_confirmed: anchor.lossless_confirmed,
            };
            let _ = self
                .vault
                .submit_anchor_sync(submission, SubmissionSource::GitHubPR)
                .map_err(map_vault_error)?;
        }
        let after = self.vault.current_hit_rate().map_err(map_vault_error)?;
        let installed = InstalledPack {
            entry: entry.clone(),
            installed_at: Utc::now().timestamp() as u64,
            anchor_ids_added: pack.anchors.iter().map(|anchor| anchor.anchor_id).collect(),
            hit_rate_before: before,
            hit_rate_after: after,
        };
        self.installed_packs.insert(pack_id, installed);
        self.save_state()?;
        Ok(InstallResult {
            pack_id,
            pack_name: entry.pack_name,
            anchors_added: pack.anchors.len(),
            hit_rate_before: before,
            hit_rate_after: after,
        })
    }

    pub fn download_and_install_sync(
        &mut self,
        pack_id: Uuid,
        user_confirmed: bool,
    ) -> Result<InstallResult, PackError> {
        if !user_confirmed {
            return Err(PackError::UserConfirmationRequired);
        }
        let entry = self
            .registry
            .read()
            .map_err(|_| PackError::Io("Pack-Registry konnte nicht gelesen werden".to_owned()))?
            .get(pack_id)
            .ok_or_else(|| {
                PackError::NotFound("Pack ist im Registry-Index nicht vorhanden".to_owned())
            })?;
        let before = self.vault.current_hit_rate().map_err(map_vault_error)?;
        let pack = self.load_pack(&entry)?;
        pack.verify(&self.engine)?;
        for anchor in &pack.anchors {
            let verification = self
                .vault
                .verify_anchor_record(anchor)
                .map_err(map_vault_error)?;
            if !verification.approved {
                return Err(PackError::Vault(
                    verification
                        .rejection_reason
                        .unwrap_or_else(|| "Pack-Anker wurde lokal abgelehnt".to_owned()),
                ));
            }
            let submission = RawAnchorSubmission {
                anchor_id: anchor.anchor_id,
                signal_type: anchor.signal_type,
                domain: anchor.domain.clone(),
                pattern_positions: anchor.pattern_positions.clone(),
                frequency_signature: anchor.frequency_signature.clone(),
                fractal_dimension: anchor.fractal_dimension,
                entropy_profile: anchor.entropy_profile,
                benford_score: anchor.benford_score,
                zipf_alpha: anchor.zipf_alpha,
                coherence_index: anchor.coherence_index,
                lossless_confirmed: anchor.lossless_confirmed,
            };
            let _ = self
                .vault
                .submit_anchor_sync(submission, SubmissionSource::GitHubPR)
                .map_err(map_vault_error)?;
        }
        let after = self.vault.current_hit_rate().map_err(map_vault_error)?;
        self.installed_packs.insert(
            pack_id,
            InstalledPack {
                entry: entry.clone(),
                installed_at: Utc::now().timestamp() as u64,
                anchor_ids_added: pack.anchors.iter().map(|anchor| anchor.anchor_id).collect(),
                hit_rate_before: before,
                hit_rate_after: after,
            },
        );
        self.save_state()?;
        Ok(InstallResult {
            pack_id,
            pack_name: entry.pack_name,
            anchors_added: pack.anchors.len(),
            hit_rate_before: before,
            hit_rate_after: after,
        })
    }

    pub async fn uninstall(&mut self, pack_id: Uuid) -> Result<(), PackError> {
        let Some(installed) = self.installed_packs.remove(&pack_id) else {
            return Err(PackError::NotFound("Pack ist nicht installiert".to_owned()));
        };
        for anchor_id in installed.anchor_ids_added {
            let _ = self
                .vault
                .remove_anchor_record(anchor_id)
                .map_err(map_vault_error)?;
        }
        self.save_state()
    }

    fn load_pack(&self, entry: &PackRegistryEntry) -> Result<AepPack, PackError> {
        let path = PathBuf::from(&entry.download_url);
        if path.exists() {
            return AepPack::read_from_path(&path, &self.engine);
        }
        if entry.download_url.starts_with("http://") || entry.download_url.starts_with("https://") {
            return Err(PackError::Download(
                "Remote-Pack-Download bleibt im Rust-Shell-Port fail-closed, bis der Netzpfad fertig portiert ist".to_owned(),
            ));
        }
        let anchors = self
            .vault
            .get_anchors_by_domain(&entry.domain)
            .map_err(map_vault_error)?;
        let mut synthetic = AepPack::new(
            entry.pack_name.clone(),
            entry.domain.clone(),
            entry.subdomain.clone(),
            entry.curator.clone(),
            entry.description.clone(),
            anchors,
        );
        synthetic.sign(&self.engine);
        Ok(synthetic)
    }

    fn save_state(&self) -> Result<(), PackError> {
        if let Some(parent) = self.install_state_path.parent() {
            fs::create_dir_all(parent).map_err(|err| PackError::Io(err.to_string()))?;
        }
        let raw = serde_json::to_string_pretty(&self.installed_packs)
            .map_err(|err| PackError::Format(err.to_string()))?;
        fs::write(&self.install_state_path, raw).map_err(|err| PackError::Io(err.to_string()))
    }
}

impl ShanwayPackAdvisor {
    pub fn new(registry: Arc<RwLock<PackRegistry>>) -> Self {
        Self::with_bus(registry, BusPublisher::noop())
    }

    pub fn with_bus(registry: Arc<RwLock<PackRegistry>>, bus: BusPublisher) -> Self {
        Self {
            registry,
            last_recommendation: HashMap::new(),
            cooldown_secs: 86_400,
            bus,
        }
    }

    pub fn evaluate_and_recommend(&mut self, profile: &UsageProfile) -> Vec<PackRecommendation> {
        let Ok(registry) = self.registry.read() else {
            return Vec::new();
        };
        let mut output = Vec::new();
        for entry in registry.find_relevant_packs(profile, 0.05) {
            if self
                .last_recommendation
                .get(&entry.pack_id)
                .map(|ts| (Utc::now().timestamp() as u64).saturating_sub(*ts) < self.cooldown_secs)
                .unwrap_or(false)
            {
                continue;
            }
            self.last_recommendation
                .insert(entry.pack_id, Utc::now().timestamp() as u64);
            self.bus
                .publish(BusEvent::PackRecommended(PackRecommendedEvent {
                    pack_id: entry.pack_id.to_string(),
                    pack_name: entry.pack_name.clone(),
                    domain: entry.domain.clone(),
                    size_mb: entry.size_bytes as f32 / 1_048_576.0,
                    estimated_hit_rate_improvement: entry.estimated_hit_rate_improvement,
                    cooldown_respected: true,
                }));
            output.push(PackRecommendation {
                pack_id: entry.pack_id,
                title: entry.pack_name.clone(),
                message: format!(
                    "Pack verfuegbar: '{}' | Domaene {} | Hit-Rate +{:.0}% | Kompression +{:.1}% | Download bleibt optional.",
                    entry.pack_name,
                    entry.domain,
                    entry.estimated_hit_rate_improvement * 100.0,
                    entry.estimated_compression_improvement * 100.0
                ),
                estimated_hit_rate_improvement: entry.estimated_hit_rate_improvement,
                estimated_compression_improvement: entry.estimated_compression_improvement,
            });
        }
        output
    }

    pub async fn download_pack(
        &self,
        pack_id: Uuid,
        user_confirmed: bool,
    ) -> Result<(), PackError> {
        if !user_confirmed {
            return Err(PackError::UserConfirmationRequired);
        }
        self.bus
            .publish(BusEvent::PackDownloadConfirmed(PackDownloadEvent {
                pack_id: pack_id.to_string(),
                confirmed_by_user: true,
                started_at: Utc::now().timestamp() as u64,
            }));
        Ok(())
    }
}

impl AutoPackGenerator {
    pub fn new(vault: Arc<VaultAccessLayer>) -> Self {
        Self {
            vault,
            output_dir: PathBuf::from("data")
                .join("rust_shell")
                .join("generated_packs"),
            engine: EnginePipeline::new(),
        }
    }

    pub async fn generate_pack(
        &self,
        domain: impl Into<String>,
        user_confirmed: bool,
    ) -> Result<GeneratedPack, PackError> {
        if !user_confirmed {
            return Err(PackError::UserConfirmationRequired);
        }
        let domain = sanitize(&domain.into());
        let anchors = self
            .vault
            .get_anchors_by_domain(&domain)
            .map_err(map_vault_error)?
            .into_iter()
            .filter(|anchor| anchor.trust_score >= 0.75 && anchor.lossless_confirmed)
            .collect::<Vec<_>>();
        let mut pack = AepPack::new(
            format!("{domain} anchor pack"),
            domain.clone(),
            None,
            "auto",
            "Automatisch aus lokal bestaetigten Ankern generiert.",
            anchors,
        );
        let path = self.output_dir.join(format!("{}.aep", pack.header.pack_id));
        pack.write_to_path(&path, &self.engine)?;
        Ok(GeneratedPack {
            pack_id: pack.header.pack_id,
            path,
            anchor_count: pack.anchors.len(),
            domain,
        })
    }

    pub fn generate_pack_sync(
        &self,
        domain: impl Into<String>,
        user_confirmed: bool,
    ) -> Result<GeneratedPack, PackError> {
        if !user_confirmed {
            return Err(PackError::UserConfirmationRequired);
        }
        let domain = sanitize(&domain.into());
        let anchors = self
            .vault
            .get_anchors_by_domain(&domain)
            .map_err(map_vault_error)?
            .into_iter()
            .filter(|anchor| anchor.trust_score >= 0.75 && anchor.lossless_confirmed)
            .collect::<Vec<_>>();
        let mut pack = AepPack::new(
            format!("{domain} anchor pack"),
            domain.clone(),
            None,
            "auto",
            "Automatisch aus lokal bestaetigten Ankern generiert.",
            anchors,
        );
        let path = self.output_dir.join(format!("{}.aep", pack.header.pack_id));
        pack.write_to_path(&path, &self.engine)?;
        Ok(GeneratedPack {
            pack_id: pack.header.pack_id,
            path,
            anchor_count: pack.anchors.len(),
            domain,
        })
    }
}

fn derive_stats(anchors: &[PublicAnchorRecord]) -> AepStats {
    let avg_trust_score = if anchors.is_empty() {
        0.0
    } else {
        anchors.iter().map(|anchor| anchor.trust_score).sum::<f32>() / anchors.len() as f32
    };
    let avg_coherence = if anchors.is_empty() {
        0.0
    } else {
        (anchors
            .iter()
            .map(|anchor| anchor.coherence_index)
            .sum::<f64>()
            / anchors.len() as f64) as f32
    };
    let compatible_signal_types = anchors.iter().fold(0u64, |mask, anchor| {
        mask | (1u64 << (anchor.signal_type as u8 & 0x07))
    });
    AepStats {
        anchor_count: anchors.len() as u32,
        avg_trust_score,
        avg_coherence,
        estimated_hit_rate_improvement: (anchors.len() as f32 / (anchors.len() as f32 + 96.0))
            .clamp(0.0, 1.0)
            * 0.20,
        estimated_compression_improvement: (anchors.len() as f32 / (anchors.len() as f32 + 128.0))
            .clamp(0.0, 1.0)
            * 0.14,
        compatible_signal_types,
    }
}

fn seed_entries() -> Vec<PackRegistryEntry> {
    vec![
        PackRegistryEntry {
            pack_id: Uuid::new_v4(),
            pack_name: "Language German Foundations".to_owned(),
            pack_version: "1.0.0".to_owned(),
            domain: "language_german".to_owned(),
            subdomain: Some("text_code".to_owned()),
            description: "Deutsche Text-, Markdown- und Code-Anker fuer schnellen Vault-Hit."
                .to_owned(),
            curator: "official".to_owned(),
            download_url: "data/rust_shell/packs/official_language_german.aep".to_owned(),
            size_bytes: 786_432,
            anchor_count: 1024,
            avg_trust_score: 0.82,
            estimated_hit_rate_improvement: 0.12,
            estimated_compression_improvement: 0.08,
            shanway_verified: true,
            created_at: Utc::now().timestamp() as u64,
            tags: vec![
                "Text / Code".to_owned(),
                "PlainText".to_owned(),
                "Code".to_owned(),
            ],
        },
        PackRegistryEntry {
            pack_id: Uuid::new_v4(),
            pack_name: "Image Structure Pack".to_owned(),
            pack_version: "1.0.0".to_owned(),
            domain: "image_editing".to_owned(),
            subdomain: Some("preview".to_owned()),
            description: "Bild- und Vorschau-Anker fuer Render- und Rasterpfade.".to_owned(),
            curator: "official".to_owned(),
            download_url: "data/rust_shell/packs/official_image_structure.aep".to_owned(),
            size_bytes: 655_360,
            anchor_count: 768,
            avg_trust_score: 0.79,
            estimated_hit_rate_improvement: 0.10,
            estimated_compression_improvement: 0.06,
            shanway_verified: true,
            created_at: Utc::now().timestamp() as u64,
            tags: vec!["Bild".to_owned(), "Unknown".to_owned()],
        },
        PackRegistryEntry {
            pack_id: Uuid::new_v4(),
            pack_name: "Security Runtime Pack".to_owned(),
            pack_version: "1.0.0".to_owned(),
            domain: "security".to_owned(),
            subdomain: Some("runtime_signal".to_owned()),
            description: "Sicherheits- und Laufzeit-Anker fuer Beobachtung und Quarantaene."
                .to_owned(),
            curator: "official".to_owned(),
            download_url: "data/rust_shell/packs/official_security_runtime.aep".to_owned(),
            size_bytes: 1_048_576,
            anchor_count: 1536,
            avg_trust_score: 0.85,
            estimated_hit_rate_improvement: 0.15,
            estimated_compression_improvement: 0.10,
            shanway_verified: true,
            created_at: Utc::now().timestamp() as u64,
            tags: vec!["Binaer".to_owned(), "runtime".to_owned()],
        },
    ]
}

fn sanitize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .replace(" / ", "_")
        .replace([' ', '-', '.'], "_")
}

fn map_vault_error(error: VaultAccessError) -> PackError {
    PackError::Vault(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_finds_relevant_pack_for_text_profile() {
        let registry = PackRegistry {
            index_url: String::new(),
            local_cache: PathBuf::new(),
            last_updated: 0,
            entries: seed_entries(),
        };
        let profile = UsageProfile {
            dominant_domains: vec![("language_german".to_owned(), 1.0)],
            active_signal_types: vec![SignalType::PlainText],
            current_hit_rate: 0.2,
        };
        let packs = registry.find_relevant_packs(&profile, 0.05);
        assert!(!packs.is_empty());
        assert!(packs.iter().any(|pack| pack.domain == "language_german"));
    }

    #[test]
    fn aep_signature_roundtrip_is_valid() {
        let engine = EnginePipeline::new();
        let mut pack = AepPack::new("demo", "security", None, "auto", "demo", Vec::new());
        pack.sign(&engine);
        pack.verify(&engine).unwrap();
    }
}
