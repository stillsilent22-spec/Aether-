use iced::event;
use iced::window;
use std::collections::BTreeMap;
use crate::state::RegisterEntry;
use iced::widget::progress_bar;
use iced::theme::Palette;
use iced::Task;
use iced::keyboard;
use iced::time;
use iced::Settings;
use iced::mouse;
use crate::py_bridge::{set_symbiont_enabled, set_symbiont_endpoint};
use crate::symbiont_rpc;
use iced::widget::canvas;
use iced::{
    Alignment, Background, Border, Color, Element, Length, Point, Rectangle, Size, Subscription, Theme,
};
use iced::widget::{Column, Row};
use std::path::{Path, PathBuf};
use std::ffi::OsStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use crate::auth::{AuthStore, UserRecord};
use crate::state::{StateStore, ChatMessage, PrivateThread, GroupRoom};
use crate::security::{SecurityMonitor, SecuritySnapshot, SecurityAuditEvent};
use crate::key_vault::DataKey;
use crate::swarm_bootstrap::{SwarmStartupStatus, probe_swarm_startup};
use crate::launcher_dashboard::{LauncherState, LauncherMode, ServiceStatus, BuildTaskResult};
use crate::py_bridge::{PythonBridgeManager, load_hybrid_settings, read_hybrid_status};
use crate::aef::{AefDecodeResult, AefDecoder, AefEncoder, EnginePipeline, VaultStore};
use crate::hardware;
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use std::io::Write;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Home, Control, Symbiont, SwarmOps, Privacy, Chat,
    Data, Anchors, Logs, Settings,
    ADE, FlowSphere, StructureMap, Gaming, Media, Research, Rekonstruktion, Launcher, Imprint,
}

impl Tab {
    pub fn label(&self) -> &'static str {
        match self {
            Tab::Home => "Home",
            Tab::Control => "Control Center",
            Tab::Symbiont => "Symbiont",
            Tab::SwarmOps => "Swarm Ops",
            Tab::Privacy => "Privacy",
            Tab::Chat => "Chat",
            Tab::Data => "Data",
            Tab::Anchors => "Anchors",
            Tab::Logs => "Logs",
            Tab::Settings => "Settings",
            Tab::ADE => "Delta-Analyse",
            Tab::FlowSphere => "FlowSphere",
            Tab::StructureMap => "Delta Convergence",
            Tab::Gaming => "Gaming",
            Tab::Media => "Media",
            Tab::Research => "Research",
            Tab::Rekonstruktion => "Rekonstruktion",
            Tab::Launcher => "Launcher",
            Tab::Imprint => "Imprint",
        }
    }
}
// ── Farbkonstanten und Hilfsfunktion ─────────────────────────────
#[allow(non_snake_case, dead_code)]
fn TEXT_H() -> Color { Color::from_rgb8(0xE4, 0xEE, 0xF2) } // Headline/Primary Text
#[allow(non_snake_case, dead_code)]
fn TEXT_M() -> Color { Color::from_rgb8(0xA8, 0xC4, 0xD8) } // Medium/Secondary Text
#[allow(non_snake_case, dead_code)]
fn TEXT_D() -> Color { Color::from_rgb8(0x70, 0x90, 0xA8) } // Disabled/Dimmed Text
#[allow(non_snake_case, dead_code)]
fn ACCENT() -> Color { Color::from_rgb8(0x66, 0x40, 0xCD) } // Main Accent
#[allow(non_snake_case, dead_code)]
fn ACCENT2() -> Color { Color::from_rgb8(0x4C, 0xD9, 0x6E) } // Secondary Accent
#[allow(non_snake_case, dead_code)]
fn BG_CARD() -> Color { Color::from_rgb8(0x1E, 0x1A, 0x2A) } // Card Background
#[allow(non_snake_case, dead_code)]
fn BG_CARD2() -> Color { Color::from_rgb8(0x24, 0x20, 0x36) } // Card Background 2
#[allow(non_snake_case, dead_code)]
fn BG_BASE() -> Color { Color::from_rgb8(0x12, 0x11, 0x1E) } // Main Background
#[allow(non_snake_case, dead_code)]
fn BORDER() -> Color { Color::from_rgb8(0x2A, 0x28, 0x3C) } // Standard Border
#[allow(non_snake_case, dead_code)]
fn BORDER_ACT() -> Color { Color::from_rgb8(0x66, 0x40, 0xCD) } // Active Border
#[allow(non_snake_case, dead_code)]
fn DANGER() -> Color { Color::from_rgb8(0xC6, 0x6A, 0x6A) } // Danger/Alert
#[allow(non_snake_case, dead_code)]
fn WARN() -> Color { Color::from_rgb8(0xD4, 0xA0, 0x42) } // Warning/Notice

const FULL_WINDOW_WIDTH: f32 = 1180.0;
const FULL_WINDOW_HEIGHT: f32 = 700.0;
const OVERLAY_WINDOW_WIDTH: f32 = 960.0;
const OVERLAY_WINDOW_HEIGHT: f32 = 72.0;

/// Helper to allow c(NAME) for color constants (for compatibility with codebase usage)
fn c(color: Color) -> Color { color }

// ---------------------------------------------------------------------------
// FlowSphere – Sub-Tab und History-Eintrag
// ---------------------------------------------------------------------------
/// Drei Zeitebenen der Musteranalyse in FlowSphere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowSphereSubTab {
    #[default]
    Session,  // Lokal – aktuelle Sitzung
    History,  // Lokal – laengerer Zeitraum (persistiert)
    Global,   // Global – Swarm-Knoten-Vergleich
}

/// Ein gespeicherter Analyseeintrag fuer die FlowSphere-History.
/// Enthaelt alle 12 Mustererkennungsmetriken normiert auf [0,1].
/// Reihenfolge: Shannon | PermEnt | KatzFD | Zipf | Benford | Fourier |
///              Noether | H-Lambda | Symmetrie | SCE | DeltaKonv | Bayes
#[derive(Debug, Clone)]
pub struct FlowSphereEntry {
    pub timestamp_secs: u64,      // Unix-Sekunden der Analyse selbst
    pub source_timestamp_secs: Option<u64>, // Aus Datei-Metadaten extrahiertes Quelldatum
    pub manual_timestamp_secs: Option<u64>, // Vom Nutzer gesetztes Bezugsdatum fuer Visualisierungen
    pub source_label: String,     // Dateiname / Signalbezeichner
    pub domain_hint: String,      // z.B. "Blutbild", "Klimadaten", "DNA", ""
    pub broadcast_hint: String,   // Optionales Nutzerlabel nur fuer Broadcast-Abwaegungen
    pub source_hash: String,      // SHA/Pipeline-Hash zur Deduplizierung
    pub metrics: [f32; 12],       // Normierte Metrik-Werte [0,1]
    pub anomaly_flags: Vec<String>,
}

impl FlowSphereEntry {
    /// Baut einen Eintrag aus einem CapsuleViewState + CascadeMetrics.
    fn from_capsule(
        capsule: &CapsuleViewState,
        cascade: Option<&CascadeMetrics>,
        stability: f32,
    ) -> Self {
        let entropy        = (capsule.entropy / 8.0).clamp(0.0, 1.0);
        let perm_entropy   = capsule.perm_entropy.clamp(0.0, 1.0);
        let katz_fd        = (capsule.katz_dimension / 2.0).clamp(0.0, 1.0);
        let zipf           = (capsule.zipf_alpha / 3.0).clamp(0.0, 1.0);
        let benford        = capsule.benford_score.clamp(0.0, 1.0);
        let fourier_raw    = cascade.map(|c| c.fourier_period as f32)
                               .unwrap_or(capsule.periodicity);
        let fourier        = (fourier_raw.ln_1p() / 3.912).clamp(0.0, 1.0);
        let noether        = capsule.noether_consistency.clamp(0.0, 1.0);
        let h_lambda       = capsule.h_lambda.clamp(0.0, 1.0);
        let symmetry       = capsule.symmetry.clamp(0.0, 1.0);
        let sce            = capsule.sce_score.clamp(0.0, 1.0);
        let delta_conv     = (1.0 - capsule.delta_ratio).clamp(0.0, 1.0);
        let bayes          = capsule.bayes_confidence.clamp(0.0, 1.0);
        let _ = stability; // reserviert fuer zukuenftige Gewichtung

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            timestamp_secs: now,
            source_timestamp_secs: None,
            manual_timestamp_secs: None,
            source_label: capsule.source_label.clone(),
            domain_hint: capsule.domain_hint.clone(),
            broadcast_hint: String::new(),
            source_hash: capsule.source_hash.clone(),
            metrics: [
                entropy, perm_entropy, katz_fd, zipf, benford, fourier,
                noether, h_lambda, symmetry, sce, delta_conv, bayes,
            ],
            anomaly_flags: capsule.anomaly_flags.clone(),
        }
    }

    /// Wählt den Zeitwert für Graphen und History-Ansichten.
    /// Nutzerlabels bleiben davon strikt getrennt.
    fn visual_timestamp_secs(&self, temporal_metadata_consent: bool) -> u64 {
        if temporal_metadata_consent {
            self.source_timestamp_secs
                .or(self.manual_timestamp_secs)
                .unwrap_or(self.timestamp_secs)
        } else {
            self.manual_timestamp_secs.unwrap_or(self.timestamp_secs)
        }
    }

    fn visual_timestamp_origin(&self, temporal_metadata_consent: bool) -> &'static str {
        if temporal_metadata_consent && self.source_timestamp_secs.is_some() {
            "meta"
        } else if self.manual_timestamp_secs.is_some() {
            "manual"
        } else {
            "analysis"
        }
    }

    /// Kosinus-Aehnlichkeit zwischen diesem Eintrag und einem Metrik-Vektor [0,1].
    fn cosine_similarity(&self, other_metrics: &[f32; 12]) -> f32 {
        let dot: f32   = self.metrics.iter().zip(other_metrics.iter()).map(|(a,b)| a*b).sum();
        let mag_a: f32 = self.metrics.iter().map(|v| v*v).sum::<f32>().sqrt();
        let mag_b: f32 = other_metrics.iter().map(|v| v*v).sum::<f32>().sqrt();
        if mag_a < 1e-6 || mag_b < 1e-6 { 0.0 } else { (dot / (mag_a * mag_b)).clamp(0.0, 1.0) }
    }

    /// Gibt Achsen-Indizes zurueck wo dieser Eintrag und der verglichene Metrik-Vektor
    /// sich stark widersprechen (einer >0.65, der andere <0.35 auf derselben Achse).
    fn contradiction_axes(&self, other_metrics: &[f32; 12]) -> Vec<usize> {
        self.metrics.iter().zip(other_metrics.iter()).enumerate()
            .filter_map(|(i, (a, b))| {
                if (*a > 0.65 && *b < 0.35) || (*a < 0.35 && *b > 0.65) { Some(i) } else { None }
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct CascadeMetrics {
    pub entropy: f64,
    pub zipf_alpha: f64,
    pub benford_score: f64,
    pub fourier_period: f64,
    pub katz_dimension: f64,
    pub perm_entropy: f64,
    pub delta_convergence: f64,
    pub noether_consistency: f64,
    pub trust_score: f64,
    pub anomaly_flags: Vec<String>,
}

impl CascadeMetrics {
    fn from_capsule_state(capsule: &CapsuleViewState, _structure_map: &StructureMapViewState) -> Self {
        Self {
            entropy: capsule.entropy as f64,
            zipf_alpha: capsule.zipf_alpha as f64,
            benford_score: capsule.benford_score as f64,
            fourier_period: capsule.periodicity as f64,
            katz_dimension: capsule.katz_dimension as f64,
            perm_entropy: capsule.perm_entropy as f64,
            delta_convergence: (1.0 - capsule.delta_ratio).clamp(0.0, 1.0) as f64,
            noether_consistency: capsule.noether_consistency as f64,
            trust_score: capsule.trust_score as f64,
            anomaly_flags: capsule.anomaly_flags.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CapsuleViewState {
    source_label: String,
    source_type: String,
    trigger: String,
    domain_hint: String,
    source_hash: String,
    source_scope: String,
    privacy_class: String,
    artifact_class: String,
    segment_count: u32,
    segment_manifest_hash: String,
    size_bytes: u64,
    entropy: f32,
    h_lambda: f32,
    symmetry: f32,
    periodicity: f32,
    zipf_alpha: f32,
    benford_score: f32,
    katz_dimension: f32,
    perm_entropy: f32,
    sce_score: f32,
    bayes_confidence: f32,
    trust_score: f32,
    noether_consistency: f32,
    delta_ratio: f32,
    changed_bytes: u64,
    anomaly_flags: Vec<String>,
    // ── Vier theoretische Limits — observational only, nie in Pipeline ──
    /// Kolmogorov-Proxy (zlib-Komprimierbarkeit), 0–1 (höher = strukturierter)
    kolmogorov_k: f32,
    /// MDL-Modellabdeckung: Anteil der Bytes die durch Anker erklärt werden (L(Modell)/L(Signal))
    anchor_coverage_ratio: f32,
}

impl CapsuleViewState {
    fn from_pipeline_result(result: &serde_json::Value) -> Self {
        let capsule = result.get("capsule").unwrap_or(&serde_json::Value::Null);
        let capsule_meta = capsule.get("capsule").unwrap_or(&serde_json::Value::Null);
        let envelope = capsule.get("envelope").unwrap_or(&serde_json::Value::Null);
        let metrics = capsule.get("metrics").unwrap_or(&serde_json::Value::Null);
        let local_delta = capsule.get("local_delta").unwrap_or(&serde_json::Value::Null);

        Self {
            source_label: envelope.get("source_label").and_then(|value| value.as_str()).unwrap_or_default().to_owned(),
            source_type: envelope
                .get("source_type")
                .and_then(|value| value.as_str())
                .unwrap_or_else(|| capsule_meta.get("source_type").and_then(|value| value.as_str()).unwrap_or_default())
                .to_owned(),
            trigger: capsule_meta.get("trigger").and_then(|value| value.as_str()).unwrap_or_default().to_owned(),
            domain_hint: envelope
                .get("domain_hint")
                .and_then(|value| value.as_str())
                .unwrap_or_else(|| capsule_meta.get("domain_hint").and_then(|value| value.as_str()).unwrap_or_default())
                .to_owned(),
            source_hash: envelope.get("source_hash").and_then(|value| value.as_str()).unwrap_or_default().to_owned(),
            source_scope: envelope.get("source_scope").and_then(|value| value.as_str()).unwrap_or("explicit_local_signal").to_owned(),
            privacy_class: envelope.get("privacy_class").and_then(|value| value.as_str()).unwrap_or("explicit_user_signal").to_owned(),
            artifact_class: envelope.get("artifact_class").and_then(|value| value.as_str()).unwrap_or("private_signal").to_owned(),
            segment_count: envelope.get("segment_count").and_then(|value| value.as_u64()).unwrap_or(1) as u32,
            segment_manifest_hash: envelope.get("segment_manifest_hash").and_then(|value| value.as_str()).unwrap_or_default().to_owned(),
            size_bytes: envelope.get("size_bytes").and_then(|value| value.as_u64()).unwrap_or_default(),
            entropy: value_as_f32(metrics.get("entropy")),
            h_lambda: value_as_f32(metrics.get("h_lambda")),
            symmetry: value_as_f32(metrics.get("symmetry")),
            periodicity: value_as_f32(metrics.get("periodicity")),
            zipf_alpha: value_as_f32(metrics.get("zipf_alpha")),
            benford_score: value_as_f32(metrics.get("benford_score")),
            katz_dimension: value_as_f32(metrics.get("katz_dimension")),
            perm_entropy: value_as_f32(metrics.get("perm_entropy")),
            sce_score: value_as_f32(metrics.get("sce_score")),
            bayes_confidence: value_as_f32(metrics.get("bayes_confidence")),
            trust_score: {
                let raw = value_as_f32(metrics.get("trust_score"));
                if raw > 0.0 { raw } else {
                    let sym = value_as_f32(metrics.get("symmetry"));
                    let bc  = value_as_f32(metrics.get("bayes_confidence"));
                    let nc  = value_as_f32(metrics.get("noether_consistency"));
                    (0.40 * sym + 0.35 * bc + 0.25 * nc).clamp(0.0, 1.0)
                }
            },
            noether_consistency: value_as_f32(metrics.get("noether_consistency")),
            delta_ratio: value_as_f32(metrics.get("delta_ratio")),
            changed_bytes: local_delta.get("changed_bytes").and_then(|value| value.as_u64()).unwrap_or_default(),
            anomaly_flags: capsule
                .get("anomaly_flags")
                .or_else(|| result.get("anomaly_flags"))
                .and_then(|value| value.as_array())
                .map(|values| values.iter().filter_map(|value| value.as_str().map(str::to_owned)).collect())
                .unwrap_or_default(),
            // Kolmogorov-Proxy: aus sce_signature (bereits berechnet, kein neuer Pass)
            kolmogorov_k: metrics
                .get("sce_signature")
                .and_then(|s| s.get("kolmogorov_k"))
                .and_then(|v| v.as_f64())
                .map(|v| v as f32)
                .unwrap_or(0.0),
            // MDL-Abdeckung: anchor_coverage_ratio direkt aus metrics
            anchor_coverage_ratio: value_as_f32(metrics.get("anchor_coverage_ratio")),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct StructureMapViewState {
    region_label: String,
    node_count: usize,
    edge_count: usize,
    anchor_count: usize,
    anomaly_count: u32,
    locked: bool,
    trust_score: f32,
    coherence_score: f32,
}

impl StructureMapViewState {
    fn from_json(value: &serde_json::Value) -> Self {
        Self {
            region_label: value.get("region_label").and_then(|item| item.as_str()).unwrap_or("REGION LOCAL").to_owned(),
            node_count: value.get("node_count").and_then(|item| item.as_u64()).unwrap_or_default() as usize,
            edge_count: value.get("edge_count").and_then(|item| item.as_u64()).unwrap_or_default() as usize,
            anchor_count: value.get("anchor_count").and_then(|item| item.as_u64()).unwrap_or_default() as usize,
            anomaly_count: value.get("anomaly_count").and_then(|item| item.as_u64()).unwrap_or_default() as u32,
            locked: value.get("locked").and_then(|item| item.as_bool()).unwrap_or(false),
            trust_score: value_as_f32(value.get("trust_score")),
            coherence_score: value_as_f32(value.get("coherence_score")),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct AelabViewState {
    fitness: f32,
    lossless: f32,
    nodes: u32,
    depth: u32,
    has_anchor: bool,
    evolved: bool,
    signature: String,
    seed_label: String,
    seed_bucket: String,
    seed_coupling: f32,
    seed_coherence: f32,
    seed_utility: f32,
    seed_times_used: u32,
    has_sequence: bool,
    has_bridge: bool,
    has_xor: bool,
    has_interfere: bool,
    vault_root: String,
    vault_total_entries: u32,
    vault_main_entries: u32,
    vault_inactive_entries: u32,
    vault_recovered_entries: u32,
    vault_integrity_ok: bool,
}

impl AelabViewState {
    fn from_result(result: &serde_json::Value) -> Option<Self> {
        let aelab = result.get("aelab")?;
        if !aelab.is_object() {
            return None;
        }
        let selected_seed = aelab.get("selected_seed").unwrap_or(&serde_json::Value::Null);
        let vault = aelab.get("vault").unwrap_or(&serde_json::Value::Null);
        Some(Self {
            fitness: value_as_f32(aelab.get("fitness")),
            lossless: value_as_f32(aelab.get("lossless")),
            nodes: aelab.get("nodes").and_then(|value| value.as_u64()).unwrap_or_default() as u32,
            depth: aelab.get("depth").and_then(|value| value.as_u64()).unwrap_or_default() as u32,
            has_anchor: aelab.get("has_anchor").and_then(|value| value.as_bool()).unwrap_or(false),
            evolved: aelab.get("evolved").and_then(|value| value.as_bool()).unwrap_or(false),
            signature: aelab.get("signature").and_then(|value| value.as_str()).unwrap_or_default().to_owned(),
            seed_label: selected_seed.get("label").and_then(|value| value.as_str()).unwrap_or_default().to_owned(),
            seed_bucket: selected_seed.get("bucket").and_then(|value| value.as_str()).unwrap_or_default().to_owned(),
            seed_coupling: value_as_f32(selected_seed.get("coupling")),
            seed_coherence: value_as_f32(selected_seed.get("coherence")),
            seed_utility: value_as_f32(selected_seed.get("utility_score")),
            seed_times_used: selected_seed.get("times_used").and_then(|value| value.as_u64()).unwrap_or_default() as u32,
            has_sequence: selected_seed.get("has_sequence").and_then(|value| value.as_bool()).unwrap_or(false),
            has_bridge: selected_seed.get("has_bridge").and_then(|value| value.as_bool()).unwrap_or(false),
            has_xor: selected_seed.get("has_xor").and_then(|value| value.as_bool()).unwrap_or(false),
            has_interfere: selected_seed.get("has_interfere").and_then(|value| value.as_bool()).unwrap_or(false),
            vault_root: vault.get("root").and_then(|value| value.as_str()).unwrap_or_default().to_owned(),
            vault_total_entries: vault.get("total_entries").and_then(|value| value.as_u64()).unwrap_or_default() as u32,
            vault_main_entries: vault.get("main_entries").and_then(|value| value.as_u64()).unwrap_or_default() as u32,
            vault_inactive_entries: vault.get("inactive_entries").and_then(|value| value.as_u64()).unwrap_or_default() as u32,
            vault_recovered_entries: vault.get("recovered_entries").and_then(|value| value.as_u64()).unwrap_or_default() as u32,
            vault_integrity_ok: vault.get("integrity_ok").and_then(|value| value.as_bool()).unwrap_or(false),
        })
    }
}

#[derive(Debug, Clone, Default)]
struct CompressionViewState {
    format: String,
    original_bytes: u64,
    changed_bytes: u64,
    compressed_bytes: u64,
    ratio: f32,
    gain_percent: f32,
}

impl CompressionViewState {
    fn from_result(result: &serde_json::Value) -> Option<Self> {
        let compression = result.get("compression")?;
        if !compression.is_object() {
            return None;
        }
        let changed_bytes = result
            .get("capsule")
            .and_then(|value| value.get("local_delta"))
            .and_then(|value| value.get("changed_bytes"))
            .and_then(|value| value.as_u64())
            .unwrap_or_default();
        Some(Self {
            format: compression.get("format").and_then(|value| value.as_str()).unwrap_or("zlib").to_owned(),
            original_bytes: compression.get("original_bytes").and_then(|value| value.as_u64()).unwrap_or_default(),
            changed_bytes,
            compressed_bytes: compression.get("compressed_bytes").and_then(|value| value.as_u64()).unwrap_or_default(),
            ratio: value_as_f32(compression.get("ratio")),
            gain_percent: value_as_f32(compression.get("gain_percent")),
        })
    }
}

#[derive(Debug, Clone, Default)]
struct ReconstructionAuditViewState {
    quality_score: f32,
    verified: bool,
    error_count: u32,
    error_fields: Vec<String>,
    path_steps: Vec<String>,
    compressibility: f32,
    anchor_coverage: f32,
}

impl ReconstructionAuditViewState {
    fn from_result(result: &serde_json::Value) -> Option<Self> {
        let reconstruction = result.get("reconstruction")?;
        if !reconstruction.is_object() {
            return None;
        }
        Some(Self {
            quality_score: value_as_f32(reconstruction.get("quality_score")),
            verified: reconstruction.get("verified").and_then(|value| value.as_bool()).unwrap_or(false),
            error_count: reconstruction.get("error_count").and_then(|value| value.as_u64()).unwrap_or_default() as u32,
            error_fields: reconstruction
                .get("error_fields")
                .and_then(|value| value.as_array())
                .map(|values| values.iter().filter_map(|value| value.as_str().map(str::to_owned)).collect())
                .unwrap_or_default(),
            path_steps: reconstruction
                .get("path")
                .and_then(|value| value.as_array())
                .map(|values| values.iter().filter_map(|value| value.as_str().map(str::to_owned)).collect())
                .unwrap_or_default(),
            compressibility: value_as_f32(reconstruction.get("compressibility")),
            anchor_coverage: value_as_f32(reconstruction.get("anchor_coverage")),
        })
    }
}
// Score-Tooltip-Mapping für die UI
pub fn get_score_tooltip(score_name: &str) -> &'static str {
    match score_name {
        "SECURITY" => "Prüft auf verbotene oder gefährliche Inhalte. Nützlich für Blacklist-Checks und Policy Enforcement.",
        "SHANNON" => "Entropie misst die Komplexität und Zufälligkeit der Datenstruktur. Hohe Werte deuten auf Verschlüsselung, Kompression oder künstliche Muster hin.",
        "H_LAMBDA" => "Restunsicherheit nach Abzug des Vorwissens. Zeigt, wie viel an der Struktur noch unbekannt oder unerklärt ist.",
        "ANCHOR" => "Detektiert natürliche Zahlenverteilungen und mathematische Konstanten. Niedrige Werte können auf künstliche oder manipulierte Strukturen hindeuten.",
        "SYMMETRY" => "Misst die Gleichmäßigkeit und Symmetrie der Verteilung. Hohe Symmetrie kann auf generierte, komprimierte oder manipulierte Daten hindeuten.",
        "DELTA" => "Vergleicht die Struktur mit einer Zufallsreferenz. Hohe Werte zeigen starke Abweichungen oder Muster, niedrige Werte deuten auf Zufall oder starke Obfuskation.",
        "PERIODICITY" => "Erkennt periodische oder wiederkehrende Muster in der Struktur. Hohe Werte bei Protokollen, Musik, maschinellen Daten.",
        "SCE" => "Gesamtkohärenz der Struktur. Hohe Werte deuten auf konsistente, natürliche Muster, niedrige auf Fragmentierung oder Inkonsistenz.",
        "BAYES" => "Bewertet die Übereinstimmung der gefundenen Muster mit bekannten, vertrauenswürdigen Strukturen.",
        "TRUST" => "Gesamteinschätzung aus allen Schichten. Hohe Werte: konsistent, natürlich, vertrauenswürdig. Niedrige Werte: auffällig, künstlich, potenziell manipuliert.",
        _ => "",
    }
}

// Beispiel: Score-Panel mit Tooltips für die Analyse-Ansicht

#[derive(Debug, Clone)]
struct AnchorClusterView {
    title: String,
    descriptor: String,
    item_count: usize,
    total_bytes: u64,
    sample_note: String,
    /// Unix-Sekunden der frühesten Beobachtung in der FlowSphere-History
    first_seen: Option<u64>,
    /// Unix-Sekunden der jüngsten Beobachtung in der FlowSphere-History
    last_seen: Option<u64>,
    /// Wie oft Einträge dieser Gruppe in der Session-History aufgetaucht sind
    observation_count: usize,
}

#[derive(Debug, Clone)]
struct AnalysisSnapshot {
    file_name: String,
    original_size: u64,
    compression_gain_percent: f32,
    anchor_summary: String,
    process_summary: String,
    preview_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GamingProgressRow {
    game_id: String,
    game_label: String,
    players: Vec<String>,
    session_count: u64,
    found_percent: f32,
    improved_percent: f32,
    quorum_ready: bool,
    last_shared_insight: String,
    last_updated: String,
}

const GAMING_PROGRESS_PATH: &str = "data/interbus/gaming_progress_table.json";

#[derive(Debug, Clone)]
struct FileAnalysisResult {
    entry: RegisterEntry,
    snapshot: AnalysisSnapshot,
    byte_hist: Vec<f32>,   // 64-bucket normalized originalbytehistogram
    xor_delta: Vec<f32>,   // 64-bucket |orig−delta| divergence for XOR-compare
    capsule_state: CapsuleViewState,
    structure_map_state: StructureMapViewState,
    aelab_state: Option<AelabViewState>,
    compression_state: Option<CompressionViewState>,
    reconstruction_state: Option<ReconstructionAuditViewState>,
    structure_map_nodes: Vec<Vec<f32>>,
    /// Entstehungsdatum aus Datei-Metadaten (Unix-Sekunden) — nur für Zeitgraph-Tab.
    /// None wenn temporal_metadata_consent=false oder kein Datum gefunden.
    /// NIEMALS in Fingerprint, Gossip oder Anker verwenden.
    source_date_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct LiveRenderAnalysisResult {
    capsule_state: CapsuleViewState,
    structure_map_state: StructureMapViewState,
    aelab_state: Option<AelabViewState>,
    compression_state: Option<CompressionViewState>,
    reconstruction_state: Option<ReconstructionAuditViewState>,
    structure_map_nodes: Vec<Vec<f32>>,
}

// ─── Domain enums & types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppMode { Overlay, Full }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChatContext { Private, Group, SwarmRequest }

/// Eingehende Broadcast-Anfrage: ein Node hat strukturelle Ankermuster-Überschneidungen
/// gefunden und bittet um Kontakt. Kein Inhalt wird übertragen.
#[derive(Debug, Clone)]
struct ChatBroadcastRequest {
    /// Kurzkennung des anfragenden Nodes (kein Klarname, kein Inhalt)
    node_id: String,
    /// Strukturelles Signal das die Anfrage ausgelöst hat (z.B. "noether_break@domain:biology")
    pattern_hint: String,
    /// Domänen-Tag der Überschneidung
    domain_tag: String,
    /// Zeitstempel der Anfrage
    epoch_week: String,
}

/// A pending swarm domain-overlap contact request from a remote node.
#[derive(Debug, Clone)]
struct SwarmOverlapRequest {
    /// Short hash of the local anchor that matched.
    anchor_hash_a: String,
    /// Domain tag assigned by the user (e.g. "biology").
    domain_tag: String,
    /// Structural similarity score, 0.0–1.0.
    structural_score: f32,
    /// Calendar week of the overlap, e.g. "KW12-2026".
    epoch_week: String,
    /// Truncated public key of the remote node (used as chat partner ID).
    remote_node_pubkey: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UiLanguage { German, English }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeProfile { Auto, Balanced, LowPower, Legacy }

#[derive(Debug, Clone, Copy)]
struct ShellPreferences {
    runtime_profile: RuntimeProfile,
    persistent_mode: bool,
    ui_language: UiLanguage,
}

/// Eine erkannte Telemetrie-Verbindung eines lokalen Prozesses.
#[derive(Debug, Clone)]
struct TelemetryAlert {
    timestamp: String,
    remote:    String,
    process:   String,
}

#[derive(Debug, Clone)]
enum Message {
    LoginUsernameChanged(String),
    LoginPasswordChanged(String),
    LoginPressed,
    RegisterPressed,
    TabSelected(Tab),
    ChatContextSelected(ChatContext),
    SecurityModeSelected(String),
    RuntimeProfileSelected(RuntimeProfile),
    UiLanguageSelected(UiLanguage),
    DashboardSearchChanged(String),
    DashboardInfoToggle(String),
    ChatUserSearchChanged(String),
    PrivatePartnerSelected(String),
    PrivateMessageChanged(String),
    PrivateMessageSend,
    /// Nutzer tippt den Usernamen für eine direkte Einladung (Privat-Chat)
    ChatInviteUsernameChanged(String),
    /// Einladung per Username absenden
    ChatInviteSend,
    ChatBlockSelectedUser,
    ChatUnblockSelectedUser,
    GroupRoomSelected(String),
    ChatGroupNameChanged(String),
    ChatGroupCreate,
    GroupMemberUsernameChanged(String),
    GroupAddMember,
    GroupRemoveMember(String),
    GroupLeaveSelected,
    GroupMessageChanged(String),
    GroupMessageSend,
    /// Broadcast-Anfrage: Nachricht für automatisierte Ankermuster-Anfrage
    ChatBroadcastDraftChanged(String),
    /// Broadcast abschicken (wird als offene Anfrage im Swarm-Anfragen-Tab sichtbar)
    ChatBroadcastSend,
    /// Eingehende Broadcast-Anfrage annehmen
    ChatBroadcastAccept(String),
    /// Eingehende Broadcast-Anfrage ablehnen
    ChatBroadcastDecline(String),
    FileHovered(PathBuf),
    FileHoverCleared,
    ShowTooltip(String),
    FileDropped(PathBuf),
    /// Nutzer tippt im Drop-Annotation-Feld
    DropAnnotationChanged(String),
    /// Nutzer tippt ein visuelles Quelldatum / Bezugsdatum fuer die Zeitachsen ein
    DropSourceDateChanged(String),
    /// Nutzer bestätigt: Analyse starten mit der eingegebenen Beschriftung
    DropAnnotationConfirmed,
    /// Nutzer bricht Drop-Annotation ab
    DropAnnotationCancelled,
    FileAnalysisCompleted(Result<FileAnalysisResult, String>),
    LiveRenderAnalysisCompleted(Result<LiveRenderAnalysisResult, String>),
    AutoAefEncodeCompleted(Result<String, String>),
    ReconstructPressed(u64),
    ReconstructionCompleted(Result<(String, AefDecodeResult), String>),
    ExportPressed(u64),
    WindowResized(f32, f32),
    FlowSphereSnapshotSelected(usize),
    FlowSphereZoomIn,
    FlowSphereZoomOut,
    FlowSphereRotateLeft,
    FlowSphereRotateRight,
    FlowSphereResetView,
    FlowSphereToggleViewMode,
    FlowSphereToggleInternal,
    FlowSphereToggleExternal,
    FlowSphereDomainRename(usize, String),
    FlowSphereBroadcastNameChanged(String),
    FlowSphereBroadcastConsentToggled,
    FlowSphereBroadcastSuggest,
    FlowSphereBroadcastApprove,
    FlowSphereBroadcastDispatch,
    FlowSphereBroadcastReject,
    FlowSphereExplain(String),
    FlowSphereNodeClicked(usize),
    FlowSphereExportPressed,
    FlowSphereSubTabSelected(FlowSphereSubTab),
    FlowSphereCompareSelected(usize),
    OpenFullTab(Tab),
    ToggleMode,
    LiveRenderToggle,
    SymbiontEventsReceived(Result<(Vec<String>, u64), String>),
    SymbiontEventsClearPressed,
    SymbiontInputChanged(String),
    SymbiontRunPressed,
    SymbiontResultReceived(Result<String, String>),
    HybridBridgeStartPressed,
    HybridBridgeStopPressed,
    HybridBridgeRestartPressed,
    HybridSymbiontEnabled(bool),
    HybridSymbiontEndpointPreset(String, u16),
    Tick,
    SecurityRecheck,
    TutorialDismissed,
    AnchorGroupSelected(usize),
    LauncherModeSelected(LauncherMode),
    LauncherServiceStartPressed(String),
    LauncherServiceStopPressed(String),
    LauncherBuildTaskPressed(String),
    LauncherBuildTaskCompleted(String, Result<BuildTaskResult, String>),
    LauncherLogsClearPressed,
    SwarmConsentToggled(bool),
    /// User accepted a swarm domain-overlap contact request (payload = anchor_hash_a).
    SwarmOverlapAccepted(String),
    /// User declined a swarm domain-overlap contact request (payload = anchor_hash_a).
    SwarmOverlapDeclined(String),
    /// Nutzer schaltet den Telemetrie-Firewall-Block ein oder aus.
    TelemetryShieldToggle(bool),
    /// Nutzer aktiviert / deaktiviert Entstehungsdatum-Lesen (nur Zeitgraph-Tab).
    TemporalMetadataConsentToggle(bool),
    /// Hintergrund-Scan hat Telemetrie-Verbindungen zurückgemeldet (oder leere Liste).
    TelemetryScanResult(Vec<TelemetryAlert>),
    /// Fenster-Schliessen-Anfrage (X-Button) abgefangen — kein Auto-Beenden.
    CloseWindowRequested(window::Id),
    /// Erzwungenes Beenden aus den Einstellungen heraus.
    ForceQuit,
    /// Permanent-Modus (Fenster bleibt offen statt zu schliessen) ein/aus.
    PersistentModeToggle(bool),
}

pub struct AetherIcedShell {
    auth_store: AuthStore,
    state_store: StateStore,
    security_monitor: SecurityMonitor,
    current_user: Option<UserRecord>,
    data_key: Option<DataKey>,
    data_key_fingerprint: String,
    security_snapshot: SecuritySnapshot,
    security_audit_events: Vec<SecurityAuditEvent>,
    swarm_startup: SwarmStartupStatus,
    login_username: String,
    login_password: String,
    status_line: String,
    app_mode: AppMode,
    active_tab: Tab,
    chat_context: ChatContext,
    show_tutorial: bool,
    selected_anchor_group: usize,
    chat_user_search: String,
    selected_private_partner: Option<String>,
    private_message_draft: String,
    /// Eingabefeld: Username für direkte Einladung im Privat-Chat
    chat_invite_username: String,
    selected_group_room_id: Option<String>,
    chat_group_name: String,
    group_member_username: String,
    /// Eingabefeld: Broadcast-Anfrage (Gruppen-Tab)
    chat_broadcast_draft: String,
    /// Eingehende Broadcast-Anfragen (strukturell initiiert)
    chat_broadcast_requests: Vec<ChatBroadcastRequest>,
    group_message_draft: String,
    analysis_running: bool,
    analysis_progress: f32,
    analysis_status: String,
    hovered_file_label: String,
    last_analysis: Option<AnalysisSnapshot>,
    capsule_state: Option<CapsuleViewState>,
    structure_map_state: Option<StructureMapViewState>,
    aelab_state: Option<AelabViewState>,
    compression_state: Option<CompressionViewState>,
    reconstruction_state: Option<ReconstructionAuditViewState>,
    window_width: f32,
    window_height: f32,
    tick_counter: u64,
    runtime_profile: RuntimeProfile,
    ui_language: UiLanguage,
    dashboard_search: String,
    dashboard_nav: String,
    dashboard_info_key: Option<String>,
    dashboard_info_open_tick: u64,
    // --- StructureMap / FlowSphere ---
    structure_map_nodes: Vec<Vec<f32>>,
    // ...existing code...
    structure_map_compression: f32,
    structure_map_locked: bool,
    structure_map_anchor_count: usize,
    structure_map_anomaly_count: u32,
    structure_map_anchor_hist: Vec<f32>,
    structure_map_mutation_hist: Vec<u32>,
    flow_sphere_snapshot_idx: usize,
    flow_sphere_zoom: f32,
    flow_sphere_rotation_offset: f32,
    flow_sphere_view_mode: bool, // true=Local (Attraktoren), false=Global (Swarm)
    flow_sphere_focus_key: String,
    flow_sphere_show_internal: bool,  // Schalter: Interne Verbindungen an/aus
    flow_sphere_show_external: bool,  // Schalter: Externe Verbindungen an/aus
    flow_sphere_domain_names: Vec<String>, // Benutzerdefinierte Namen fuer interne Domaenen
    flow_sphere_broadcast_name: String,    // Optionaler Hinweis fuer Broadcast-Vorschlag
    flow_sphere_broadcast_opt_in: bool,    // Broadcast nur nach ausdruecklicher Zustimmung
    flow_sphere_broadcast_proposal: Option<String>,
    flow_sphere_broadcast_visible: Option<String>,
    flow_sphere_broadcast_outbound: Option<String>,
    flow_sphere_broadcast_last_sent_at: Option<String>,
    // FlowSphere – History und Sub-Tab
    flow_sphere_subtab: FlowSphereSubTab,
    flow_sphere_history: Vec<FlowSphereEntry>,  // persistierte Analyseeintraege (aller Sitzungen)
    flow_sphere_session_entries: Vec<FlowSphereEntry>, // nur diese Sitzung
    flow_sphere_compare_idx: Option<usize>,     // Index in history fuer direkten Vergleich
    // --- Rekonstruktion ---
    rekonstruktion_selected: Option<u64>,
    rekonstruktion_running: bool,
    rekonstruktion_result: Option<Result<(String, AefDecodeResult), String>>,
    // --- IPC Bridge: Python backend state ---
    backend_vault_main: u64,
    backend_vault_sub: u64,
    backend_entropy_mean: f32,
    backend_anchor_count: u64,
    backend_cpu_pct: f32,
    backend_mem_used_gb: f32,
    backend_swarm_node_count: u64,
    backend_swarm_reachable_node_count: u64,
    backend_swarm_pack_count: u64,
    backend_swarm_candidate_count: u64,
    backend_swarm_consensus_count: u64,
    backend_swarm_genesis_key_ok: bool,
    backend_swarm_quorum_reachable: bool,
    backend_swarm_estimated_saving_percent: f32,
    backend_swarm_summary: String,
    backend_state_loaded: bool,
    hybrid_bridge: PythonBridgeManager,
    hybrid_symbiont_enabled: bool,
    hybrid_bridge_running: bool,
    hybrid_bridge_error: String,
    hybrid_symbiont_running: bool,
    hybrid_aethernet_running: bool,
    hybrid_aethernet_receiver_port: u16,
    hybrid_yggdrasil_running: bool,
    hybrid_yggdrasil_addr: String,
    symbiont_host: String,
    symbiont_port: u16,
    symbiont_input: String,
    symbiont_result: String,
    symbiont_busy: bool,
    symbiont_events: Vec<String>,
    symbiont_events_polling: bool,
    symbiont_last_event_idx: u64,
    vscode_symbiont_active: bool,
    vscode_symbiont_mode: String,
    // Launcher Dashboard
    launcher_state: LauncherState,
    // XOR bytestream compare (Leistenmodus strip)
    last_byte_hist: Vec<f32>,
    last_xor_delta: Vec<f32>,
    // Persistent live render analytics mode
    live_render_mode: bool,
    live_render_analysis_running: bool,
    live_render_last_frame: Vec<u8>,
    live_render_last_running_services: Vec<String>,
    live_render_last_os_processes: Vec<String>,
    live_render_prev_xor_delta: Vec<f32>,
    live_render_invariant_streak: u64,
    live_render_saved_patterns: u64,
    live_render_last_delta_ratio: f32,
    live_render_last_pixeldynamics: f32,
    live_render_last_godel_level: u8,
    live_render_last_godel_delta: f32,
    live_render_anchor_boost: bool,
    live_render_last_os_sample_tick: u64,
    // Noether K: temporale Erhaltungsgrösse (Symmetriebruch-Detektor nach Noether-Theorem)
    // K = 0.40 * spektrale_aehlichkeit + 0.30 * (1 - entropiedrift) + 0.30 * (1 - deltavarianz)
    live_render_noether_k: f32,
    live_render_noether_delta_k: f32,
    live_render_noether_symmetry_preserved: bool,
    live_render_noether_prev_spectral: [f32; 5],
    live_render_noether_prev_entropy: f32,
    /// Bits per Joule — live efficiency metric.
    /// bits_saved_this_tick / joules_consumed_this_tick
    /// (bits_saved = (1-delta_ratio)*frame_bytes*8, joules = cpu_pct/100*15W*1/fps)
    live_render_bits_per_joule: f32,
    /// Rolling history of bits-per-joule (last 60 values = ~2 min at default tick).
    live_render_bpj_history: Vec<f32>,
    /// Gödelstop counter for the outer live-render analysis loop.
    /// Incremented when the inner Gödel probe converges naturally (delta < 1%).
    /// When >= 5: outer analysis is paused for this tick (prevents endless self-analysis).
    /// Reset to 0 when the signal is no longer stable.
    live_render_godel_stop_skip: u8,
    /// True when the user explicitly toggled Live-Render via the button (survives tab switches).
    /// False (default): context-driven — active automatically only on Gaming / Media tabs.
    live_render_explicit: bool,
    pending_analysis_world: Option<Tab>,
    pending_analysis_path: Option<PathBuf>,
    pending_chat_partner: Option<String>,
    pending_chat_group_room_id: Option<String>,
    /// Drop-Annotation-Modal: Datei wartet auf Nutzer-Beschriftung
    drop_pending_path: Option<PathBuf>,
    drop_pending_world: Option<Tab>,
    drop_annotation_input: String,
    drop_source_date_input: String,
    pending_broadcast_hint: Option<String>,
    pending_visual_source_date_secs: Option<u64>,
    /// Schnell-Entropie aus den ersten 4KB der Datei (0.0–8.0 bits/byte)
    drop_quick_entropy: f32,
    active_gaming_game_id: Option<String>,
    gaming_progress_rows: Vec<GamingProgressRow>,
    gaming_progress_last_live_update_tick: u64,
    swarm_consented: bool, // Swarm-Teilnahme: opt-in/out über UI steuerbar
    /// Pending swarm domain-overlap contact requests, polled from data/interbus/.
    swarm_overlap_requests: Vec<SwarmOverlapRequest>,

    // Cascade result state
    cascade_run_id: Option<String>,
    cascade_metrics: Option<CascadeMetrics>,
    /// Emergent OS capability score 0.0–1.0, filled by capability_score.py.
    backend_capability_score: f32,
    /// Human-readable stage label for the capability score.
    backend_capability_stage: String,
    /// Ob der Telemetrie-Firewall-Block aktiv ist.
    telemetry_shield_enabled: bool,
    /// Zustimmung: Entstehungsdatum aus Datei-Metadaten lesen (nur für Zeitgraph-Tab).
    /// Kein Inhalt wird gelesen — nur mtime / Header-Timestamp-Bytes.
    temporal_metadata_consent: bool,
    /// Erkannte Telemetrie-Verbindungen (max. 30, neueste zuerst).
    telemetry_alerts: Vec<TelemetryAlert>,
    /// Programm läuft dauerhaft: X-Button minimiert zur Leiste statt zu beenden.
    persistent_mode: bool,
    /// Netzwerk-Tier aus hw_capability.json (geschrieben beim Start via hardware::detect).
    hw_network_tier: String,
    /// OS-Platform-Label aus hw_capability.json.
    hw_os_platform: String,
    /// Welche P2P-Features freigeschaltet (lan_beacon, lan_p2p, yggdrasil, dht).
    hw_p2p_unlocked: [bool; 4],
}

impl AetherIcedShell {
    fn bootstrap() -> Self {
        let swarm_startup = probe_swarm_startup();
        let hybrid_settings = load_hybrid_settings();
        let mut hybrid_bridge = PythonBridgeManager::new();
        let hybrid_start_error = if hybrid_settings.enabled {
            hybrid_bridge.start().err().unwrap_or_default()
        } else {
            String::new()
        };
        let auth_store = AuthStore::load_default();
        let known_user_count = auth_store.user_count();
        let known_username = auth_store.sole_username();
        let state_store = StateStore::load_default();
        let detected_hardware_profile = {
            let hw = hardware::detect();
            hardware::write_capability_json(&hw);
            hw
        };
        let detected_runtime_profile = {
            use crate::hardware::RecommendedProfile;
            match detected_hardware_profile.recommended_profile() {
                RecommendedProfile::Legacy => RuntimeProfile::Legacy,
                RecommendedProfile::LowPower => RuntimeProfile::LowPower,
                RecommendedProfile::Auto => RuntimeProfile::Auto,
            }
        };
        let (_, detected_lb, detected_lp, detected_ygg, detected_dht) =
            detected_hardware_profile.network_tier.features();
        let detected_os_platform = match &detected_hardware_profile.os_platform {
            hardware::OsPlatform::Win9x => "Win9x",
            hardware::OsPlatform::Win2000 => "Win2000",
            hardware::OsPlatform::WinXP => "WinXP",
            hardware::OsPlatform::WinVista7 => "WinVista7",
            hardware::OsPlatform::WinModern => "WinModern",
            hardware::OsPlatform::LinuxLegacy => "LinuxLegacy",
            hardware::OsPlatform::LinuxModern => "LinuxModern",
            hardware::OsPlatform::RaspberryPi => "RaspberryPi",
            hardware::OsPlatform::Unknown => "Unknown",
        }
        .to_owned();
        let shell_preferences = read_shell_preferences(detected_runtime_profile);
        let mut shell = Self {
            auth_store,
            state_store,
            security_monitor: SecurityMonitor::new(PathBuf::from(".")),
            current_user: None,
            data_key: None,
            data_key_fingerprint: String::new(),
            security_snapshot: SecuritySnapshot::default(),
            security_audit_events: Vec::new(),
            swarm_startup: swarm_startup.clone(),
            login_username: known_username.clone().unwrap_or_default(),
            login_password: String::new(),
            status_line: if let Some(username) = known_username {
                format!(
                    "Lokales Konto '{}' erkannt. Anmeldung weiterhin erforderlich.",
                    username
                )
            } else if known_user_count > 0 {
                format!(
                    "{} lokaler Nutzer erkannt. Anmeldung weiterhin erforderlich.",
                    known_user_count
                )
            } else if swarm_startup.node_initialized {
                "Bitte lokal anmelden oder registrieren.".to_owned()
            } else {
                swarm_startup.summary.clone()
            },
            app_mode: AppMode::Full,
            active_tab: Tab::Home,
            chat_context: ChatContext::Private,
            show_tutorial: false,
            selected_anchor_group: 0,
            chat_user_search: String::new(),
            selected_private_partner: None,
            private_message_draft: String::new(),
            chat_invite_username: String::new(),
            selected_group_room_id: None,
            chat_group_name: String::new(),
            group_member_username: String::new(),
            chat_broadcast_draft: String::new(),
            chat_broadcast_requests: Vec::new(),
            group_message_draft: String::new(),
            analysis_running: false,
            analysis_progress: 0.0,
            analysis_status: "Bereit fuer lokale Artefakte.".to_owned(),
            hovered_file_label: "Datei in das Fenster ziehen, um die Analyse zu starten."
                .to_owned(),
            last_analysis: None,
            capsule_state: None,
            structure_map_state: None,
            aelab_state: None,
            compression_state: None,
            reconstruction_state: None,
            last_byte_hist: Vec::new(),
            last_xor_delta: Vec::new(),
            window_width: FULL_WINDOW_WIDTH,
            window_height: FULL_WINDOW_HEIGHT,
            tick_counter: 0,
            runtime_profile: shell_preferences.runtime_profile,
            ui_language: shell_preferences.ui_language,
            dashboard_search: String::new(),
            dashboard_nav: "Overview".to_owned(),
            dashboard_info_key: None,
            dashboard_info_open_tick: 0,
            structure_map_nodes: Vec::new(),
            structure_map_compression: 0.0,
            structure_map_locked: false,
            structure_map_anchor_count: 0,
            structure_map_anomaly_count: 0,
            structure_map_anchor_hist: Vec::new(),
            structure_map_mutation_hist: Vec::new(),
            flow_sphere_snapshot_idx: 0,
            flow_sphere_zoom: 1.0,
            flow_sphere_rotation_offset: 0.0,
            flow_sphere_view_mode: true, // Default: Local mode (Attraktoren)
            flow_sphere_focus_key: "internal_core".to_owned(),
            flow_sphere_show_internal: true,
            flow_sphere_show_external: false,
            flow_sphere_domain_names: vec![String::new(); 6],
            flow_sphere_broadcast_name: String::new(),
            flow_sphere_broadcast_opt_in: false,
            flow_sphere_broadcast_proposal: None,
            flow_sphere_broadcast_visible: None,
            flow_sphere_broadcast_outbound: None,
            flow_sphere_broadcast_last_sent_at: None,
            flow_sphere_subtab: FlowSphereSubTab::Session,
            flow_sphere_history: Vec::new(),
            flow_sphere_session_entries: Vec::new(),
            flow_sphere_compare_idx: None,
            rekonstruktion_selected: None,
            rekonstruktion_running: false,
            rekonstruktion_result: None,
            backend_vault_main: 0,
            backend_vault_sub: 0,
            backend_entropy_mean: 0.0,
            backend_anchor_count: 0,
            backend_cpu_pct: 0.0,
            backend_mem_used_gb: 0.0,
            backend_swarm_node_count: 0,
            backend_swarm_reachable_node_count: 0,
            backend_swarm_pack_count: 0,
            backend_swarm_candidate_count: 0,
            backend_swarm_consensus_count: 0,
            backend_swarm_genesis_key_ok: false,
            backend_swarm_quorum_reachable: false,
            backend_swarm_estimated_saving_percent: 0.0,
            backend_swarm_summary: String::new(),
            backend_state_loaded: false,
            hybrid_bridge,
            hybrid_symbiont_enabled: hybrid_settings.symbiont.enabled,
            hybrid_bridge_running: false,
            hybrid_bridge_error: hybrid_start_error,
            hybrid_symbiont_running: false,
            hybrid_aethernet_running: false,
            hybrid_aethernet_receiver_port: 7385,
            hybrid_yggdrasil_running: false,
            hybrid_yggdrasil_addr: String::new(),
            symbiont_host: hybrid_settings.symbiont.host.clone(),
            symbiont_port: hybrid_settings.symbiont.port,
            symbiont_input: String::new(),
            symbiont_result: "Noch keine Symbiont-RPC-Ausfuehrung.".to_owned(),
            symbiont_busy: false,
            symbiont_events: Vec::new(),
            symbiont_events_polling: false,
            symbiont_last_event_idx: 0,
            vscode_symbiont_active: false,
            vscode_symbiont_mode: String::new(),
            launcher_state: LauncherState::new(),
            live_render_mode: false,
            live_render_analysis_running: false,
            live_render_last_frame: Vec::new(),
            live_render_last_running_services: Vec::new(),
            live_render_last_os_processes: Vec::new(),
            live_render_prev_xor_delta: Vec::new(),
            live_render_invariant_streak: 0,
            live_render_saved_patterns: 0,
            live_render_last_delta_ratio: 0.0,
            live_render_last_pixeldynamics: 0.0,
            live_render_last_godel_level: 0,
            live_render_last_godel_delta: 0.0,
            live_render_anchor_boost: false,
            live_render_last_os_sample_tick: 0,
            live_render_noether_k: 1.0,
            live_render_noether_delta_k: 0.0,
            live_render_noether_symmetry_preserved: true,
            live_render_noether_prev_spectral: [0.0f32; 5],
            live_render_noether_prev_entropy: 0.0,
            live_render_bits_per_joule: 0.0,
            live_render_bpj_history: Vec::new(),
            live_render_godel_stop_skip: 0,
            live_render_explicit: false,
            pending_analysis_world: None,
            pending_analysis_path: None,
            pending_chat_partner: None,
            pending_chat_group_room_id: None,
            drop_pending_path: None,
            drop_pending_world: None,
            drop_annotation_input: String::new(),
            drop_source_date_input: String::new(),
            pending_broadcast_hint: None,
            pending_visual_source_date_secs: None,
            drop_quick_entropy: 0.0,
            active_gaming_game_id: None,
            gaming_progress_rows: load_gaming_progress_rows(),
            gaming_progress_last_live_update_tick: 0,
            cascade_run_id: None,
            cascade_metrics: None,
            backend_capability_score: 0.0,
            backend_capability_stage: String::new(),
            swarm_consented: read_swarm_consent(),
            swarm_overlap_requests: Vec::new(),
            telemetry_shield_enabled: false,
            telemetry_alerts: Vec::new(),
            temporal_metadata_consent: {
                let p = std::path::Path::new("data/settings.json");
                std::fs::read_to_string(p)
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v.get("temporal_metadata_consent").and_then(|b| b.as_bool()))
                    .unwrap_or(false)
            },
            persistent_mode: shell_preferences.persistent_mode,
            hw_network_tier: detected_hardware_profile.network_tier.label().to_owned(),
            hw_os_platform: detected_os_platform,
            hw_p2p_unlocked: [detected_lb, detected_lp, detected_ygg, detected_dht],
        };
        if shell.swarm_startup.node_initialized {
            shell.analysis_status = shell.swarm_startup.summary.clone();
        }
        shell.poll_hybrid_state();
        shell.refresh_security_snapshot(false, "startup");
        shell
    }
            }


// --- Moved methods into impl block ---

fn read_swarm_consent() -> bool {
    let path = crate::data_path("swarm_consent.json");
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(v) = val.get("consented").and_then(|v| v.as_bool()) {
                return v;
            }
            if let Some(v) = val.get("consent_ok").and_then(|v| v.as_bool()) {
                return v;
            }
            if let Some(v) = val.get("approved").and_then(|v| v.as_bool()) {
                return v;
            }
            return true;
        }
    }
    true // opt-out: kein File = Swarm standardmäßig aktiv
}

fn write_swarm_consent(enabled: bool) -> Result<(), String> {
    let path = crate::data_path("swarm_consent.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut state: serde_json::Value = if path.exists() {
        fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    state["consented"] = serde_json::Value::Bool(enabled);
    state["consent_ok"] = serde_json::Value::Bool(enabled);
    state["approved"] = serde_json::Value::Bool(enabled);
    if !enabled {
        state["revoked"] = serde_json::Value::Bool(true);
    } else {
        state["revoked"] = serde_json::Value::Bool(false);
    }
    let ts = chrono::Utc::now().to_rfc3339();
    state["updated_at"] = serde_json::Value::String(ts);
    state["actor"] = serde_json::Value::String("iced_shell".to_owned());
    fs::write(&path, serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

fn read_shell_preferences(detected_runtime_profile: RuntimeProfile) -> ShellPreferences {
    let path = crate::data_path("settings.json");
    let mut prefs = ShellPreferences {
        runtime_profile: detected_runtime_profile,
        persistent_mode: true,
        ui_language: UiLanguage::German,
    };

    let Ok(raw) = fs::read_to_string(&path) else {
        return prefs;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return prefs;
    };

    if let Some(profile_raw) = value
        .get("runtime_profile_override")
        .and_then(|entry| entry.as_str())
    {
        if let Some(profile) = parse_runtime_profile(profile_raw) {
            prefs.runtime_profile = profile;
        }
    }
    if let Some(persistent_mode) = value
        .get("close_only_via_settings")
        .and_then(|entry| entry.as_bool())
    {
        prefs.persistent_mode = persistent_mode;
    }
    if let Some(language_raw) = value.get("shell_ui_language").and_then(|entry| entry.as_str()) {
        if let Some(language) = parse_ui_language(language_raw) {
            prefs.ui_language = language;
        }
    }

    prefs
}

fn write_shell_preferences(
    runtime_profile: RuntimeProfile,
    persistent_mode: bool,
    ui_language: UiLanguage,
) -> Result<(), String> {
    let path = crate::data_path("settings.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }

    let mut value = if path.exists() {
        fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()))
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    if !value.is_object() {
        value = serde_json::Value::Object(serde_json::Map::new());
    }

    value["runtime_profile_override"] =
        serde_json::Value::String(runtime_profile_setting_label(runtime_profile).to_owned());
    value["close_only_via_settings"] = serde_json::Value::Bool(persistent_mode);
    value["shell_ui_language"] =
        serde_json::Value::String(ui_language_setting_label(ui_language).to_owned());

    let serialized = serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?;
    fs::write(&path, serialized).map_err(|err| err.to_string())
}

fn parse_runtime_profile(value: &str) -> Option<RuntimeProfile> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Some(RuntimeProfile::Auto),
        "balanced" => Some(RuntimeProfile::Balanced),
        "low-power" | "low_power" | "lowpower" => Some(RuntimeProfile::LowPower),
        "legacy" => Some(RuntimeProfile::Legacy),
        _ => None,
    }
}

fn runtime_profile_setting_label(profile: RuntimeProfile) -> &'static str {
    match profile {
        RuntimeProfile::Auto => "auto",
        RuntimeProfile::Balanced => "balanced",
        RuntimeProfile::LowPower => "low-power",
        RuntimeProfile::Legacy => "legacy",
    }
}

fn parse_ui_language(value: &str) -> Option<UiLanguage> {
    match value.trim().to_ascii_lowercase().as_str() {
        "de" | "german" | "deutsch" => Some(UiLanguage::German),
        "en" | "english" => Some(UiLanguage::English),
        _ => None,
    }
}

fn ui_language_setting_label(language: UiLanguage) -> &'static str {
    match language {
        UiLanguage::German => "de",
        UiLanguage::English => "en",
    }
}

fn load_gaming_progress_rows() -> Vec<GamingProgressRow> {
    let path = Path::new(GAMING_PROGRESS_PATH);
    if let Ok(raw) = fs::read_to_string(path) {
        if let Ok(rows) = serde_json::from_str::<Vec<GamingProgressRow>>(&raw) {
            return rows;
        }
    }
    Vec::new()
}

fn save_gaming_progress_rows(rows: &[GamingProgressRow]) -> Result<(), String> {
    let path = Path::new(GAMING_PROGRESS_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let payload = serde_json::to_string_pretty(rows).map_err(|err| err.to_string())?;
    fs::write(path, payload).map_err(|err| err.to_string())
}

fn game_label_from_hint(game_hint: &str) -> String {
    let p = Path::new(game_hint);
    p.file_stem()
        .or_else(|| p.file_name())
        .and_then(OsStr::to_str)
        .unwrap_or(game_hint)
        .trim()
        .to_owned()
}

fn normalized_game_id_from_hint(game_hint: &str) -> String {
    game_label_from_hint(game_hint)
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn compact_insight_text(note: &str) -> String {
    let mut text = note.trim().replace('\n', " ");
    if text.len() > 140 {
        text.truncate(140);
    }
    text
}

impl AetherIcedShell {
    fn apply_projection_state(
        &mut self,
        capsule_state: CapsuleViewState,
        structure_map_state: StructureMapViewState,
        structure_map_nodes: Vec<Vec<f32>>,
        aelab_state: Option<AelabViewState>,
        compression_state: Option<CompressionViewState>,
        reconstruction_state: Option<ReconstructionAuditViewState>,
    ) {
        self.cascade_run_id = Some(if capsule_state.source_hash.is_empty() {
            capsule_state.source_label.clone()
        } else {
            capsule_state.source_hash.clone()
        });
        self.cascade_metrics = Some(CascadeMetrics::from_capsule_state(&capsule_state, &structure_map_state));
        self.capsule_state = Some(capsule_state);
        self.structure_map_state = Some(structure_map_state.clone());
        if aelab_state.is_some() {
            self.aelab_state = aelab_state;
        }
        if compression_state.is_some() {
            self.compression_state = compression_state;
        }
        if reconstruction_state.is_some() {
            self.reconstruction_state = reconstruction_state;
        }
        self.structure_map_nodes = structure_map_nodes;
        self.structure_map_compression = (structure_map_state.coherence_score * 100.0).clamp(0.0, 100.0);
        self.structure_map_locked = structure_map_state.locked;
        self.structure_map_anchor_count = structure_map_state.anchor_count;
        self.structure_map_anomaly_count = structure_map_state.anomaly_count;
        self.structure_map_anchor_hist.push(structure_map_state.anchor_count as f32);
        if self.structure_map_anchor_hist.len() > 30 {
            self.structure_map_anchor_hist.remove(0);
        }
        self.structure_map_mutation_hist.push(structure_map_state.anomaly_count);
        if self.structure_map_mutation_hist.len() > 20 {
            self.structure_map_mutation_hist.remove(0);
        }
    }

    fn ui_text<'a>(&self, de: &'a str, en: &'a str) -> &'a str {
        match self.ui_language {
            UiLanguage::German => de,
            UiLanguage::English => en,
        }
    }

    fn tab_subtitle(&self) -> &'static str {
        match self.ui_language {
            UiLanguage::German => match self.active_tab {
                Tab::Home         => "Startseite: aktueller Systemzustand, Warnungen, Bereitschaftsanzeige und Schnellzugriff.",
                Tab::Control      => "Steuerzentrale: Checks starten, System stabilisieren, Fehler beheben \u{2014} alles auf einen Blick.",
                Tab::Symbiont     => "Hilfsknoten verwalten: verbundene Python-Agenten und Co-Pilot-Laufzeiten anzeigen und steuern.",
                Tab::SwarmOps     => "Schwarm: Knoten starten, verbinden und koordinieren. Zeigt wer aktiv ist und welche Invarianten geteilt werden.",
                Tab::Privacy      => "Datenschutz: festlegen wer welche Daten sieht, wie lange sie gespeichert bleiben und was geschw\u{e4}rzt wird.",
                Tab::Chat         => "Chat: Fragen stellen, Abl\u{e4}ufe steuern und Nachrichten mit anderen lokalen Nutzern austauschen.",
                Tab::Data         => "Daten: Dateien ablegen, analysieren und als Artefakte sichern \u{2014} hier landen alle Analyse-Ergebnisse.",
                Tab::Settings     => "Einstellungen: Laufzeit-Profil w\u{e4}hlen (Legacy f\u{fc}r \u{e4}ltere Hardware), Takt und Bridge-Verbindungen konfigurieren.",
                Tab::Logs         => "Protokoll: alle Ereignisse, Fehler und Sicherheitsmeldungen chronologisch \u{2014} der Blick hinter die Kulissen.",
                Tab::Anchors      => "Anker: unver\u{e4}nderliche Strukturpunkte anzeigen, die beweisen dass Daten nicht manipuliert wurden.",
                Tab::ADE          => "Bedrohungsanalyse: Dateien auf Malware, Obfuskation und Anomalien pr\u{fc}fen \u{2014} mit erkl\u{e4}rbaren Ergebnissen.",
                Tab::FlowSphere   => "FlowSphere: 3D-Musterbild \u{2014} zeigt Zusammenh\u{e4}nge, Ausrei\u{df}er und Stabilit\u{e4}t des Gesamtbilds.",
                Tab::StructureMap => "Strukturkarte: Delta-Konvergenz und Kompressionspfad \u{2014} wie stark haben sich Daten ver\u{e4}ndert, wie gut lassen sie sich rekonstruieren.",
                Tab::Gaming       => "Gaming-Welt: misst wie viel Aether \u{fc}ber interaktive Muster gelernt hat und wann ein stabiler Rollout sinnvoll ist.",
                Tab::Media        => "Medien-Welt: Sequenzen, Videos und Audio werden offline verdichtet \u{2014} je mehr Material, desto besser die Modelle.",
                Tab::Research     => "Forschungs-Welt: Messdaten und Archive r\u{fc}ckwirkend verkn\u{fc}pfen und reproduzierbar machen.",
                Tab::Rekonstruktion => "Rekonstruktion: Artefakte aus dem Vault wiederherstellen und den Rekonstruktionspfad nachvollziehen.",
                Tab::Launcher     => "Launcher: Dienste starten und stoppen, Build-Aufgaben ausf\u{fc}hren und Live-Logs beobachten.",
                Tab::Imprint      => "Impressum: Version, Datenschutzprinzipien und rechtliche Hinweise zu Aether.",
            },
            UiLanguage::English => match self.active_tab {
                Tab::Home         => "Dashboard: current system state, alerts, readiness score and quick access.",
                Tab::Control      => "Control Center: run checks, stabilize the system, resolve issues \u{2014} everything at a glance.",
                Tab::Symbiont     => "Manage companion nodes: connected Python agents and co-pilot runtimes.",
                Tab::SwarmOps     => "Swarm: start, connect and coordinate nodes. Shows who is active and which invariants are shared.",
                Tab::Privacy      => "Privacy: define who sees what data, how long it is retained, and what gets redacted.",
                Tab::Chat         => "Chat: ask questions, control workflows, and exchange messages with other local users.",
                Tab::Data         => "Data: store files, run analysis, and save results as artifacts.",
                Tab::Settings     => "Settings: choose runtime profile, configure tick cadence and bridge connections.",
                Tab::Logs         => "Logs: all events, errors and security messages in chronological order.",
                Tab::Anchors      => "Anchors: view immutable structural checkpoints that prove data has not been tampered with.",
                Tab::ADE          => "Threat Analysis: scan files for malware, obfuscation and anomalies \u{2014} with explainable results.",
                Tab::FlowSphere   => "FlowSphere: 3D pattern view \u{2014} shows relationships, outliers and overall stability.",
                Tab::StructureMap => "Structure Map: delta convergence and compression path \u{2014} how much data changed and how well it can be reconstructed.",
                Tab::Gaming       => "Gaming World: measures how much Aether learned from interactive patterns and when a stable rollout makes sense.",
                Tab::Media        => "Media World: sequences, videos and audio are compressed offline \u{2014} more material means better models.",
                Tab::Research     => "Research World: link measurement series and archives retroactively and make them reproducible.",
                Tab::Rekonstruktion => "Reconstruction: restore artifacts from the vault and trace the reconstruction path.",
                Tab::Launcher     => "Launcher: start and stop services, run build tasks, and monitor live logs.",
                Tab::Imprint      => "About: version, privacy principles and legal information about Aether.",
            },
        }
    }

    fn flow_sphere_focus_details(&self, key: &str) -> (String, String, String, Color) {
        let entropy = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.entropy as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.entropy))
            .unwrap_or(self.structure_map_compression / 100.0);
        let stability = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.perm_entropy as f32)
            .unwrap_or_else(|| {
                if self.structure_map_locked {
                    1.0
                } else {
                    self.structure_map_compression / 100.0
                }
            });
        let noether = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.noether_consistency as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.noether_consistency))
            .unwrap_or(stability);
        let trust = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.trust_score as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.trust_score))
            .unwrap_or(stability);
        let katz = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.katz_dimension as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.katz_dimension))
            .unwrap_or(0.0);
        let bayes = self
            .capsule_state
            .as_ref()
            .map(|capsule| capsule.bayes_confidence)
            .unwrap_or(0.0);
        let anomaly_flags = self
            .capsule_state
            .as_ref()
            .map(|capsule| capsule.anomaly_flags.clone())
            .unwrap_or_default();
        let external_link_strength = if self.backend_swarm_node_count == 0 {
            0.0
        } else {
            ((self.backend_swarm_reachable_node_count as f32 / self.backend_swarm_node_count as f32)
                * 0.7
                + (self.backend_swarm_candidate_count as f32
                    / self.backend_swarm_node_count.max(1) as f32)
                    .min(1.0)
                    * 0.3)
                .clamp(0.0, 1.0)
        };

        match key {
            "internal_core" => (
                "Kernmuster".to_owned(),
                format!("Innenruhe {:.0}% bei Shannon {:.2} bit", stability * 100.0, entropy * 7.83),
                format!(
                    "Der violette Kern steht fuer den Bereich, in dem sich das Muster trotz Bewegung noch sammelt. Hohe Stabilitaet und starke Noether-Werte bedeuten, dass dieselben Grundformen wiederkehren statt auseinanderzufallen. Aktuell: Noether {:.0}%, Katz FD {:.2}.",
                    noether * 100.0,
                    katz
                ),
                Color::from_rgb8(0x9A, 0x67, 0xFF),
            ),
            "overlay" => (
                "Ueberlagerungen".to_owned(),
                format!(
                    "Delta-Pulse zeigen Versatz und Takt bei {:.0}% Delta",
                    self.cascade_metrics
                        .as_ref()
                        .map(|metrics| metrics.delta_convergence as f32)
                        .unwrap_or(0.0)
                        * 100.0
                ),
                "Die goldenen Pulse markieren Stellen, an denen mehrere Bewegungen gleichzeitig sichtbar werden. Wenn Linien, Wellen und Pulse dicht zusammenlaufen, ueberlagern sich verschiedene Muster oder Veraenderungsphasen. Dort lohnt sich ein zweiter Blick auf Ursache, Reihenfolge und Drift.".to_owned(),
                Color::from_rgb8(0xFF, 0xC8, 0x3A),
            ),
            "anomaly" => (
                "Auffaelligkeiten".to_owned(),
                if anomaly_flags.is_empty() {
                    format!("Kein harter Bruch sichtbar, Trust {:.0}%", trust * 100.0)
                } else {
                    format!("{} Marker aktiv: {}", anomaly_flags.len(), anomaly_flags.join(", "))
                },
                "Rote Marker zeigen Punkte, an denen das aktuelle Bild nicht mehr sauber zu den uebrigen Signalen passt. Das kann ein echter Ausreisser, ein Bruch in der Reihenfolge oder eine untypische Verteilung sein. Benford, Bayes und Trust helfen dabei zu trennen, ob nur Rauschen oder ein relevanter Wechsel vorliegt.".to_owned(),
                Color::from_rgb8(0xE0, 0x5A, 0x5A),
            ),
            "external_links" => (
                "Aussenbezug".to_owned(),
                if self.backend_swarm_node_count == 0 {
                    "Noch keine externen Knoten sichtbar".to_owned()
                } else {
                    format!(
                        "{} Knoten, {:.0}% Kopplung nach aussen",
                        self.backend_swarm_node_count,
                        external_link_strength * 100.0
                    )
                },
                "Die cyanfarbenen Knoten und Leitungen zeigen, wie stark der aktuelle Bereich nach aussen verbunden ist. Dichte, ruhige Linien sprechen fuer gemeinsame Bewegung ueber Domaenengrenzen hinweg. Lockere oder rot kipppende Verbindungen deuten eher auf Drift, geringe Uebereinstimmung oder instabile Kopplung hin.".to_owned(),
                Color::from_rgb8(0x59, 0xD5, 0xE9),
            ),
            _ if key.starts_with("attractor_") => {
                let idx = key
                    .trim_start_matches("attractor_")
                    .parse::<usize>()
                    .unwrap_or(0);
                (
                    format!("Attraktor {}", idx + 1),
                    format!("Musterkern {} von {}", idx + 1, self.structure_map_anchor_count.max(1)),
                    "Dieser gruene Knoten ist ein stabiler Sammelpunkt im Innenbild. Er steht fuer einen wiederkehrenden Zustand oder eine Form, zu der der Verlauf immer wieder zurueckfindet. Je ruhiger die Umgebung und je hoeher Noether/Bayes stehen, desto belastbarer ist dieser Knoten als Erklaerungskern.".to_owned(),
                    Color::from_rgb8(0x4C, 0xD9, 0x6E),
                )
            }
            _ if key.starts_with("swarm_") => {
                let idx = key
                    .trim_start_matches("swarm_")
                    .parse::<usize>()
                    .unwrap_or(0);
                let label = self
                    .backend_swarm_summary
                    .split_whitespace()
                    .next()
                    .unwrap_or("Swarm");
                (
                    format!("Swarm-Knoten {}", idx + 1),
                    format!("Externer Bezug im Netzkontext {}", label),
                    format!(
                        "Dieser Knoten repraesentiert einen externen Vergleichspunkt. Die Linie dorthin zeigt, ob die lokale Bewegung auch ausserhalb des aktuellen Bereichs wieder auftaucht. Hohe Kopplung und ein ruhiger Bayes-Wert sprechen eher fuer geteilte Struktur als fuer Zufall oder isolierte Spitzen. Bayes aktuell {:.0}%.",
                        bayes * 100.0
                    ),
                    Color::from_rgb8(0x7F, 0xD9, 0xFF),
                )
            }
            _ => (
                "FlowSphere Fokus".to_owned(),
                "Musterbereich ausgewaehlt".to_owned(),
                "Waehle einen farbigen Fokus oder klicke direkt auf Knoten in der Sphere, um zu sehen, wie der Bereich zu lesen ist.".to_owned(),
                Color::from_rgb8(0x9A, 0x67, 0xFF),
            ),
        }
    }

    fn flow_sphere_broadcast_suggestion(&self) -> Option<String> {
        let external_link_strength = if self.backend_swarm_node_count == 0 {
            0.0
        } else {
            ((self.backend_swarm_reachable_node_count as f32 / self.backend_swarm_node_count as f32)
                * 0.7
                + (self.backend_swarm_candidate_count as f32
                    / self.backend_swarm_node_count.max(1) as f32)
                    .min(1.0)
                    * 0.3)
                .clamp(0.0, 1.0)
        };
        let noether = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.noether_consistency as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.noether_consistency))
            .unwrap_or(self.structure_map_compression / 100.0);
        let trust = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.trust_score as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.trust_score))
            .unwrap_or(self.structure_map_compression / 100.0);
        let anomaly_pressure = self
            .capsule_state
            .as_ref()
            .map(|capsule| capsule.anomaly_flags.len() as f32 / 4.0)
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        let reachable = self.backend_swarm_reachable_node_count;
        if self.backend_swarm_node_count == 0
            || external_link_strength < 0.42
            || noether < 0.58
            || trust < 0.52
            || reachable < 2
            || anomaly_pressure > 0.65
        {
            return None;
        }

        let recent_broadcast_hint = self
            .flow_sphere_session_entries
            .iter()
            .rev()
            .chain(self.flow_sphere_history.iter().rev())
            .find_map(|entry| {
                let trimmed = entry.broadcast_hint.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_owned())
                }
            });
        let domain_hint = self
            .flow_sphere_domain_names
            .iter()
            .find_map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_owned())
                }
            })
            .unwrap_or_else(|| "unbenannte Struktur".to_owned());
        let user_hint = self.flow_sphere_broadcast_name.trim();
        let relation = if noether > 0.72 {
            "stabile Aussenkopplung"
        } else if self.backend_swarm_candidate_count > self.backend_swarm_reachable_node_count {
            "pruefenswerte Strukturnaehe"
        } else {
            "lose aber wiederkehrende Kopplung"
        };

        let prefix = if !user_hint.is_empty() {
            user_hint.to_owned()
        } else if let Some(hint) = recent_broadcast_hint {
            hint
        } else {
            domain_hint
        };

        Some(format!(
            "{} | {} | {:.0}% Kopplung | {} erreichbare Peers",
            prefix,
            relation,
            external_link_strength * 100.0,
            self.backend_swarm_reachable_node_count
        ))
    }

    fn flow_sphere_broadcast_gate_details(&self) -> (bool, String, String) {
        let external_link_strength = if self.backend_swarm_node_count == 0 {
            0.0
        } else {
            ((self.backend_swarm_reachable_node_count as f32 / self.backend_swarm_node_count as f32)
                * 0.7
                + (self.backend_swarm_candidate_count as f32
                    / self.backend_swarm_node_count.max(1) as f32)
                    .min(1.0)
                    * 0.3)
                .clamp(0.0, 1.0)
        };
        let noether = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.noether_consistency as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.noether_consistency))
            .unwrap_or(self.structure_map_compression / 100.0);
        let trust = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.trust_score as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.trust_score))
            .unwrap_or(self.structure_map_compression / 100.0);
        let anomaly_pressure = self
            .capsule_state
            .as_ref()
            .map(|capsule| capsule.anomaly_flags.len() as f32 / 4.0)
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);

        let gate_ok = self.backend_swarm_node_count > 0
            && external_link_strength >= 0.42
            && noether >= 0.58
            && trust >= 0.52
            && self.backend_swarm_reachable_node_count >= 2
            && anomaly_pressure <= 0.65;

        let summary = format!(
            "Gate: Kopplung {:.0}% | Noether {:.0}% | Trust {:.0}% | Peers {} | Stoerdruck {:.0}%",
            external_link_strength * 100.0,
            noether * 100.0,
            trust * 100.0,
            self.backend_swarm_reachable_node_count,
            anomaly_pressure * 100.0
        );

        let detail = if gate_ok {
            "Broadcast darf vorgeschlagen werden, weil Aussenkopplung, Invarianz und Vertrauenslage gleichzeitig ueber den Mindestschwellen liegen und der Stoerdruck niedrig genug bleibt.".to_owned()
        } else {
            "Broadcast bleibt gesperrt, solange mindestens eine Schwelle unterschritten ist: Kopplung < 42%, Noether < 58%, Trust < 52%, weniger als 2 erreichbare Peers oder Stoerdruck > 65%.".to_owned()
        };

        (gate_ok, summary, detail)
    }

    fn set_flow_sphere_focus(&mut self, key: impl Into<String>) {
        let key = key.into();
        let (title, summary, _, _) = self.flow_sphere_focus_details(&key);
        self.flow_sphere_focus_key = key;
        self.status_line = format!("FlowSphere: {} - {}", title, summary);
    }

    fn poll_backend_state(&mut self) {
        let path = crate::data_path("interbus/backend_state.json");
        if !path.exists() {
            return;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return;
        };
        self.backend_vault_main = val["vault_main"].as_u64().unwrap_or(self.backend_vault_main);
        self.backend_vault_sub = val["vault_sub"].as_u64().unwrap_or(self.backend_vault_sub);
        self.backend_entropy_mean =
            val["entropy_mean"].as_f64().unwrap_or(self.backend_entropy_mean as f64) as f32;
        self.backend_anchor_count = val["anchor_count"].as_u64().unwrap_or(self.backend_anchor_count);
        self.backend_cpu_pct = val["cpu_pct"].as_f64().unwrap_or(self.backend_cpu_pct as f64) as f32;
        self.backend_mem_used_gb =
            val["mem_used_gb"].as_f64().unwrap_or(self.backend_mem_used_gb as f64) as f32;
        self.backend_swarm_node_count = val["swarm_node_count"]
            .as_u64()
            .unwrap_or(self.backend_swarm_node_count);
        self.backend_swarm_reachable_node_count = val["swarm_reachable_node_count"]
            .as_u64()
            .unwrap_or(self.backend_swarm_reachable_node_count);
        self.backend_swarm_pack_count = val["swarm_pack_count"]
            .as_u64()
            .unwrap_or(self.backend_swarm_pack_count);
        self.backend_swarm_candidate_count = val["swarm_candidate_count"]
            .as_u64()
            .unwrap_or(self.backend_swarm_candidate_count);
        self.backend_swarm_consensus_count = val["swarm_consensus_count"]
            .as_u64()
            .unwrap_or(self.backend_swarm_consensus_count);
        self.backend_swarm_genesis_key_ok = val["swarm_genesis_key_ok"]
            .as_bool()
            .unwrap_or(self.backend_swarm_genesis_key_ok);
        self.backend_swarm_quorum_reachable = val["swarm_quorum_reachable"]
            .as_bool()
            .unwrap_or(self.backend_swarm_quorum_reachable);
        self.backend_swarm_estimated_saving_percent = val["swarm_estimated_saving_percent"]
            .as_f64()
            .unwrap_or(self.backend_swarm_estimated_saving_percent as f64) as f32;
        self.backend_swarm_summary = val["swarm_summary"]
            .as_str()
            .unwrap_or(&self.backend_swarm_summary.clone())
            .to_owned();
        self.backend_state_loaded = true;

        let cap_path = crate::data_path("interbus/capability_score.json");
        if let Ok(raw) = std::fs::read_to_string(&cap_path) {
            if let Ok(cval) = serde_json::from_str::<serde_json::Value>(&raw) {
                self.backend_capability_score = cval["percent"]
                    .as_f64()
                    .unwrap_or(self.backend_capability_score as f64) as f32;
                self.backend_capability_stage = cval["stage"]
                    .as_str()
                    .unwrap_or(&self.backend_capability_stage.clone())
                    .to_owned();
            }
        }

        let hw_path = crate::data_path("interbus/hw_capability.json");
        if let Ok(raw) = std::fs::read_to_string(&hw_path) {
            if let Ok(hval) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(s) = hval["network_tier"].as_str() {
                    self.hw_network_tier = s.to_owned();
                }
                if let Some(s) = hval["os_platform"].as_str() {
                    self.hw_os_platform = s.to_owned();
                }
                self.hw_p2p_unlocked = [
                    hval["lan_beacon"].as_bool().unwrap_or(false),
                    hval["lan_p2p"].as_bool().unwrap_or(false),
                    hval["yggdrasil"].as_bool().unwrap_or(false),
                    hval["dht"].as_bool().unwrap_or(false),
                ];
            }
        }
    }

    /// Reads `data/interbus/swarm_overlap_events.json` and appends new entries to
    /// `self.swarm_overlap_requests`. Duplicate entries (same `anchor_hash_a`) are skipped.
    fn poll_swarm_overlap_events(&mut self) {
        let path = crate::data_path("interbus/swarm_overlap_events.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return;
        };
        let Some(list) = val.as_array() else {
            return;
        };
        for item in list {
            let anchor_hash_a = item
                .get("anchor_hash_a")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if anchor_hash_a.is_empty() {
                continue;
            }
            // Skip duplicates already in the pending list.
            if self
                .swarm_overlap_requests
                .iter()
                .any(|r| r.anchor_hash_a == anchor_hash_a)
            {
                continue;
            }
            self.swarm_overlap_requests.push(SwarmOverlapRequest {
                anchor_hash_a,
                domain_tag: item
                    .get("domain_tag")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unbekannt")
                    .to_string(),
                structural_score: item
                    .get("structural_score")
                    .and_then(|v| v.as_f64())
                    .map(|f| f as f32)
                    .unwrap_or(0.0),
                epoch_week: item
                    .get("epoch_week")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                remote_node_pubkey: item
                    .get("remote_node_pubkey")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }

    fn poll_hybrid_state(&mut self) {
        self.hybrid_bridge_running = self.hybrid_bridge.is_running();
        let shared = load_hybrid_settings();
        self.symbiont_host = shared.symbiont.host;
        self.symbiont_port = shared.symbiont.port;
        if let Some(status) = read_hybrid_status() {
            self.hybrid_bridge_running = status.bridge_running;
            self.hybrid_symbiont_running = status.symbiont_running;
            self.hybrid_aethernet_running = status.aethernet_running;
            if status.aethernet_receiver_port > 0 {
                self.hybrid_aethernet_receiver_port = status.aethernet_receiver_port;
            }
            if !status.symbiont_host.trim().is_empty() {
                self.symbiont_host = status.symbiont_host;
            }
            if status.symbiont_port > 0 {
                self.symbiont_port = status.symbiont_port;
            }
            if !status.last_error.trim().is_empty() {
                self.hybrid_bridge_error = status.last_error;
            }
            self.hybrid_yggdrasil_running = status.yggdrasil_running;
            if !status.yggdrasil_addr.trim().is_empty() {
                self.hybrid_yggdrasil_addr = status.yggdrasil_addr;
            }
        }
        let vscode_path = std::path::Path::new("data/interbus/vscode_symbiont_status.json");
        if let Ok(raw) = std::fs::read_to_string(vscode_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                self.vscode_symbiont_active = val["active"].as_bool().unwrap_or(false);
                self.vscode_symbiont_mode = val["reqMode"].as_str().unwrap_or("").to_owned();
            }
        }
    }

    fn refresh_security_snapshot(&mut self, persist_audit: bool, reason: &str) {
        let register_count = self
            .current_username()
            .map(|username| self.state_store.entries_for(&username).len())
            .unwrap_or(0);
        let snapshot = self.security_monitor.evaluate(
            self.current_user.as_ref(),
            register_count,
            register_count > 0,
            false,
            false,
        );
        if persist_audit {
            let _ = self.security_monitor.append_audit(&snapshot, reason);
        }
        self.security_snapshot = snapshot;
        self.security_audit_events = self.security_monitor.load_recent_audit(24);
    }

    fn current_username(&self) -> Option<String> {
        self.current_user.as_ref().map(|user| user.username.clone())
    }

    fn upsert_gaming_progress(
        &mut self,
        game_hint: &str,
        username: &str,
        found_percent: f32,
        improved_percent: f32,
        insight: &str,
    ) {
        let player = username.trim().to_ascii_lowercase();
        if player.is_empty() {
            return;
        }
        let game_id = normalized_game_id_from_hint(game_hint);
        if game_id.trim().is_empty() {
            return;
        }
        let game_label = game_label_from_hint(game_hint);
        let found = found_percent.clamp(0.0, 100.0);
        let improved = improved_percent.clamp(0.0, 100.0);
        let compact_insight = compact_insight_text(insight);
        let now = chrono::Utc::now().to_rfc3339();

        if let Some(row) = self
            .gaming_progress_rows
            .iter_mut()
            .find(|row| row.game_id == game_id)
        {
            let prev_sessions = row.session_count as f32;
            row.session_count = row.session_count.saturating_add(1);
            if !row
                .players
                .iter()
                .any(|known| known.eq_ignore_ascii_case(&player))
            {
                row.players.push(player.clone());
                row.players.sort();
            }
            let sessions = row.session_count as f32;
            row.found_percent = ((row.found_percent * prev_sessions + found) / sessions)
                .clamp(0.0, 100.0);
            row.improved_percent = ((row.improved_percent * prev_sessions + improved) / sessions)
                .clamp(0.0, 100.0);
            row.quorum_ready = row.players.len() >= 3;
            row.last_shared_insight = if row.quorum_ready {
                compact_insight.clone()
            } else {
                format!("Quorum ausstehend ({}/3 Spieler)", row.players.len())
            };
            row.last_updated = now;
        } else {
            let quorum_ready = false;
            self.gaming_progress_rows.push(GamingProgressRow {
                game_id,
                game_label,
                players: vec![player],
                session_count: 1,
                found_percent: found,
                improved_percent: improved,
                quorum_ready,
                last_shared_insight: if quorum_ready {
                    compact_insight
                } else {
                    "Quorum ausstehend (1/3 Spieler)".to_owned()
                },
                last_updated: now,
            });
        }

        self.gaming_progress_rows.sort_by(|left, right| {
            right
                .improved_percent
                .total_cmp(&left.improved_percent)
                .then(right.session_count.cmp(&left.session_count))
        });

        if let Err(err) = save_gaming_progress_rows(&self.gaming_progress_rows) {
            self.status_line = format!("Gaming-Fortschritt konnte nicht gespeichert werden: {err}");
        }
    }

    fn update_gaming_progress_from_file(&mut self, game_hint: &str, result: &FileAnalysisResult) {
        let found_percent = (result.capsule_state.trust_score * 100.0).clamp(0.0, 100.0);
        let improved_percent = result
            .snapshot
            .compression_gain_percent
            .max((1.0 - result.capsule_state.delta_ratio).clamp(0.0, 1.0) * 100.0);
        self.upsert_gaming_progress(
            game_hint,
            &result.entry.owner_username,
            found_percent,
            improved_percent,
            &result.snapshot.preview_note,
        );
    }

    fn update_gaming_progress_from_live(
        &mut self,
        game_hint: &str,
        username: &str,
        result: &LiveRenderAnalysisResult,
    ) {
        let found_percent = (result.capsule_state.trust_score * 100.0).clamp(0.0, 100.0);
        let improved_percent = result
            .compression_state
            .as_ref()
            .map(|state| state.gain_percent)
            .unwrap_or((1.0 - result.capsule_state.delta_ratio).clamp(0.0, 1.0) * 100.0)
            .clamp(0.0, 100.0);
        let insight = if result.capsule_state.anomaly_flags.is_empty() {
            format!(
                "Live Trust {:.1}% | Delta {:.2} | H_lambda {:.2}",
                found_percent,
                result.capsule_state.delta_ratio,
                result.capsule_state.h_lambda,
            )
        } else {
            format!(
                "Live Flags: {}",
                result.capsule_state.anomaly_flags.join(", ")
            )
        };
        self.upsert_gaming_progress(game_hint, username, found_percent, improved_percent, &insight);
    }

    fn clear_runtime_keys(&mut self) {
        if let Some(mut data_key) = self.data_key.take() {
            data_key.zeroize();
        }
        self.data_key_fingerprint.clear();
    }

    fn derive_runtime_keys(&mut self, user: &UserRecord, password: &str) {
        let data_key = DataKey::derive(password, &user.salt_hex, &user.username);
        self.data_key_fingerprint = data_key.fingerprint();
        self.data_key = Some(data_key);
    }

    fn data_key_fork(&self) -> Option<DataKey> {
        self.data_key.as_ref().map(DataKey::fork)
    }

    fn security_mode(&self) -> String {
        self.current_user
            .as_ref()
            .and_then(|user| user.user_settings.get("security_mode"))
            .cloned()
            .unwrap_or_else(|| "local".to_owned())
    }

    fn set_security_mode(&mut self, mode: &str) {
        let Some(username) = self.current_username() else {
            self.status_line = "Security-Modus erfordert eine lokale Anmeldung.".to_owned();
            return;
        };
        match self
            .auth_store
            .update_user_setting(&username, "security_mode", mode)
        {
            Ok(()) => {
                if let Some(user) = self.current_user.as_mut() {
                    user.user_settings
                        .insert("security_mode".to_owned(), mode.to_owned());
                }
                self.refresh_security_snapshot(true, "mode_change");
                self.status_line = format!("Security-Modus auf {} gesetzt.", mode.to_uppercase());
            }
            Err(err) => {
                self.status_line = err;
            }
        }
    }

    fn entries(&self) -> Vec<RegisterEntry> {
        self.current_username()
            .map(|username| self.state_store.entries_for(&username))
            .unwrap_or_default()
    }

    fn private_threads(&self) -> Vec<PrivateThread> {
        self.current_username()
            .map(|username| self.state_store.private_threads_for(&username))
            .unwrap_or_default()
    }

    fn group_rooms(&self) -> Vec<GroupRoom> {
        self.current_username()
            .map(|username| self.state_store.group_rooms_for(&username))
            .unwrap_or_default()
    }

    fn blocked_usernames(&self) -> Vec<String> {
        self.current_username()
            .map(|username| self.state_store.blocked_users_for(&username))
            .unwrap_or_default()
    }

    fn other_usernames(&self) -> Vec<String> {
        let current = self.current_username();
        let query = self.chat_user_search.trim().to_ascii_lowercase();
        self.auth_store
            .usernames()
            .into_iter()
            .filter(|username| Some(username.clone()) != current)
            .filter(|username| {
                if let Some(current_username) = current.as_ref() {
                    !self
                        .state_store
                        .is_blocked_between(current_username, username)
                } else {
                    true
                }
            })
            .filter(|username| {
                query.is_empty() || username.to_ascii_lowercase().contains(query.as_str())
            })
            .collect()
    }

    fn active_private_partner(&self) -> Option<String> {
        if let Some(selected) = &self.selected_private_partner {
            return Some(selected.clone());
        }
        self.private_threads()
            .into_iter()
            .map(|thread| thread.partner_name)
            .next()
    }

    fn active_private_messages(&self) -> Vec<ChatMessage> {
        let Some(partner) = self.active_private_partner() else {
            return Vec::new();
        };
        self.private_threads()
            .into_iter()
            .find(|thread| thread.partner_name == partner)
            .map(|thread| thread.messages)
            .unwrap_or_default()
    }

    fn active_private_blocked(&self) -> bool {
        let Some(username) = self.current_username() else {
            return false;
        };
        let Some(partner) = self.active_private_partner() else {
            return false;
        };
        self.state_store.is_blocked_between(&username, &partner)
    }

    fn active_group_room(&self) -> Option<GroupRoom> {
        let rooms = self.group_rooms();
        if let Some(selected_id) = &self.selected_group_room_id {
            if let Some(room) = rooms.iter().find(|room| room.id == *selected_id) {
                return Some(room.clone());
            }
        }
        rooms.into_iter().next()
    }

    fn active_group_messages(&self) -> Vec<ChatMessage> {
        self.active_group_room()
            .map(|room| room.messages)
            .unwrap_or_default()
    }

    fn active_group_is_owner(&self) -> bool {
        let Some(username) = self.current_username() else {
            return false;
        };
        self.active_group_room()
            .map(|room| room.owner_username == username)
            .unwrap_or(false)
    }

    fn select_group_room(&mut self, room_id: String) {
        self.selected_group_room_id = Some(room_id.clone());
        self.chat_context = ChatContext::Group;
        if let Some(room) = self.state_store.group_room_by_id(&room_id) {
            self.status_line = format!("Gruppe '{}' geoeffnet.", room.name);
        }
    }

    fn queue_pending_chat_share(&mut self) {
        self.pending_chat_partner = None;
        self.pending_chat_group_room_id = None;
        if self.active_tab != Tab::Chat {
            return;
        }
        match self.chat_context {
            ChatContext::Private => {
                self.pending_chat_partner = self.active_private_partner();
            }
            ChatContext::Group => {
                self.pending_chat_group_room_id = self.active_group_room().map(|room| room.id);
            }
            ChatContext::SwarmRequest => {}
        }
    }

    fn structure_share_message(&self, result: &FileAnalysisResult) -> String {
        format!(
            "Strukturabgleich · {} | Anchors {} | Trust {:.1}% | Gewinn {:.1}% | {}",
            result.snapshot.file_name,
            result.structure_map_state.anchor_count,
            result.capsule_state.trust_score * 100.0,
            result.snapshot.compression_gain_percent,
            result.snapshot.preview_note,
        )
    }

    fn publish_pending_chat_share(&mut self, result: &FileAnalysisResult) -> Result<Option<String>, String> {
        let Some(author) = self.current_username() else {
            self.pending_chat_partner = None;
            self.pending_chat_group_room_id = None;
            return Ok(None);
        };
        let body = self.structure_share_message(result);
        if let Some(partner) = self.pending_chat_partner.take() {
            if self.state_store.is_blocked_between(&author, &partner) {
                return Ok(Some(format!(
                    "Strukturvergleich mit {} wurde durch eine Blockliste gestoppt.",
                    partner
                )));
            }
            self.state_store
                .add_private_message(&author, &partner, &author, &body)?;
            if self
                .auth_store
                .usernames()
                .into_iter()
                .any(|username| username == partner)
            {
                let _ = self
                    .state_store
                    .add_private_message(&partner, &author, &author, &body);
            }
            self.selected_private_partner = Some(partner.clone());
            return Ok(Some(format!(
                "Strukturvergleich im privaten Thread mit {} abgelegt.",
                partner
            )));
        }
        if let Some(room_id) = self.pending_chat_group_room_id.take() {
            let Some(room) = self.state_store.group_room_by_id(&room_id) else {
                return Ok(Some("Ausgewaehlte Gruppe war nicht mehr verfuegbar.".to_owned()));
            };
            self.state_store.add_group_message(&room_id, &author, &body)?;
            self.selected_group_room_id = Some(room_id);
            return Ok(Some(format!(
                "Strukturvergleich in Gruppe '{}' abgelegt.",
                room.name
            )));
        }
        Ok(None)
    }

    fn anchor_clusters(&self) -> Vec<AnchorClusterView> {
        let mut grouped: BTreeMap<String, Vec<RegisterEntry>> = BTreeMap::new();
        for entry in self.entries() {
            let extension = entry
                .file_name
                .rsplit('.')
                .next()
                .map(|item| item.to_lowercase())
                .unwrap_or_else(|| "struktur".to_owned());
            let source = if entry.source_kind.trim().is_empty() {
                "lokal".to_owned()
            } else {
                entry.source_kind.to_lowercase()
            };
            grouped
                .entry(format!("{source}|{extension}"))
                .or_default()
                .push(entry);
        }
        if grouped.is_empty() {
            return vec![
                AnchorClusterView {
                    title: "Cluster 01".to_owned(),
                    descriptor: "Leeres Startprofil".to_owned(),
                    item_count: 0,
                    total_bytes: 0,
                    sample_note:
                        "Aether erzeugt Cluster datengetrieben aus lokalen Strukturmerkmalen."
                            .to_owned(),
                    first_seen: None,
                    last_seen: None,
                    observation_count: 0,
                },
                AnchorClusterView {
                    title: "Analyse-Gruppe A".to_owned(),
                    descriptor: "Vorbereitung".to_owned(),
                    item_count: 0,
                    total_bytes: 0,
                    sample_note:
                        "Keine Ausfuehrung. Nur isolierte Verarbeitung und Anchor-Signale."
                            .to_owned(),
                    first_seen: None,
                    last_seen: None,
                    observation_count: 0,
                },
            ];
        }
        grouped
            .into_iter()
            .enumerate()
            .map(|(index, (key, items))| {
                let mut parts = key.split('|');
                let source = parts.next().unwrap_or("lokal");
                let extension = parts.next().unwrap_or("struktur");
                let total_bytes = items.iter().map(|entry| entry.original_size).sum();
                let sample_note = items
                    .first()
                    .map(|entry| entry.preview_note.clone())
                    .unwrap_or_else(|| "Noch kein Detail.".to_owned());
                // Zeitdimension: FlowSphere-History nach passenden Dateinamen durchsuchen.
                // Kein Einfluss auf Metriken — nur Anzeige.
                let file_names: std::collections::HashSet<&str> =
                    items.iter().map(|e| e.file_name.as_str()).collect();
                let matching_ts: Vec<u64> = self
                    .flow_sphere_history
                    .iter()
                    .filter(|e| file_names.contains(e.source_label.as_str()))
                    .map(|e| e.visual_timestamp_secs(self.temporal_metadata_consent))
                    .collect();
                let first_seen = matching_ts.iter().copied().min();
                let last_seen  = matching_ts.iter().copied().max();
                let observation_count = matching_ts.len();
                AnchorClusterView {
                    title: format!("Cluster {:02}", index + 1),
                    descriptor: format!("{} / .{}", source, extension),
                    item_count: items.len(),
                    total_bytes,
                    sample_note,
                    first_seen,
                    last_seen,
                    observation_count,
                }
            })
            .collect()
    }

    fn context_button(&self, context: ChatContext, label: &'static str) -> Element<'_, Message> {
        let is_active = self.chat_context == context;
        container(
            button(text(label).size(15))
                .padding([8, 18])
                .on_press(Message::ChatContextSelected(context))
                .style(if is_active { primary_button_style } else { secondary_button_style }),
        )
        .style(move |_theme: &Theme| {
            if is_active {
                container::Style {
                    background: Some(Background::Color(Color::from_rgba(0.59, 0.34, 0.96, 0.12))),
                    border: Border {
                        color: Color::from_rgb8(0xA0, 0x70, 0xFF),
                        width: 1.2,
                        radius: 10.0.into(),
                    },
                    text_color: Some(Color::from_rgb8(0xEE, 0xEA, 0xFF)),
                    ..Default::default()
                }
            } else {
                container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x12, 0x11, 0x1C))),
                    border: Border {
                        color: Color::from_rgb8(0x2C, 0x2A, 0x46),
                        width: 1.0,
                        radius: 10.0.into(),
                    },
                    ..Default::default()
                }
            }
        })
        .into()
    }

    fn view_auth(&self) -> Element<'_, Message> {
        let left: Element<'_, Message> = container(
            Column::new()
                .push(
                    container(
                        row![
                            text("ADE").size(54).color(Color::from_rgb8(0x8B, 0x52, 0xF6)),
                            column![
                                text("Aether-Delta Engine").size(28).color(c(TEXT_H())),
                                text("Structural capsule runtime for local analysis and reconstruction.")
                                    .size(12)
                                    .color(c(TEXT_M())),
                            ]
                            .spacing(2)
                        ]
                        .spacing(14)
                        .align_y(Alignment::Center)
                    )
                    .padding([6, 0])
                )
                .push(text("AetherGuard").size(30).color(Color::from_rgb8(0xA0, 0x60, 0xFF)))
                .push(text("Deterministic Security Kernel").size(34).color(c(TEXT_H())))
                .push(text("Lokale Analyse, rekonstruierbare Entscheidungen und Privacy by Architecture.")
                    .size(14)
                    .color(c(TEXT_M())))
                .push(text("Kein Cloud-Zwang. Keine Black Box. Keine versteckte Semantik.")
                    .size(13)
                    .color(c(TEXT_D())))
                .push(container(
                    Column::new()
                        .push(text("Live Engine State").size(12).color(c(TEXT_M())))
                        .push(text(format!("Tick {}", self.tick_counter)).size(14).color(c(TEXT_H())))
                        .push(text(format!("Runtime {}", self.runtime_profile_label())).size(12).color(c(TEXT_D())))
                        .push(text(format!("Swarm {}", self.swarm_startup.node_count)).size(12).color(c(TEXT_D())))
                        .push(text(if self.swarm_startup.node_initialized {
                            self.swarm_startup.summary.clone()
                        } else {
                            "Rust-Start blockiert keinen Login, aber Node-Init fehlt.".to_owned()
                        })
                        .size(11)
                        .color(c(TEXT_D())))
                        .spacing(4)
                )
                .padding(12)
                .style(accent_card_style))
                // Backup-Option Beschreibung (sichtbar im Auth/Analyse-Panel)
                .push(container(
                    Column::new()
                        .push(text("Backup vor Analyse").size(13).color(c(TEXT_H())))
                        .push(text("Jede Datei wird vor der Analyse automatisch gesichert (C:/AetherBackup). Diese Option schützt vor Datenverlust und kann in den Einstellungen deaktiviert werden.")
                            .size(11)
                            .color(c(TEXT_M())))
                        .spacing(2)
                )
                .padding(8)
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x16, 0x20, 0x28))),
                    border: Border {
                        color: Color::from_rgb8(0x2F, 0xA3, 0xB5),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                }))
                .spacing(12)
        )
        .padding(18)
        .style(panel_frame_style)
        .width(Length::FillPortion(3))
        .into();

        let status_color = if self.status_line.contains("erfolgreich") || self.status_line.contains("abgeschlossen") {
            Color::from_rgb8(0x4C, 0xD9, 0x6E)
        } else if self.status_line.is_empty() || self.status_line.contains("Bitte") {
            Color::from_rgb8(0x88, 0x84, 0xAA)
        } else {
            Color::from_rgb8(0xD9, 0x6E, 0x4C)
        };

        let right: Element<'_, Message> = container(
            Column::new()
                .push(text("Anmelden").size(28).color(c(TEXT_H())))
                .push(text("Benutzername").size(12).color(c(TEXT_M())))
                .push(
                    text_input("Benutzername eingeben", &self.login_username)
                        .on_input(Message::LoginUsernameChanged)
                        .padding([11, 14])
                        .size(15)
                )
                .push(text("Passwort").size(12).color(c(TEXT_M())))
                .push(
                    text_input("Passwort eingeben", &self.login_password)
                        .on_input(Message::LoginPasswordChanged)
                        .secure(true)
                        .padding([11, 14])
                        .size(15)
                )
                .push(
                    button(text("  Anmelden  ").size(15).color(Color::WHITE))
                        .on_press(Message::LoginPressed)
                        .padding([12, 28])
                        .style(|_: &Theme, _| button::Style {
                            background: Some(Background::Color(Color::from_rgb8(0x5A, 0x2E, 0xC8))),
                            border: Border {
                                color: Color::from_rgb8(0xA0, 0x70, 0xFF),
                                width: 1.0,
                                radius: 10.0.into(),
                            },
                            text_color: Color::WHITE,
                            ..Default::default()
                        })
                )
                .push(
                    button(text("Neu registrieren").size(13).color(c(TEXT_M())))
                        .on_press(Message::RegisterPressed)
                        .padding([9, 18])
                        .style(|_: &Theme, _| button::Style {
                            background: Some(Background::Color(Color::from_rgba(0.28, 0.18, 0.55, 0.35))),
                            border: Border {
                                color: Color::from_rgb8(0x60, 0x50, 0x90),
                                width: 1.0,
                                radius: 8.0.into(),
                            },
                            ..Default::default()
                        })
                )
                .push(
                    container(
                        text(if self.status_line.is_empty() {
                            "Lokale Authentifizierung — kein Cloud-Zugang erforderlich.".to_owned()
                        } else {
                            self.status_line.clone()
                        })
                        .size(12)
                        .color(status_color),
                    )
                    .padding([8, 0])
                )
                .spacing(14)
        )
        .padding(32)
        .style(panel_frame_style)
        .width(Length::FillPortion(2))
        .into();

        container(
            Row::new()
                .push(left)
                .push(right)
                .spacing(0)
                .width(Length::Fill)
                .height(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x06, 0x08, 0x14))),
            ..Default::default()
        })
        .into()
    }
    // ---------------------------------------------------------------------------
// Aether.FlowSphere – deterministic 3D sphere projection (iced Canvas)
// Replaces the old 10-ring StructureMap as the modern structural visualizer.
// All animation parameters are derived from tick + entropy, no random values.
// ---------------------------------------------------------------------------
    fn view_home(&self) -> Element<'_, Message> {
        self.view_home_aether_cyber()
    }

    fn view_home_aether_cyber(&self) -> Element<'_, Message> {
        let t = self.tick_counter as f32;
        let risk_score = (self.backend_entropy_mean * 1000.0) as u32;
        let noether_score = if self.backend_state_loaded {
            (self.backend_entropy_mean / 8.0).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let entries = self.entries();
        let private_threads = self.private_threads();
        let group_rooms = self.group_rooms();
        let anchor_clusters = self.anchor_clusters();
        let total_original_bytes: u64 = entries.iter().map(|entry| entry.original_size).sum();
        let total_delta_bytes: u64 = entries.iter().map(|entry| entry.delta_size).sum();
        let avg_compression_gain = if entries.is_empty() {
            0.0
        } else {
            entries
                .iter()
                .map(|entry| entry.compression_gain_percent)
                .sum::<f32>()
                / entries.len() as f32
        };
        let total_private_messages: usize = private_threads
            .iter()
            .map(|thread| thread.messages.len())
            .sum();
        let total_group_messages: usize = group_rooms
            .iter()
            .map(|room| room.messages.len())
            .sum();
        let latest_entry_note = entries
            .first()
            .map(|entry| {
                format!(
                    "#{} {} | {} | {}",
                    entry.id,
                    entry.file_name,
                    if entry.anchor_summary.trim().is_empty() {
                        "kein Anchor-Summary".to_owned()
                    } else {
                        entry.anchor_summary.clone()
                    },
                    if entry.preview_note.trim().is_empty() {
                        "keine Vorschau".to_owned()
                    } else {
                        entry.preview_note.clone()
                    }
                )
            })
            .unwrap_or_else(|| "Noch keine lokale Analyse ausgefuehrt.".to_owned());
        let pane_slide = ((self.tick_counter % 8) as f32 / 8.0).clamp(0.0, 1.0); // 120ms @ ~60fps
        let node_pulse = 1.0 + 0.03 * (t * 1.57).sin(); // 40ms pulse
        let data_flash = 0.45 + 0.55 * (t * 5.0).sin().abs(); // pulse intensity for border shimmer
        let _graph_reveal = ((self.tick_counter % 6) as f32 / 6.0).clamp(0.0, 1.0); // 90ms reveal
        let info_reveal = (((self.tick_counter.saturating_sub(self.dashboard_info_open_tick)) as f32)
            * self.tick_interval_ms() as f32 / 80.0)
            .clamp(0.0, 1.0);

        let threat_rows: Vec<(String, String, String, String, String)> = vec![];
        let device_rows: Vec<(String, f32)> = vec![];

        let q = self.dashboard_search.trim().to_ascii_lowercase();
        let _filtered_threat_rows: Vec<_> = threat_rows
            .into_iter()
            .filter(|(_, device, virus, path, file_type)| {
                q.is_empty()
                    || device.to_ascii_lowercase().contains(&q)
                    || virus.to_ascii_lowercase().contains(&q)
                    || path.to_ascii_lowercase().contains(&q)
                    || file_type.to_ascii_lowercase().contains(&q)
            })
            .collect();

        let device_panel: Element<'_, Message> = container({
            let mut col = Column::new();
            let mut row1 = Row::new();
            row1 = row1.push(text("Threat by device").size(18).color(c(TEXT_H())));
            row1 = row1.push(info_icon_button("device_list"));
            col = col.push(row1.spacing(8).align_y(Alignment::Center));

            let mut rows_col = Column::new();
            for (device, level) in device_rows {
                let mut row = Row::new();
                row = row.push(
                    text(device)
                        .size(12)
                        .color(c(TEXT_H()))
                        .width(Length::FillPortion(3)),
                );
                row = row.push(iced::Element::from(
                    canvas::Canvas::new(DonutScene {
                        values: [level, 1.0 - level, 0.0, 0.0],
                        colors: [
                            Color::from_rgb8(0xC7, 0xA0, 0x4A),
                            Color::from_rgb8(0x12, 0x1B, 0x22),
                            Color::TRANSPARENT,
                            Color::TRANSPARENT,
                        ],
                        pulse: node_pulse,
                    })
                    .height(Length::Fixed(24.0))
                    .width(Length::Fixed(24.0)),
                ));
                rows_col = rows_col.push(row.spacing(8).align_y(Alignment::Center));
            }

            col = col.push(rows_col.spacing(7));
            col.spacing(8)
        })
        .padding(14)
        .width(Length::FillPortion(2))
        .style(standard_card_style)
        .into();

        let info_overlay: Element<'_, Message> = if let Some(key) = &self.dashboard_info_key {
            let alpha = (0.20 + 0.80 * info_reveal).clamp(0.0, 1.0);
            container({
                let mut col = Column::new().spacing(8);
                let mut row = Row::new();
                row = row.push(text(format!("Info: {key}")).size(14).color(c(TEXT_H())));
                row = row.push(iced::widget::Space::new(Length::Fill, Length::Shrink));
                row = row.push(button(text("x").size(12)).on_press(Message::DashboardInfoToggle(key.clone())).padding([2, 8]));
                col = col.push(row.align_y(Alignment::Center));
                col = col.push(text(dashboard_info_text(key)).size(12).color(c(TEXT_M())));
                col
            })
            .padding(12)
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.03, 0.10, 0.18, alpha))),
                border: Border { color: Color::from_rgba(0.63, 0.43, 1.0, alpha), width: 1.0 + 1.2 * info_reveal, radius: (6.0 + 10.0 * info_reveal).into() },
                ..Default::default()
            })
            .width(Length::Fill)
            .into()
        } else {
            container(iced::widget::Space::new(Length::Shrink, Length::Shrink)).into()
        };

        let dashboard_body: Element<'_, Message> = if self.dashboard_nav == "Overview" {
            let primary_metrics = Row::new()
                .spacing(10)
                .push(info_card("Trust-State", &self.security_snapshot.trust_state))
                .push(info_card("Lokale Artefakte", &entries.len().to_string()))
                .push(info_card("Anchor-Cluster", &anchor_clusters.len().to_string()))
                .push(info_card("Risk Score", &risk_score.to_string()));

            let system_metrics = Row::new()
                .spacing(10)
                .push(info_card("Noether", &format!("{:.3}", noether_score)))
                .push(info_card("CPU", &format!("{:.1}%", self.backend_cpu_pct)))
                .push(info_card("RAM", &format!("{:.2} GB", self.backend_mem_used_gb)))
                .push(info_card("Swarm-Nodes", &self.swarm_startup.node_count.to_string()));

            let cap_pct = (self.backend_capability_score * 100.0) as u32;
            let cap_stage_label = if self.backend_capability_stage.is_empty() {
                "Wird analysiert…".to_owned()
            } else {
                self.backend_capability_stage.clone()
            };
            let cap_accent = if cap_pct >= 100 {
                Color::from_rgb8(0x4C, 0xD9, 0x6E)
            } else if cap_pct >= 75 {
                Color::from_rgb8(0x66, 0x40, 0xCD)
            } else if cap_pct >= 50 {
                Color::from_rgb8(0xFF, 0xC8, 0x3A)
            } else {
                Color::from_rgb8(0x70, 0x90, 0xA8)
            };
            let capability_panel: Element<'_, Message> = container(
                Column::new()
                    .push(
                        Row::new()
                            .push(text("Aether OS Readiness").size(13).color(c(TEXT_H())))
                            .push(iced::widget::Space::new(Length::Fill, Length::Shrink))
                            .push(text(format!("{}% — {}", cap_pct, cap_stage_label))
                                .size(12)
                                .color(cap_accent))
                            .spacing(8)
                            .align_y(Alignment::Center),
                    )
                    .push(progress_bar(0.0..=1.0, self.backend_capability_score).height(7))
                    .push(
                        text(
                            "Jedes Subsystem das erfolgreich startet erhöht den Score. \
                             Bei 100 % ist der vollständige Aether-OS-Modus verfügbar."
                        )
                        .size(11)
                        .color(c(TEXT_D())),
                    )
                    .spacing(5),
            )
            .padding([10, 14])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.02, 0.07, 0.14, 0.92))),
                border: Border {
                    color: cap_accent,
                    width: 1.0,
                    radius: 8.0.into(),
                },
                ..Default::default()
            })
            .width(Length::Fill)
            .into();

            let quick_actions = container(
                Row::new()
                    .spacing(10)
                    .push(
                        button(text("Dateien pruefen").size(13))
                            .on_press(Message::TabSelected(Tab::Data))
                            .padding([10, 14])
                            .style(primary_button_style),
                    )
                    .push(
                        button(text("Delta-Analyse").size(13))
                            .on_press(Message::TabSelected(Tab::ADE))
                            .padding([10, 14])
                            .style(secondary_button_style),
                    )
                    .push(
                        button(text("Launcher").size(13))
                            .on_press(Message::TabSelected(Tab::Launcher))
                            .padding([10, 14])
                            .style(secondary_button_style),
                    )
                    .push(
                        button(text("Logs").size(13))
                            .on_press(Message::TabSelected(Tab::Logs))
                            .padding([10, 14])
                            .style(secondary_button_style),
                    ),
            )
            .padding(12)
            .style(accent_card_style);

            let artifacts_panel: Element<'_, Message> = container({
                let mut col = Column::new().spacing(8);
                col = col.push(text("Artefaktlage").size(18).color(c(TEXT_H())));
                col = col.push(text(format!(
                    "Originaldaten {} B | Delta {} B | mittlere Kompression {:.2}%",
                    total_original_bytes,
                    total_delta_bytes,
                    avg_compression_gain
                )).size(12).color(c(TEXT_M())));
                col = col.push(info_card("Neueste Analyse", &latest_entry_note));

                if entries.is_empty() {
                    col = col.push(text("Noch keine Register-Eintraege vorhanden. Ziehe eine Datei in das Fenster oder oeffne den Files-Tab.")
                        .size(12)
                        .color(c(TEXT_D())));
                } else {
                    for entry in entries.iter().take(4) {
                        let summary = format!(
                            "{} | {} B -> {} B | {:.2}% | {}",
                            entry.file_name,
                            entry.original_size,
                            entry.delta_size,
                            entry.compression_gain_percent,
                            if entry.process_summary.trim().is_empty() {
                                "kein Prozess-Summary"
                            } else {
                                entry.process_summary.as_str()
                            }
                        );
                        col = col.push(info_card("Register", &summary));
                    }
                }

                col
            })
            .padding(14)
            .style(standard_card_style)
            .width(Length::FillPortion(2))
            .into();

            let comms_panel: Element<'_, Message> = container({
                let mut col = Column::new().spacing(8);
                col = col.push(text("Kommunikation & Sitzungen").size(18).color(c(TEXT_H())));
                col = col.push(info_card("Private Threads", &private_threads.len().to_string()));
                col = col.push(info_card("Gruppen", &group_rooms.len().to_string()));
                col = col.push(info_card("Private Nachrichten", &total_private_messages.to_string()));
                col = col.push(info_card("Gruppen-Nachrichten", &total_group_messages.to_string()));
                col = col.push(info_card(
                    "Session-Policy",
                    "Aktive Session wird nicht von Platte wiederhergestellt. Jeder Start verlangt eine neue lokale Anmeldung.",
                ));
                col
            })
            .padding(14)
            .style(standard_card_style)
            .width(Length::FillPortion(1))
            .into();

            let runtime_panel: Element<'_, Message> = container({
                let mut col = Column::new().spacing(8);
                col = col.push(text("Systemzustand").size(18).color(c(TEXT_H())));
                col = col.push(info_card("Runtime-Profil", self.runtime_profile_label()));
                col = col.push(info_card("Tick-Intervall", &format!("{} ms", self.tick_interval_ms())));
                col = col.push(info_card("Analyse-Status", &self.analysis_status));
                col = col.push(info_card(
                    "Swarm",
                    &if self.swarm_startup.node_initialized {
                        self.swarm_startup.summary.clone()
                    } else {
                        format!("Node-Init fehlt | {}", self.swarm_startup.summary)
                    },
                ));
                col = col.push(info_card(
                    "Hybrid-Bridge",
                    if self.hybrid_bridge_running { "aktiv" } else { "inaktiv" },
                ));
                col
            })
            .padding(14)
            .style(standard_card_style)
            .width(Length::Fill)
            .into();

            Column::new()
                .spacing(10)
                .push(primary_metrics)
                .push(system_metrics)
                .push(capability_panel)
                .push(quick_actions)
                .push(Row::new().spacing(10).push(artifacts_panel).push(comms_panel))
                .push(runtime_panel)
                .into()
        } else {
            let embedded: Element<'_, Message> = match self.dashboard_nav.as_str() {
                "Files" => self.view_data(),
                "Chat" => self.view_chat(),
                "Logs" => self.view_logs(),
                "Delta-Analyse" => self.view_ade(),
                "FlowSphere" => self.view_flow_sphere(),
                "Threat Graph" => self.view_flow_sphere(),
                "Delta Convergence" => self.view_delta_convergence(),
                "Anchors" => self.view_anchors(),
                "Reconstruction" => self.view_rekonstruktion(),
                "Info" => self.view_imprint(),
                "Runtime" => self.view_dashboard_performance(),
                _ => self.view_logs(),
            };
            container(embedded)
                .padding(4)
                .style(standard_card_style)
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        };

        let mid_layer = container(
            {
                let mut col = Column::new().spacing(10);
                col = col.push(container(text(self.dashboard_search_help()).size(11).color(c(TEXT_D()))).padding([0, 4]));
                col = col.push(dashboard_body);
                col = col.push(info_overlay);
                col
            }
        )
        .style(standard_card_style)
        .padding(10)
        .width(Length::Fill);

        let _background_layer: Element<'_, Message> = container(iced::widget::Space::new(Length::Fill, Length::Fill))
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgb8(0x0C, 0x0B, 0x12))),
                border: Border {
                    color: Color::from_rgba(0.61, 0.39, 1.0, 0.22 + 0.28 * data_flash),
                    width: 1.0 + 0.8 * node_pulse,
                    radius: 14.0.into(),
                },
                ..Default::default()
            })
            .into();

        let overlay_layer = container(
            {
                let mut row = Row::new().spacing(8).align_y(Alignment::Center);
                row = row.push(text(format!("Noether {:.3}", noether_score)).size(11).color(c(TEXT_H())));
                row = row.push(info_icon_button("noether_score"));
                row = row.push(text(format!("Risk {}", risk_score)).size(11).color(c(WARN())));
                row = row.push(text(format!("Aether Event Model | Nav: {}", self.dashboard_nav)).size(11).color(c(TEXT_D())));
                row = row.push(text(format!(
                    "Runtime {} | Tick {}ms",
                    self.runtime_profile_label(),
                    self.tick_interval_ms(),
                )).size(11).color(c(TEXT_M())));
                row
            }
        )
        .padding([6, 10])
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.03, 0.09, 0.20, 0.65 * pane_slide + 0.25))),
            border: Border { color: c(BORDER()), width: 1.0, radius: 8.0.into() },
            ..Default::default()
        });

        column![overlay_layer, mid_layer, device_panel]
            .width(Length::Fill)
            .height(Length::Fill)
            .spacing(10)
            .into()
    }
    fn view_dashboard_performance(&self) -> Element<'_, Message> {
        let profile = self.runtime_profile;
        let profile_button = |label: &'static str, p: RuntimeProfile, active: bool| {
            button(text(if active { format!("{} [active]", label) } else { label.to_owned() }).size(13))
                .on_press(Message::RuntimeProfileSelected(p))
                .padding([10, 14])
                .style(move |_: &Theme, _| button::Style {
                    background: Some(Background::Color(if active {
                        Color::from_rgba(0.59, 0.34, 0.96, 0.22)
                    } else {
                        Color::from_rgba(0.07, 0.14, 0.24, 0.86)
                    })),
                    border: Border {
                        color: if active { Color::from_rgb8(0xA0, 0x70, 0xFF) } else { Color::from_rgb8(0x2E, 0x2C, 0x4C) },
                        width: if active { 1.2 } else { 1.0 },
                        radius: 10.0.into(),
                    },
                    ..Default::default()
                })
        };

        container({
            let mut col = Column::new();
            let mut row1 = Row::new().spacing(8).align_y(Alignment::Center);
            row1 = row1.push(text("Performance Optimization").size(22).color(c(TEXT_H())));
            row1 = row1.push(info_icon_button("performance"));
            row1 = row1.push(iced::widget::Space::new(Length::Fill, Length::Shrink));
            row1 = row1.push(text(format!("Current: {}", self.runtime_profile_label())).size(12).color(c(TEXT_M())));
            col = col.push(row1);
            col = col.push(text("Deterministic runtime profiles for latency, throughput and low-resource stability.").size(13).color(c(TEXT_M())));
            let mut row2 = Row::new().spacing(10);
            row2 = row2.push(profile_button("AUTO", RuntimeProfile::Auto, profile == RuntimeProfile::Auto));
            row2 = row2.push(profile_button("BALANCED", RuntimeProfile::Balanced, profile == RuntimeProfile::Balanced));
            row2 = row2.push(profile_button("LOW-POWER", RuntimeProfile::LowPower, profile == RuntimeProfile::LowPower));
            row2 = row2.push(profile_button("LEGACY", RuntimeProfile::Legacy, profile == RuntimeProfile::Legacy));
            col = col.push(row2);
            let mut row3 = Row::new().spacing(10);
            row3 = row3.push(info_card("Tick-Intervall", &format!("{} ms", self.tick_interval_ms())));

            col = col.push(row3);
            let mut row4 = Row::new().spacing(10);
            row4 = row4.push(info_card("Analyse-Status", &self.analysis_status));
            row4 = row4.push(info_card(
                "Node-Status",
                if self.swarm_startup.node_initialized {
                    "initialisiert"
                } else {
                    "fehlt"
                }
            ));
            row4 = row4.push(info_card("Swarm-Nodes", &self.swarm_startup.node_count.to_string()));
            row4 = row4.push(info_card("Neue Packs", &self.swarm_startup.new_pack_count.to_string()));
            col = col.push(row4);
            col = col.push(
                container(text(&self.swarm_startup.summary).size(12).color(c(TEXT_D())))
                    .padding(10)
                    .style(standard_card_style)
            );
            col = col.push(
                container(
                    text("Hinweis: Diese Profile beeinflussen Scheduler-Takt, Browser-Sync-Frequenz und Lastcharakteristik deterministisch.")
                        .size(12)
                        .color(c(TEXT_D()))
                )
                .padding(10)
                .style(standard_card_style)
            );
            col.spacing(12)
        })
        .padding(12)
        .style(accent_card_style)
        .into()
    }

    fn view_chat(&self) -> Element<'_, Message> {
        let tutorial_button: Element<'_, Message> = if self.show_tutorial {
            button(text("Tutorial ausblenden"))
                .padding([8, 14])
                .on_press(Message::TutorialDismissed)
                .into()
        } else {
            container(text("")).into()
        };
        let panel = match self.chat_context {
            ChatContext::Private => self.view_private_chat(),
            ChatContext::Group => self.view_group_chat(),
            ChatContext::SwarmRequest => self.view_swarm_requests(),
        };
        // Swarm-Anfragen-Tab with a live count badge when requests are pending.
        let swarm_req_count = self.swarm_overlap_requests.len();
        let swarm_tab_label = if swarm_req_count > 0 {
            format!("Swarm-Anfragen ({})", swarm_req_count)
        } else {
            "Swarm-Anfragen".to_string()
        };
        let is_swarm_active = self.chat_context == ChatContext::SwarmRequest;
        let swarm_tab_btn: Element<'_, Message> = container(
            button(text(swarm_tab_label).size(15))
                .padding([8, 18])
                .on_press(Message::ChatContextSelected(ChatContext::SwarmRequest))
                .style(if is_swarm_active {
                    primary_button_style
                } else {
                    secondary_button_style
                }),
        )
        .style(move |_theme: &Theme| {
            if is_swarm_active {
                container::Style {
                    background: Some(Background::Color(Color::from_rgba(
                        0.59, 0.34, 0.96, 0.12,
                    ))),
                    border: Border {
                        color: Color::from_rgb8(0xA0, 0x70, 0xFF),
                        width: 1.2,
                        radius: 10.0.into(),
                    },
                    text_color: Some(Color::from_rgb8(0xEE, 0xEA, 0xFF)),
                    ..Default::default()
                }
            } else {
                container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x12, 0x11, 0x1C))),
                    border: Border {
                        color: Color::from_rgb8(0x2C, 0x2A, 0x46),
                        width: 1.0,
                        radius: 10.0.into(),
                    },
                    ..Default::default()
                }
            }
        })
        .into();
        container(
            Column::new()
                .push(
                    Row::new()
                        .push(self.context_button(ChatContext::Private, "Privat"))
                        .push(self.context_button(ChatContext::Group, "Gruppen"))
                        .push(swarm_tab_btn)
                        .push(tutorial_button)
                        .spacing(10)
                )
                .push(panel)
                .spacing(16),
        )
        .padding(12)
        .into()
    }

    fn view_data(&self) -> Element<'_, Message> {
        let cyan = Color::from_rgb8(0x3F, 0xBA, 0xC2);
        let amber = Color::from_rgb8(0xD4, 0xA0, 0x42);
        let purple = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let green = Color::from_rgb8(0x4C, 0xD9, 0x6E);
        let capsule_state = self.capsule_state.as_ref();
        let structure_map_state = self.structure_map_state.as_ref();
        let compression_state = self.compression_state.as_ref();
        let analysis_detail = match (capsule_state, structure_map_state, self.last_analysis.as_ref()) {
            (Some(capsule), Some(structure_map), Some(analysis)) => format!(
                "{}\nTrigger {} | {} | {} B\nRegion {} | Nodes {} | Edges {} | Anchors {} | Flags {}\n{}",
                analysis.preview_note,
                capsule.trigger,
                capsule.domain_hint,
                capsule.size_bytes,
                structure_map.region_label,
                structure_map.node_count,
                structure_map.edge_count,
                structure_map.anchor_count,
                structure_map.anomaly_count,
                analysis.process_summary,
            ),
            (_, _, Some(analysis)) => format!(
                "{}\n{}\n{}",
                analysis.preview_note,
                analysis.anchor_summary,
                analysis.process_summary,
            ),
            _ => "Kompressionsgewinn, Delta, Capsule-Metriken und Structure-Map erscheinen nach dem ersten Drop oder Live-Render-Zyklus.".to_owned(),
        };
        let mut items = Column::new()
            .push(text("Data").size(24))
            .push(text("Dateien, Analysen, Deltas und Transformationen bleiben intern organisiert.").size(16))
            .push(
                container(
                    column![
                        text("Metriken direkt erklaeren").size(14).color(c(TEXT_H())),
                        Row::new()
                            .push(metric_help_chip("Entropie", "ENTROPY", purple))
                            .push(metric_help_chip("Symmetrie", "SYMMETRY", cyan))
                            .push(metric_help_chip("Delta", "DELTA", amber))
                            .push(metric_help_chip("Kompression", "COMPRESSION", green))
                            .spacing(8),
                        Row::new()
                            .push(metric_help_chip("H-Lambda", "H_LAMBDA", cyan))
                            .push(metric_help_chip("SCE", "SCE", green))
                            .push(metric_help_chip("Bayes", "BAYES", purple))
                            .push(metric_help_chip("Trust", "TRUST", amber))
                            .spacing(8),
                    ]
                    .spacing(8)
                )
                .padding([10, 12])
                .style(panel_frame_style)
            )
            .push(
                Column::new()
                    .push(
                        Row::new()
                            .push(Row::new().push(text("Entropie").size(12).color(c(TEXT_M()))).push(info_badge("Entropie beschreibt die Restunsicherheit eines Artefakts.")).spacing(6))
                            .push(Row::new().push(text("Symmetrie").size(12).color(c(TEXT_M()))).push(info_badge("Symmetrie markiert wiederkehrende Struktur und Invarianz.")).spacing(6))
                            .push(Row::new().push(text("Drift").size(12).color(c(TEXT_M()))).push(info_badge("Drift misst lokale Byte-Aenderung zwischen benachbarten Bereichen.")).spacing(6))
                            .spacing(12)
                    )
                    .push(
                        Row::new()
                            .push(Row::new().push(text("Gain").size(12).color(c(TEXT_M()))).push(info_badge("Gain beschreibt den Kompressionsgewinn gegen das Original.")).spacing(6))
                            .push(Row::new().push(text("E-Lambda").size(12).color(c(TEXT_M()))).push(info_badge("E-Lambda ist der interne Kohaerenzindikator der AEF-Pipeline.")).spacing(6))
                            .push(Row::new().push(text("Trust").size(12).color(c(TEXT_M()))).push(info_badge("Trust kombiniert Filter, Kohaerenz und Lossless-Bestaetigung.")).spacing(6))
                            .spacing(12)
                    )
                    .spacing(8)
            )
            .push(
                analysis_card(
                    self.analysis_progress,
                    &self.analysis_status,
                    &self.hovered_file_label,
                    &analysis_detail,
                )
            )
            .push(
                {
                    if let (Some(capsule), Some(structure_map)) = (capsule_state, structure_map_state) {
                        let scores = vec![
                            ("ENTROPY".to_string(), capsule.entropy),
                            ("H_LAMBDA".to_string(), capsule.h_lambda),
                            ("SYMMETRY".to_string(), capsule.symmetry),
                            ("PERIOD".to_string(), capsule.periodicity),
                            ("TRUST".to_string(), capsule.trust_score),
                            ("SCE".to_string(), structure_map.coherence_score),
                            ("ANCHORS".to_string(), structure_map.anchor_count as f32),
                            ("NODES".to_string(), structure_map.node_count as f32),
                        ];
                        view_score_panel(scores)
                    } else {
                        Column::new().into() // leer, falls keine Analyse vorliegt
                    }
                }
            );
        items = items.push(
            if let Some(compression) = compression_state {
                info_card(
                    "Kompression nach Analyse",
                    &format!(
                        "Format: {}\nOriginal: {} B | Komprimiert: {} B\nAenderung: {} B | Ratio: {:.4}\nGewinn: {:.2}%",
                        compression.format,
                        compression.original_bytes,
                        compression.compressed_bytes,
                        compression.changed_bytes,
                        compression.ratio,
                        compression.gain_percent,
                    ),
                )
            } else {
                info_card(
                    "Kompression nach Analyse",
                    "Noch keine Kompressionsdaten sichtbar. Nach einer erfolgreichen Datei-Analyse erscheint hier der konkrete Gewinn inklusive Ratio und geaenderter Bytes.",
                )
            }
        );
        let entries = self.entries();
        if entries.is_empty() {
            items = items.push(info_card(
                "Leerer Datenraum",
                "Sobald lokale Artefakte analysiert werden, erscheinen hier Analysepfade und Anchor-Signale.",
            ));
        } else {
            for entry in entries.into_iter().take(24) {
                items = items.push(register_card(entry));
            }
        }
        container(scrollable(items).height(Length::Fill))
            .padding(12)
            .into()
    }

    fn convergence_signal_pack(&self) -> (f32, f32, f32, f32, f32, f32, f32, f32) {
        let trust = self
            .capsule_state
            .as_ref()
            .map(|capsule| capsule.trust_score.clamp(0.0, 1.0))
            .or_else(|| self.structure_map_state.as_ref().map(|state| state.trust_score.clamp(0.0, 1.0)))
            .unwrap_or(0.0);
        let compression = self
            .compression_state
            .as_ref()
            .map(|state| (state.gain_percent / 100.0).clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let aelab_exact = self
            .aelab_state
            .as_ref()
            .map(|state| state.lossless.clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let reconstruction_exact = self
            .reconstruction_state
            .as_ref()
            .map(|state| {
                let base = state
                    .compressibility
                    .max(state.anchor_coverage)
                    .max(state.quality_score)
                    .clamp(0.0, 1.0);
                if state.verified {
                    base.max(0.65)
                } else {
                    base * 0.45
                }
            })
            .unwrap_or(0.0);
        let exactness = aelab_exact.max(reconstruction_exact).clamp(0.0, 1.0);
        let delta_convergence = self
            .capsule_state
            .as_ref()
            .map(|capsule| (1.0 - capsule.delta_ratio).clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let coherence = self
            .structure_map_state
            .as_ref()
            .map(|state| state.coherence_score.clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let noether = self
            .capsule_state
            .as_ref()
            .map(|capsule| capsule.noether_consistency.clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let reproducibility = self
            .reconstruction_state
            .as_ref()
            .map(|state| {
                if state.verified {
                    (0.55 + 0.45 * state.quality_score.clamp(0.0, 1.0)).clamp(0.0, 1.0)
                } else {
                    (0.18 + 0.32 * state.quality_score.clamp(0.0, 1.0)).clamp(0.0, 1.0)
                }
            })
            .unwrap_or(exactness * 0.5);
        let entries = self.entries().len() as f32;
        let entry_signal = ((entries + 1.0).ln() / 3.6).clamp(0.0, 1.0);
        let anchor_signal = self
            .structure_map_state
            .as_ref()
            .map(|state| (state.anchor_count as f32 / 24.0).clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let vault_signal = self
            .aelab_state
            .as_ref()
            .map(|state| (((state.vault_total_entries as f32) + 1.0).ln() / 5.5).clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let evidence = (0.40 * entry_signal + 0.30 * anchor_signal + 0.30 * vault_signal).clamp(0.0, 1.0);
        (trust, compression, exactness, delta_convergence, coherence, noether, reproducibility, evidence)
    }

    fn world_scores(&self, world: Tab) -> (f32, f32, f32, f32) {
        let (trust, compression, exactness, delta_convergence, coherence, noether, reproducibility, evidence) = self.convergence_signal_pack();
        match world {
            Tab::Gaming => {
                let known = (0.25 * trust + 0.20 * exactness + 0.15 * compression + 0.20 * evidence + 0.20 * delta_convergence).clamp(0.0, 1.0);
                let readiness = (0.30 * exactness + 0.25 * reproducibility + 0.20 * trust + 0.15 * noether + 0.10 * evidence).clamp(0.0, 1.0);
                let residual = (1.0 - (0.45 * exactness + 0.25 * compression + 0.15 * delta_convergence + 0.15 * evidence)).clamp(0.0, 1.0);
                (known, exactness, residual, readiness)
            }
            Tab::Media => {
                let known = (0.20 * trust + 0.20 * compression + 0.20 * exactness + 0.20 * coherence + 0.20 * evidence).clamp(0.0, 1.0);
                let readiness = (0.25 * exactness + 0.20 * coherence + 0.20 * trust + 0.20 * compression + 0.15 * reproducibility).clamp(0.0, 1.0);
                let residual = (1.0 - (0.40 * compression + 0.25 * exactness + 0.20 * coherence + 0.15 * evidence)).clamp(0.0, 1.0);
                (known, exactness, residual, readiness)
            }
            Tab::Research => {
                let known = (0.22 * trust + 0.18 * noether + 0.18 * exactness + 0.18 * evidence + 0.14 * coherence + 0.10 * compression).clamp(0.0, 1.0);
                let readiness = (0.30 * reproducibility + 0.25 * exactness + 0.20 * trust + 0.15 * noether + 0.10 * evidence).clamp(0.0, 1.0);
                let residual = (1.0 - (0.38 * exactness + 0.18 * noether + 0.17 * trust + 0.15 * evidence + 0.12 * compression)).clamp(0.0, 1.0);
                (known, exactness, residual, readiness)
            }
            _ => (0.0, 0.0, 1.0, 0.0),
        }
    }

    fn world_stage(&self, world: Tab, readiness: f32, exactness: f32) -> (&'static [&'static str], usize) {
        let labels: &'static [&'static str] = match world {
            Tab::Gaming => &["Observe", "Simulate", "Verify", "Local", "Stable"],
            Tab::Media => &["Observe", "Learn", "Repack", "Validate", "Release"],
            Tab::Research => &["Observe", "Compare", "Explain", "Reproduce", "Consolidate"],
            _ => &["Observe", "Learn", "Verify", "Use", "Scale"],
        };
        let maturity = (0.60 * readiness + 0.40 * exactness).clamp(0.0, 1.0);
        let index = if maturity < 0.18 {
            0
        } else if maturity < 0.38 {
            1
        } else if maturity < 0.58 {
            2
        } else if maturity < 0.80 {
            3
        } else {
            4
        };
        (labels, index)
    }

    fn view_gaming_world(&self) -> Element<'_, Message> {
        self.view_world_space(Tab::Gaming)
    }

    fn view_media_world(&self) -> Element<'_, Message> {
        self.view_world_space(Tab::Media)
    }

    fn view_research_world(&self) -> Element<'_, Message> {
        self.view_world_space(Tab::Research)
    }

    fn view_world_space(&self, world: Tab) -> Element<'_, Message> {
        let (title, intro, learning_policy, next_data_hint, actions, accent) = match world {
            Tab::Gaming => (
                "Gaming",
                "Gaming bleibt als Welt erhalten, ohne die bestehenden Analyse-Tabs zu ersetzen: diese Ansicht ordnet nur zusammen, wie viel interaktive Struktur Aether bereits kennt, exakt rekonstruieren kann und spaeter konservativ freigeben darf. Push von Invarianten und Shared Insights folgt dabei derselben Regel wie in den anderen Bereichen: erst bei Quorum von mindestens 3 unterschiedlichen Spielern pro Titel.",
                "Live bleibt spaeter konservativ, Lernen bleibt aggressiv im Hintergrund. Neue Sessions sollen Main Vault und Subvault sofort rueckpruefen, ohne den Runtime-Pfad aufzublaehen.",
                "Mehrwert jetzt: wiederholte Sessions, gleiche Szenen, stabile Renderpfade, Launcher-Starts und weitere Byte-/Frame-Beobachtung heben die konservative Reife am staerksten.",
                vec![
                    ("Launcher", Tab::Launcher),
                    ("Files", Tab::Data),
                    ("FlowSphere", Tab::FlowSphere),
                    ("Delta Conv", Tab::StructureMap),
                ],
                Color::from_rgb8(0x5A, 0x8C, 0xE8),
            ),
            Tab::Media => (
                "Media",
                "Media bekommt eine eigene Welt statt in den vorhandenen Tabs zu verschwinden: Sequenzen, Audio und Bewegtbild duerfen offline deutlich aggressiver repacken, solange exakte Rekonstruktion und sauberer Fallback erhalten bleiben.",
                "Mit jeder neuen Medienanalyse sollte der Bestand sofort auf repackbare Sequenzen, Frames und Segmentfamilien geprueft werden. Ziel ist wachsender Exact-Coverage-Anteil bei schrumpfendem Residual.",
                "Mehrwert jetzt: weitere Sequenzen, Wiederholungen, Audio-/Videoausschnitte und Drop-Analysen vergroessern die repackbare Flaeche und verbessern die globale Medienbibliothek.",
                vec![
                    ("Files", Tab::Data),
                    ("FlowSphere", Tab::FlowSphere),
                    ("Delta Conv", Tab::StructureMap),
                ],
                Color::from_rgb8(0xC7, 0xA0, 0x4A),
            ),
            Tab::Research => (
                "Research",
                "Research ist die dritte Welt neben Gaming und Media: fuer Arzt-, Klima-, Finanz- und andere Forschungsdaten zaehlen Rueckverfolgbarkeit, Reproduzierbarkeit und rueckwirkende Nachverdichtung alter Bestaende mit neuem Wissen.",
                "Neue Analysen sollen alte Messreihen, Datensaetze und Archive sofort gegen Main Vault, Subvault und neue Strukturhinweise rueckpruefen, ohne dass bestehende Analysepfade entfernt werden muessen.",
                "Mehrwert jetzt: wiederholte Messreihen, Vergleichsstaende, strukturierte Archive und weitere Artefakte heben Coverage, Provenienztreue und reproduzierbare Rueckwirkung.",
                vec![
                    ("Files", Tab::Data),
                    ("Anchors", Tab::Anchors),
                    ("Delta", Tab::ADE),
                    ("Delta Conv", Tab::StructureMap),
                ],
                Color::from_rgb8(0x4C, 0xD9, 0x6E),
            ),
            _ => unreachable!(),
        };

        let (knowledge, exactness, residual, readiness) = self.world_scores(world);
        let (stage_labels, current_stage_idx) = self.world_stage(world, readiness, exactness);
        let current_stage = stage_labels[current_stage_idx];
        let stage_line = stage_labels.join(" -> ");
        let capsule = self.capsule_state.as_ref();
        let structure = self.structure_map_state.as_ref();
        let aelab = self.aelab_state.as_ref();
        let compression = self.compression_state.as_ref();
        let reconstruction = self.reconstruction_state.as_ref();
        let entries = self.entries();
        let evidence_note = format!(
            "Artefakte {} | Trust {:.2} | Noether {:.2} | Delta-Konvergenz {:.2} | Lossless {:.2} | Gain {:.2}% | Vault {}",
            entries.len(),
            capsule.map(|state| state.trust_score).unwrap_or(0.0),
            capsule.map(|state| state.noether_consistency).unwrap_or(0.0),
            capsule.map(|state| (1.0 - state.delta_ratio).clamp(0.0, 1.0)).unwrap_or(0.0),
            aelab.map(|state| state.lossless).unwrap_or(0.0),
            compression.map(|state| state.gain_percent).unwrap_or(0.0),
            aelab.map(|state| state.vault_total_entries).unwrap_or(0),
        );
        let next_step = match world {
            Tab::Gaming if readiness < 0.35 => "Noch im Beobachtungsraum: weitere wiederholte Sessions und gleiche Szenen sind noetig, bevor konservative Freigabe sinnvoll wird.",
            Tab::Gaming if exactness < 0.55 => "Bekannte Muster wachsen, aber exakte Rekonstruktionsabdeckung ist noch zu niedrig. Weitere Byte-/Render-Wiederholungen waeren der staerkste Hebel.",
            Tab::Media if residual > 0.45 => "Residual ist noch dominant. Mehr Wiederholung im Material und mehr repackbare Teilsequenzen vergroessern den exakten Medienraum am schnellsten.",
            Tab::Media => "Medienwissen ist schon verwertbar. Jetzt zahlt vor allem weitere Sequenzvielfalt, damit alte Residuals im Hintergrund rueckwirkend schrumpfen.",
            Tab::Research if readiness < 0.40 => "Forschungswissen ist noch eher beobachtend. Zusätzliche Vergleichsstaende, Wiederholmessungen und saubere Provenienz liefern hier den groessten Mehrwert.",
            Tab::Research => "Rueckwirkende Verdichtung wird sinnvoller: neue Messreihen und Vergleichsgruppen helfen jetzt am meisten, um alten Bestand strukturierter zu erklaeren.",
            _ => next_data_hint,
        };

        let action_row = actions.into_iter().fold(Row::new().spacing(10), |row, (label, tab)| {
            row.push(
                button(text(label).size(12).color(c(TEXT_H())))
                    .on_press(Message::TabSelected(tab))
                    .padding([8, 12])
                    .style(primary_button_style),
            )
        });

        let metrics = Row::new()
            .spacing(10)
            .push(world_metric_card("Known", knowledge, "Wie viel Struktur Aether lokal bereits wiedererkennt.", accent))
            .push(world_metric_card("Exact", exactness, "Beweisbar exakter Ersatz statt blosses Heuristik-Wissen.", accent))
            .push(world_metric_card("Residual", 1.0 - residual, "Je hoeher, desto mehr Restdaten schon aus gelerntem Wissen ersetzbar.", accent))
            .push(world_metric_card("Readiness", readiness, "Freigabe- bzw. Einsatzreife fuer diese Welt.", accent));

        let analysis_hint = format!("Aktuelle Weltstufe: {} | Leiter: {}", current_stage, stage_line);
        let analysis_detail = format!("{}\n{}\n{}", learning_policy, evidence_note, next_step);

        let mut content = Column::new()
            .spacing(12)
            .push(text(title).size(24).color(c(TEXT_H())))
            .push(text(intro).size(15).color(c(TEXT_M())))
            .push(analysis_card(self.analysis_progress.max(readiness), &self.analysis_status, &analysis_hint, &analysis_detail))
            .push(metrics)
            .push(if world == Tab::Gaming {
                gaming_progress_table(&self.gaming_progress_rows)
            } else {
                info_card(
                    "Progress Ledger",
                    "Diese Welt nutzt den globalen Strukturfortschritt ohne ein separates Spiel-Quorum.",
                )
            })
            .push(info_card(
                "Drag and Drop Intake",
                match world {
                    Tab::Gaming => "Droppe ein Spiel oder einen Spielpfad direkt in dieses Fenster. Aether startet den Artefaktpfad, aktiviert Live Render und stoesst gleichzeitig Byte-, Struktur-, Delta- und Rekonstruktionsanalyse an.",
                    Tab::Media => "Droppe Medienartefakte direkt in dieses Fenster. Aether oeffnet den Pfad mit dem System, aktiviert Live Render und startet parallel die bestehende Datei-, Struktur- und Kompressionsanalyse.",
                    Tab::Research => "Research bleibt intake-neutral: Drops fuehren weiter in die normale Analyse. Bestehende Dateien, Datasets und Messreihen koennen danach rueckwirkend ueber den Konvergenzpfad nachverdichtet werden.",
                    _ => "Droppe Artefakte fuer die Analyse in dieses Fenster.",
                },
            ))
            .push(
                Row::new()
                    .spacing(10)
                    .push(info_card("Current Policy", learning_policy))
                    .push(info_card("Next Best Input", next_data_hint))
            )
            .push(
                Row::new()
                    .spacing(10)
                    .push(info_card("Current Stage", &format!("{}\n{}", current_stage, stage_line)))
                    .push(info_card("Current Signals", &evidence_note))
            )
            .push(
                Row::new()
                    .spacing(10)
                    .push(info_card(
                        "Retroactive Convergence",
                        &format!(
                            "Neue Analysen sollen den Bestand sofort rueckpruefen. Main Vault, Subvault, Residuals und exakte Rekonstruktionspfade bleiben verbunden, ohne die vorhandenen Analyse-Tabs zu ersetzen.\n\nStructure nodes: {} | Anchors: {} | Rebuild verified: {}",
                            structure.map(|state| state.node_count).unwrap_or(0),
                            structure.map(|state| state.anchor_count).unwrap_or(0),
                            reconstruction.map(|state| state.verified).unwrap_or(false),
                        ),
                    ))
                    .push(info_card(
                        "Integration With Existing Tabs",
                        "Diese Welt ist nur eine geordnete Sicht auf bereits vorhandene Pfade. Files bleibt Intake, FlowSphere bleibt Musterbild, Delta Convergence bleibt Kompressionspfad, Symbiont und ADE bleiben Analysequellen.",
                    ))
            )
            .push(container(action_row).padding(12).style(panel_frame_style));

        if let Some(last) = &self.last_analysis {
            content = content.push(info_card(
                "Latest Local Artifact",
                &format!(
                    "{}\nSize: {} B\nPreview: {}\nAnchors: {}\nProcess: {}",
                    last.file_name,
                    last.original_size,
                    last.preview_note,
                    last.anchor_summary,
                    last.process_summary,
                ),
            ));
        }

        if let Some(comp) = compression {
            content = content.push(info_card(
                "Compression Path",
                &format!(
                    "Format {} | Original {} B | Compressed {} B | Changed {} B | Gain {:.2}% | Ratio {:.4}",
                    comp.format,
                    comp.original_bytes,
                    comp.compressed_bytes,
                    comp.changed_bytes,
                    comp.gain_percent,
                    comp.ratio,
                ),
            ));
        }

        container(scrollable(content).height(Length::Fill))
            .padding(12)
            .into()
    }

    fn view_private_chat(&self) -> Element<'_, Message> {
        let accent  = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let teal    = Color::from_rgb8(0x3F, 0xBA, 0xC2);
        let green   = Color::from_rgb8(0x4C, 0xD9, 0x6E);
        let dim     = Color::from_rgb8(0x50, 0x6A, 0x7A);
        let mid     = Color::from_rgb8(0xA8, 0xC4, 0xD8);
        let panel_s = Color::from_rgb8(0x05, 0x10, 0x1C);

        let selected_partner = self.active_private_partner();
        let blocked_users = self.blocked_usernames();
        let is_blocked = self.active_private_blocked();

        // ── Erklärungsbereich: Was ist strukturelle Analyse im Chat? ─────────
        let info_panel: Element<'_, Message> = container(
            column![
                text("\u{25c6} PRIVATER ANALYSE-CHAT").size(15).color(accent),
                text("Normale Kommunikation: Ende-zu-Ende verschl\u{fc}sselt. Kein Inhalt wird gelesen, gespeichert oder ausgewertet \u{2014} auch nicht lokal.").size(12).color(mid),
                text("\u{25aa} \u{c4}rztliches Geheimnis bleibt gewahrt: Es werden keine Patientendaten, Diagnosen, Befunde oder Namen \u{fc}bertragen \u{2014} nur strukturelle Fingerabdr\u{fc}cke die lokal aus den Rohdaten berechnet werden. Kein R\u{fc}ckschluss auf Individuen m\u{f6}glich.").size(12).color(mid),
                text("Strukturelle Analyse (optional, lokal): Datei in den Thread ziehen \u{2192} Muster entstehen. Diese Muster \u{2014} keine Inhalte \u{2014} k\u{f6}nnen mit dem Chatpartner verglichen werden um Zusammenh\u{e4}nge zu erkunden die kein einzelnes Institut allein sehen w\u{fc}rde.").size(12).color(mid),
                text("Was bestimmte Metriken in der Praxis bedeuten k\u{f6}nnten:").size(12).color(teal),
                row![
                    column![
                        text("\u{25aa} Noether-Break").size(11).color(teal),
                        text("Symmetriebruch in Zeitreihen. In Blutwertreihen: pl\u{f6}tzliche Asymmetrie k\u{f6}nnte auf biologischen Kaskadenstart hindeuten der im Einzellabor im Rauschen untergeht. Gleichzeitig \u{fc}ber mehrere Kliniken: m\u{f6}glicherweise gemeinsamer Ausl\u{f6}ser oder neuer Erreger.").size(10).color(dim),
                    ].spacing(2).width(Length::FillPortion(1)),
                    column![
                        text("\u{25aa} Benford-Drift").size(11).color(teal),
                        text("Ziffernverteilung weicht ab. In Blutbilddaten: bekannter Fr\u{fc}hindikator f\u{fc}r biologische stochastische Ver\u{e4}nderungen. In Genomvarianten-Z\u{e4}hlungen: m\u{f6}gliche Selektionsdrucksignatur. In Wasserproben-Messreihen: strukturelle Anomalie.").size(10).color(dim),
                    ].spacing(2).width(Length::FillPortion(1)),
                    column![
                        text("\u{25aa} Entropy-Spike").size(11).color(teal),
                        text("Lokaler Entropiesprung. In EEG-Daten: Strukturst\u{f6}rung in normalerweise periodischen Signalen. In Genomsequenzen: lokale H\u{e4}ufung ungew\u{f6}hnlicher Varianten in einer Region. In chemischen Messreihen: Anomalie des Signals.").size(10).color(dim),
                    ].spacing(2).width(Length::FillPortion(1)),
                ].spacing(10),
                row![
                    column![
                        text("\u{25aa} Noether-K (Zeitkoh\u{e4}renz)").size(11).color(teal),
                        text("Strukturelle Stabilit\u{e4}t \u{fc}ber Zeit. F\u{e4}llt in Blutwertreihen ab \u{2192} etwas hat sich in der zugrundeliegenden Biologie ver\u{e4}ndert. Gleichzeitiger Abfall \u{fc}ber mehrere Standorte: geteilter externer Faktor denkbar.").size(10).color(dim),
                    ].spacing(2).width(Length::FillPortion(1)),
                    column![
                        text("\u{25aa} Delta-Konvergenz").size(11).color(teal),
                        text("Genomsequenzen verschiedener Patienten oder Quellen: wenn Delta-Muster zeitlich konvergieren \u{2192} k\u{f6}nnte auf gemeinsamen evolutionären Druck oder gemeinsamen Ursprung hinweisen. Dom\u{e4}nen\u{fc}bergreifend mit Bodenproben oder Lebensmitteldaten kombinierbar.").size(10).color(dim),
                    ].spacing(2).width(Length::FillPortion(1)),
                    column![
                        text("\u{25aa} Fourier-Periodiziät").size(11).color(teal),
                        text("Unerwartete periodische Strukturen in EEG: Intensit\u{e4}tsverlust in normalerweise regelm\u{e4}\u{df}igen Mustern. In Blutwerten: rhythmische St\u{f6}rung die vorher nicht da war. Signaltr\u{e4}ger\u{fc}bergreifend interessant wenn mehrere Quellen gleichzeitig betroffen.").size(10).color(dim),
                    ].spacing(2).width(Length::FillPortion(1)),
                ].spacing(10),
                text("Signaltr\u{e4}ger die verglichen werden k\u{f6}nnen (metrikbasiert, ohne Inhalt): Blutbild \u{b7} EEG \u{b7} Genomsequenzen \u{b7} Wasserproben \u{b7} Bodenproben \u{b7} Lebensmittel- / D\u{fc}ngemittelproben \u{b7} wirtschaftliche Zeitreihen \u{b7} Sensordaten \u{2014} die Liste ist theoretisch unbegrenzt.").size(11).color(dim),
                text("Was diese Muster bedeuten liegt beim Nutzer mit dem Dom\u{e4}nenwissen. Aether zeigt nur ob strukturelle Aufälligkeiten vorhanden sind und ob sie evtl. interessant sein k\u{f6}nnten.").size(11).color(dim),
                text("Verschl\u{fc}sselung: dieselbe wie im Rest des Systems. Kein zentraler Server. Peer-to-Peer.").size(11).color(dim),
            ].spacing(8),
        )
        .padding([12, 14])
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(panel_s)),
            border: Border { color: Color::from_rgb8(0x9A, 0x67, 0xFF), width: 1.0, radius: 8.0.into() },
            ..Default::default()
        })
        .into();

        // ── Einladung per Username ────────────────────────────────────────────
        let invite_panel: Element<'_, Message> = container(
            column![
                text("Nutzer direkt einladen").size(13).color(green),
                text("Gib den Usernamen deines Gegen\u{fc}bers ein, um einen privaten Thread zu \u{f6}ffnen. Kein Inhalt flie\u{df}t ohne deine Aktion.").size(11).color(dim),
                row![
                    text_input("Username eingeben\u{2026}", &self.chat_invite_username)
                        .on_input(Message::ChatInviteUsernameChanged)
                        .padding(9)
                        .size(14),
                    button(text("Einladen").size(13))
                        .padding([9, 14])
                        .on_press(Message::ChatInviteSend)
                        .style(primary_button_style),
                ].spacing(8).align_y(Alignment::Center),
            ].spacing(8),
        )
        .padding([10, 12])
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(panel_s)),
            border: Border { color: Color::from_rgb8(0x3F, 0xBA, 0xC2), width: 1.0, radius: 6.0.into() },
            ..Default::default()
        })
        .into();

        // ── Partner-Liste ─────────────────────────────────────────────────────
        let mut partners = Column::new();
        partners = partners.push(
            text_input("Nutzer suchen", &self.chat_user_search)
                .on_input(Message::ChatUserSearchChanged)
                .padding(10)
                .size(16)
        );
        partners = partners.spacing(10);
        for username in self.other_usernames().into_iter().take(12) {
            let active = selected_partner.as_deref() == Some(username.as_str());
            partners = partners.push(
                button(text(if active {
                    format!("{username} [aktiv]")
                } else {
                    username.clone()
                }))
                .padding([8, 12])
                .on_press(Message::PrivatePartnerSelected(username))
                .style(if active { primary_button_style } else { secondary_button_style }),
            );
        }
        if !blocked_users.is_empty() {
            partners = partners.push(text("Blockiert").size(12).color(dim));
            for username in blocked_users.into_iter().take(8) {
                partners = partners.push(info_card("Blockiert", &username));
            }
        }

        // ── Konversation ──────────────────────────────────────────────────────
        let messages = self.active_private_messages();
        let conversation: Element<'_, Message> = if let Some(partner) = &selected_partner {
            let mut content = Column::new();
            content = content.push(text(format!("Privater Kanal \u{b7} {partner}")).size(18));
            content = content.push(text("Inhalt bleibt privat und verschl\u{fc}sselt. Strukturmuster k\u{f6}nnen optional separat geteilt werden.").size(12).color(dim));
            content = content.push(
                row![
                    button(text(if is_blocked { "Entblocken" } else { "Blockieren" }))
                        .padding([8, 14])
                        .on_press(if is_blocked {
                            Message::ChatUnblockSelectedUser
                        } else {
                            Message::ChatBlockSelectedUser
                        })
                        .style(if is_blocked { secondary_button_style } else { primary_button_style }),
                ]
                .spacing(8),
            );
            content = content.spacing(10);
            if messages.is_empty() {
                content = content.push(info_card(
                    "Leerer Thread",
                    "Noch keine lokalen Nachrichten. Schreibe direkt oder ziehe eine Datei in das Fenster um strukturelle Muster zu erzeugen.",
                ));
            } else {
                for message in messages.iter().take(32) {
                    content = content.push(info_card(&message.author, &message.body));
                }
            }
            if is_blocked {
                content = content.push(info_card(
                    "Kontakt blockiert",
                    "Direkte Nachrichten und Strukturvergleiche sind blockiert, bis der Kontakt wieder entblockt wird.",
                ));
            } else {
                content = content.push(
                    text_input("Nachricht verfassen", &self.private_message_draft)
                        .on_input(Message::PrivateMessageChanged)
                        .padding(10)
                        .size(16),
                );
                content = content.push(
                    button(text("Senden"))
                        .padding([10, 16])
                        .on_press(Message::PrivateMessageSend)
                        .style(primary_button_style),
                );
            }
            container(scrollable(content).height(Length::Fill))
                .padding(16)
                .style(panel_frame_style)
                .into()
        } else {
            container(
                column![
                    info_panel,
                    invite_panel,
                ].spacing(10),
            ).into()
        };

        let mut row = Row::new();
        row = row.push(
            container(
                column![
                    scrollable(partners).height(Length::Fill),
                ].spacing(8),
            )
            .padding(16)
            .style(panel_frame_style)
            .width(Length::FillPortion(1)),
        );
        row = row.push(
            container(conversation).style(panel_frame_style).width(Length::FillPortion(2)),
        );
        row = row.spacing(14);
        container(row)
            .height(Length::Fill)
            .into()

    }

    fn view_group_chat(&self) -> Element<'_, Message> {
        let accent  = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let teal    = Color::from_rgb8(0x3F, 0xBA, 0xC2);
        let green   = Color::from_rgb8(0x4C, 0xD9, 0x6E);
        let warn    = Color::from_rgb8(0xD4, 0xA0, 0x42);
        let mid     = Color::from_rgb8(0xA8, 0xC4, 0xD8);
        let dim     = Color::from_rgb8(0x70, 0x90, 0xA8);
        let panel_s = Color::from_rgb8(0x05, 0x10, 0x1C);

        let rooms = self.group_rooms();
        let selected_room = self.active_group_room();
        let active_messages = self.active_group_messages();
        let is_owner = self.active_group_is_owner();
        let mut content = Column::new().spacing(12);

        // ── Erklärungspanel: Strukturelle Kollaboration ──────────────────────
        content = content.push(
            container(
                column![
                    text("\u{25c6} GRUPPEN \u{b7} STRUKTURELLES ANALYSE-NETZWERK").size(15).color(accent),
                    text("Gruppen-Chats sind Ende-zu-Ende verschl\u{fc}sselt. Kein Inhalt wird zentral gespeichert. \u{c4}rztliches Geheimnis und Datenschutz bleiben gewahrt: ausgetauscht werden ausschlie\u{df}lich strukturelle Fingerabdr\u{fc}cke ohne jeden Inhalt oder Personenbezug.").size(12).color(mid),
                    text("Bez\u{fc}glich Ärztesgeheimnis: strukturelle Muster sind keine Diagnosen. Es werden keine Patientendaten, Befunde oder Identit\u{e4}ten \u{fc}bertragen — nur ob bestimmte Strukturmerkmale in der Datenbasis vorhanden sind. Vergleichbar damit, ob zwei R\u{f6}ntgenbilder gleich viele Knochen zeigen, ohne dass man wei\u{df} wem sie geh\u{f6}ren.").size(12).color(mid),
                    text("Strukturelle Kollaboration \u{2014} was heute sonst nicht m\u{f6}glich w\u{e4}re:").size(12).color(teal),
                    text("\u{25aa} Mehrere unabh\u{e4}ngige Gruppen analysieren Datens\u{e4}tze in ihrer Dom\u{e4}ne. Wenn strukturell \u{e4}hnliche Muster auftauchen gibt Aether ein Signal ohne den Inhalt zu kennen.").size(11).color(dim),
                    text("\u{25aa} Besonders wo der Zeitfaktor erst den Zusammenhang sichtbar macht: Ein Muster das einzeln harmlos wirkt wird erst durch seinen zeitlichen Kontext relevant \u{2014} wenn es an mehreren Stellen gleichzeitig oder kurz nacheinander auftritt.").size(11).color(dim),
                    text("Beispiele f\u{fc}r strukturelle Signale im Gruppen-Kontext:").size(12).color(teal),
                    row![
                        column![
                            text("Pandemie-Fr\u{fc}herkennung").size(11).color(green),
                            text("Noether-Breaks in Aufnahme-Zeitreihen mehrerer Kliniken zur gleichen Zeit \u{2014} kein Befund, kein Name, nur ob Strukturmuster von der Baseline abweichen. Einzeln rauscht es durch, zusammen wird es sichtbar.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                        column![
                            text("Wasser + Patienten + Genomdaten").size(11).color(green),
                            text("Benford-Drift in kommunalen Wasserproben + zeitlich korrelierter Entropie-Spike in Blutwerten aus derselben Region + ungewöhnliche Delta-Konvergenz in Genomsequenzen \u{2014} diese Kombination ist ohne Datenaustausch pr\u{fc}fbar.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                        column![
                            text("Wirtschaft + Gesundheitsdaten").size(11).color(green),
                            text("Noether-K-Abfall in wirtschaftlichen Transaktionszeitreihen + gleichzeitiger Noether-Break in Klinikaufnahmedaten \u{2014} strukturelle Korrelation die auf Stresskaske vor offiziell erkanntem Ausbruch hindeuten k\u{f6}nnte.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                    ].spacing(10),
                    row![
                        column![
                            text("Boden / Lebensmittel / D\u{fc}nger").size(11).color(green),
                            text("Delta-Konvergenz \u{fc}ber Boden-, Lebensmittel- und D\u{fc}ngemittelproben + Genomsequenz-Drift in lokaler Pflanzenpopulation \u{2014} struktureller Zusammenhang erkennbar ohne die Proben selbst zu teilen.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                        column![
                            text("EEG + Blutbild + Umweltdaten").size(11).color(green),
                            text("Fourier-Periodizit\u{e4}tsverlust in EEG-Messreihen mehrerer Patienten + Benford-Drift in ihren Laborwerten zur gleichen Zeit + Entropy-Spike in regionalen Umweltmessungen: Signaltr\u{e4}ger\u{fc}bergreifendes Muster.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                        column![
                            text("Wissenschaftl. Reproduzierbarkeit").size(11).color(green),
                            text("Mehrere Labore vergleichen ob ihre Replikate strukturell \u{e4}quivalent sind \u{2014} Delta-Vergleich ohne Datenaustausch. Gleichzeitiger Noether-Break in allen Replikaten zeigt: die Messbedingung hat sich ver\u{e4}ndert.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                    ].spacing(10),
                    text("Signaltr\u{e4}ger die strukturell verglichen werden k\u{f6}nnen: Blutbild \u{b7} EEG \u{b7} Genomsequenzen \u{b7} Wasserproben \u{b7} Bodenproben \u{b7} Lebensmittel-/D\u{fc}ngemittelanalysen \u{b7} wirtschaftliche Zeitreihen \u{b7} Sensordaten \u{b7} Klimamessreihen \u{2014} die Liste ist theoretisch unbegrenzt.").size(11).color(dim),
                    text("Diese Muster und Zusammenh\u{e4}nge k\u{f6}nnten interessant sein \u{2014} besonders wenn \u{e4}hnliche Strukturen zur gleichen Zeit oder in kurzer Folge an verschiedenen Stellen auftreten. Was sie bedeuten liegt beim Nutzer mit dem Dom\u{e4}nenwissen.").size(11).color(dim),
                ].spacing(7),
            )
            .padding([12, 14])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(panel_s)),
                border: Border { color: accent, width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
        );

        // ── Broadcast-Anfrage ────────────────────────────────────────────────
        content = content.push(
            container(
                column![
                    text("Broadcast-Anfrage \u{b7} strukturelle Suche").size(13).color(teal),
                    text("Schicke eine anonymisierte Broadcast-Anfrage an Swarm-Teilnehmer mit \u{e4}hnlichen Anker-Dom\u{e4}nen. Kein Inhalt wird \u{fc}bertragen \u{2014} nur das Signal ob strukturelle \u{dc}berschneidungen vorliegen.").size(11).color(dim),
                    text("Die Anfrage erscheint bei anderen als best\u{e4}tigungspflichtige Einladung. Erst nach gegenseitiger Zustimmung wird ein Kanal ge\u{f6}ffnet.").size(11).color(dim),
                    row![
                        text_input("Dom\u{e4}nen-Hinweis f\u{fc}r Broadcast (z.B. \u{201e}Zeitreihe/Klimatik\u{201c})\u{2026}", &self.chat_broadcast_draft)
                            .on_input(Message::ChatBroadcastDraftChanged)
                            .padding(9)
                            .size(13),
                        button(text("Broadcast senden").size(12))
                            .padding([9, 14])
                            .on_press(Message::ChatBroadcastSend)
                            .style(primary_button_style),
                    ].spacing(8).align_y(Alignment::Center),
                ].spacing(8),
            )
            .padding([10, 12])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(panel_s)),
                border: Border { color: teal, width: 1.0, radius: 6.0.into() },
                ..Default::default()
            })
        );

        // ── Eingehende Broadcast-Anfragen ────────────────────────────────────
        if !self.chat_broadcast_requests.is_empty() {
            content = content.push(text("Eingehende Broadcast-Anfragen").size(13).color(warn));
            for req in &self.chat_broadcast_requests {
                let node = req.node_id.clone();
                let node2 = req.node_id.clone();
                content = content.push(
                    container(
                        column![
                            text(format!("Node: {} \u{b7} Dom\u{e4}ne: {} \u{b7} {}", &req.node_id.chars().take(12).collect::<String>(), req.domain_tag, req.epoch_week)).size(12).color(mid),
                            text(format!("Signal: {}", req.pattern_hint)).size(11).color(dim),
                            row![
                                button(text("Annehmen \u{2192} Privaten Thread").size(12))
                                    .padding([7,12])
                                    .on_press(Message::ChatBroadcastAccept(node))
                                    .style(primary_button_style),
                                button(text("Ablehnen").size(12))
                                    .padding([7,12])
                                    .on_press(Message::ChatBroadcastDecline(node2))
                                    .style(secondary_button_style),
                            ].spacing(8),
                        ].spacing(6),
                    )
                    .padding([8, 10])
                    .style(move |_: &Theme| container::Style {
                        background: Some(Background::Color(panel_s)),
                        border: Border { color: warn, width: 1.0, radius: 5.0.into() },
                        ..Default::default()
                    })
                );
            }
        }

        // ── Gruppen-Räume ────────────────────────────────────────────────────
        content = content.push(text("Gruppengespräche").size(16).color(mid));
        content = content.push(
            container(
                column![
                    text("Neue Gruppe anlegen").size(13).color(green),
                    row![
                        text_input("Gruppenname", &self.chat_group_name)
                            .on_input(Message::ChatGroupNameChanged)
                            .padding(9)
                            .size(14),
                        button(text("Anlegen").size(13))
                            .padding([9, 14])
                            .on_press(Message::ChatGroupCreate)
                            .style(primary_button_style),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                ]
                .spacing(8),
            )
            .padding([10, 12])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(panel_s)),
                border: Border { color: green, width: 1.0, radius: 6.0.into() },
                ..Default::default()
            })
        );
        if rooms.is_empty() {
            content = content.push(info_card(
                "Keine Gruppenräume",
                "Lege eine Gruppe an, damit Mitglieder aufgenommen werden und strukturierte Vergleiche im Gruppenkontext landen können.",
            ));
        } else {
            let mut room_picker = Column::new().spacing(8);
            for room in rooms.iter().take(12) {
                let active = selected_room
                    .as_ref()
                    .map(|selected| selected.id == room.id)
                    .unwrap_or(false);
                let label = format!(
                    "{} · {} Mitglieder · {} Nachrichten",
                    room.name,
                    room.members.len(),
                    room.messages.len()
                );
                room_picker = room_picker.push(
                    button(text(label))
                        .padding([8, 12])
                        .on_press(Message::GroupRoomSelected(room.id.clone()))
                        .style(if active { primary_button_style } else { secondary_button_style }),
                );
            }
            content = content.push(room_picker);
        }

        if let Some(room) = selected_room {
            let owner_label = format!("Ersteller: {}", room.owner_username);
            let member_list = room.members.join(", ");
            let mut room_panel = Column::new()
                .spacing(10)
                .push(text(format!("Aktive Gruppe · {}", room.name)).size(18))
                .push(text(owner_label).size(12).color(dim))
                .push(text(format!("Mitglieder: {}", member_list)).size(12).color(mid));

            if is_owner {
                room_panel = room_panel.push(
                    row![
                        text_input("Mitglied per Username hinzufuegen", &self.group_member_username)
                            .on_input(Message::GroupMemberUsernameChanged)
                            .padding(9)
                            .size(14),
                        button(text("Hinzufuegen").size(12))
                            .padding([8, 12])
                            .on_press(Message::GroupAddMember)
                            .style(primary_button_style),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                );
            }

            if active_messages.is_empty() {
                room_panel = room_panel.push(info_card(
                    "Noch kein Gruppenverlauf",
                    "Schreibe direkt in den Raum oder ziehe eine Datei im Chatfenster ab, um einen strukturellen Vergleich in diese Gruppe zu legen.",
                ));
            } else {
                for message in active_messages.iter().take(40) {
                    room_panel = room_panel.push(info_card(&message.author, &message.body));
                }
            }

            if is_owner {
                for member in room.members.iter().filter(|member| member.as_str() != room.owner_username) {
                    room_panel = room_panel.push(
                        row![
                            text(format!("Mitglied: {}", member)).size(12).color(mid),
                            button(text("Entfernen").size(11))
                                .padding([6, 10])
                                .on_press(Message::GroupRemoveMember(member.clone()))
                                .style(secondary_button_style),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                    );
                }
            }

            room_panel = room_panel.push(
                text_input(
                    &format!("Nachricht an {}", room.name),
                    &self.group_message_draft,
                )
                .on_input(Message::GroupMessageChanged)
                .padding(10)
                .size(16),
            );
            room_panel = room_panel.push(
                row![
                    button(text("Senden"))
                        .padding([10, 16])
                        .on_press(Message::GroupMessageSend)
                        .style(primary_button_style),
                    button(text("Gruppe verlassen"))
                        .padding([10, 16])
                        .on_press(Message::GroupLeaveSelected)
                        .style(secondary_button_style),
                ]
                .spacing(10),
            );
            content = content.push(
                container(room_panel)
                    .padding(12)
                    .style(panel_frame_style),
            );
        }

        container(scrollable(content).height(Length::Fill))
            .padding(12)
            .style(panel_frame_style)
            .into()
    }

    fn view_swarm_requests(&self) -> Element<'_, Message> {
        let mut col = Column::new().spacing(12);
        col = col.push(text("Swarm · Domänen-Anfragen").size(20));
        col = col.push(
            text("Andere Nodes haben strukturelle Überschneidungen in deinen Anker-Domänen gefunden und bitten um anonymen Kontakt. Du entscheidest, ob du antwortest.")
                .size(14),
        );
        if self.swarm_overlap_requests.is_empty() {
            col = col.push(info_card(
                "Keine offenen Anfragen",
                "Sobald ein anderer Node strukturelle Überschneidungen mit deinen Domänen-Tags erkennt, erscheint hier eine Kontaktanfrage.",
            ));
        } else {
            for req in &self.swarm_overlap_requests {
                let score_pct = (req.structural_score * 100.0).round() as u32;
                let short_pubkey: String = req.remote_node_pubkey.chars().take(16).collect();
                let card: Element<'_, Message> = container(
                    Column::new()
                        .push(
                            text(format!(
                                "Domäne: {}  ·  Ähnlichkeit: {}%  ·  {}",
                                req.domain_tag, score_pct, req.epoch_week
                            ))
                            .size(15),
                        )
                        .push(
                            text(format!(
                                "Lokaler Anker: {}  ·  Node: {}…",
                                req.anchor_hash_a, short_pubkey
                            ))
                            .size(13),
                        )
                        .push(
                            Row::new()
                                .push(
                                    button(text("Annehmen – privaten Chat öffnen"))
                                        .padding([8, 14])
                                        .on_press(Message::SwarmOverlapAccepted(
                                            req.anchor_hash_a.clone(),
                                        ))
                                        .style(primary_button_style),
                                )
                                .push(
                                    button(text("Ablehnen"))
                                        .padding([8, 14])
                                        .on_press(Message::SwarmOverlapDeclined(
                                            req.anchor_hash_a.clone(),
                                        ))
                                        .style(secondary_button_style),
                                )
                                .spacing(10),
                        )
                        .spacing(8),
                )
                .padding(12)
                .style(panel_frame_style)
                .into();
                col = col.push(card);
            }
        }
        container(scrollable(col).height(Length::Fill))
            .padding(16)
            .height(Length::Fill)
            .into()
    }

    fn view_settings(&self) -> Element<'_, Message> {
        let mode = self.security_mode();
        let profile = self.runtime_profile;
        let lang = self.ui_language;
        container(
            scrollable(
                {
                    let mut col = Column::new();
                    col = col.push(text(self.ui_text("Einstellungen", "Settings")).size(24));
                    col = col.push(text(self.ui_text("Interface-Sprache", "Interface language")).size(20));
                    col = col.push(
                        {
                            let mut row = Row::new();
                            row = row.push(
                                button(text(if lang == UiLanguage::German { "Deutsch [aktiv]" } else { "Deutsch" }))
                                    .padding([10, 16])
                                    .on_press(Message::UiLanguageSelected(UiLanguage::German))
                                    .style(if lang == UiLanguage::German { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(
                                button(text(if lang == UiLanguage::English { "English [active]" } else { "English" }))
                                    .padding([10, 16])
                                    .on_press(Message::UiLanguageSelected(UiLanguage::English))
                                    .style(if lang == UiLanguage::English { primary_button_style } else { secondary_button_style })
                            );
                            row.spacing(8)
                        }
                    );
                    // ── Telemetrie-Shield ─────────────────────────────────────────────
                    col = col.push(text(self.ui_text("Telemetrie-Shield", "Telemetry Shield")).size(20));
                    col = col.push(text(self.ui_text(
                        "Erkennt Windows-Telemetrieprozesse mit aktiven Verbindungen und blockiert diese per Firewall-Regel (Adminrechte erforderlich).",
                        "Detects Windows telemetry processes with active connections and blocks them via firewall rule (admin rights required).",
                    )).size(13).color(c(TEXT_M())));
                    col = col.push(
                        {
                            let mut row = Row::new();
                            row = row.push(
                                button(text(if self.telemetry_shield_enabled {
                                    self.ui_text("\u{25a0} SHIELD AKTIV", "\u{25a0} SHIELD ACTIVE")
                                } else {
                                    self.ui_text("\u{25a1} SHIELD AKTIVIEREN", "\u{25a1} ACTIVATE SHIELD")
                                }))
                                .padding([10, 18])
                                .on_press(Message::TelemetryShieldToggle(!self.telemetry_shield_enabled))
                                .style(if self.telemetry_shield_enabled { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(info_card("OS-Layer",
                                if self.telemetry_shield_enabled {
                                    self.ui_text("Firewall: aktiv \u{b7} Sandbox: lokal", "Firewall: active \u{b7} Sandbox: local")
                                } else {
                                    self.ui_text("Firewall: aus \u{b7} Sandbox: lokal", "Firewall: off \u{b7} Sandbox: local")
                                }));
                            row.spacing(14)
                        }
                    );
                    if self.telemetry_alerts.is_empty() {
                        col = col.push(
                            text(self.ui_text(
                                "Keine aktive Telemetrie erkannt.",
                                "No active telemetry detected.",
                            )).size(12).color(c(TEXT_D()))
                        );
                    } else {
                        col = col.push(
                            text(format!(
                                "{} {}",
                                self.ui_text("\u{26a0} Telemetrie erkannt:", "\u{26a0} Telemetry detected:"),
                                self.telemetry_alerts.len(),
                            )).size(13).color(c(WARN()))
                        );
                        let alerts_col: Element<'_, Message> = {
                            let mut ac = Column::new().spacing(2);
                            for alert in self.telemetry_alerts.iter().rev().take(8) {
                                ac = ac.push(
                                    text(format!("{} \u{2502} {} \u{2192} {}",
                                        alert.timestamp, alert.process, alert.remote))
                                        .size(11)
                                        .color(c(DANGER()))
                                );
                            }
                            ac.into()
                        };
                        col = col.push(alerts_col);
                    }
                    // ── Zeitgraph-Metadaten-Zustimmung ─────────────────────────────────
                    col = col.push(text("").size(6));
                    col = col.push(text(self.ui_text(
                        "Entstehungsdatum aus Datei-Metadaten",
                        "File origin date from metadata",
                    )).size(20));
                    col = col.push(text(self.ui_text(
                        "Liest beim Analysieren das Entstehungsdatum aus Datei-Metadaten (Dateiinfo + Header-Bytes). Kein Inhalt wird gelesen. Das Ergebnis erscheint nur im Zeitgraph-Tab \u{2014} nie in der Analyse selbst oder im Swarm.",
                        "Reads the file origin date from metadata (file info + header bytes) during analysis. No content is read. The result appears only in the timeline graph tab \u{2014} never in the analysis itself or in the swarm.",
                    )).size(13).color(c(TEXT_M())));
                    col = col.push({
                        let mut row = Row::new();
                        row = row.push(
                            button(text(if self.temporal_metadata_consent {
                                self.ui_text("\u{25a0} AKTIV", "\u{25a0} ACTIVE")
                            } else {
                                self.ui_text("\u{25a1} AKTIVIEREN", "\u{25a1} ACTIVATE")
                            }))
                            .padding([10, 18])
                            .on_press(Message::TemporalMetadataConsentToggle(!self.temporal_metadata_consent))
                            .style(if self.temporal_metadata_consent { primary_button_style } else { secondary_button_style })
                        );
                        row = row.push(info_card(
                            self.ui_text("Zeitgraph", "Timeline"),
                            if self.temporal_metadata_consent {
                                self.ui_text("Metadaten-Datum: aktiv \u{b7} nur Zeitgraph", "Metadata date: active \u{b7} timeline only")
                            } else {
                                self.ui_text("Metadaten-Datum: aus \u{b7} Analysezeitpunkt", "Metadata date: off \u{b7} analysis timestamp")
                            },
                        ));
                        row.spacing(14)
                    });
                    col = col.push(text("").size(4));
                    // ── Security-Modus ──────────────────────────────────────────────────
                    col = col.push(text(self.ui_text("Security-Modus", "Security mode")).size(20));
                    col = col.push(
                        {
                            let mut row = Row::new();
                            row = row.push(
                                button(text(if mode == "local" { "LOCAL [aktiv]" } else { "LOCAL" }))
                                    .padding([10, 18])
                                    .on_press(Message::SecurityModeSelected("local".to_owned()))
                                    .style(if mode == "local" { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(
                                button(text(if mode == "dev" { "DEV [aktiv]" } else { "DEV" }))
                                    .padding([10, 18])
                                    .on_press(Message::SecurityModeSelected("dev".to_owned()))
                                    .style(if mode == "dev" { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(
                                button(text("Recheck"))
                                    .padding([10, 18])
                                    .on_press(Message::SecurityRecheck)
                                    .style(secondary_button_style)
                            );
                            row.spacing(10)
                        }
                    );
                    col = col.push(text(self.ui_text("Runtime-Profil (lokaler Takt)", "Runtime profile (local cadence)")).size(20));
                    col = col.push(text(self.ui_text(
                        "AUTO, BALANCED, LOW-POWER und LEGACY steuern nur lokalen Takt, Polling und Watchdogs. Das Netzwerk-Tier bleibt separat hardwaregebunden: Vault-first-Geraete profitieren lokal, normale PCs behalten freie Profilwahl.",
                        "AUTO, BALANCED, LOW-POWER and LEGACY only control local cadence, polling and watchdog pressure. The network tier stays separately hardware-bound: vault-first devices still benefit locally, while normal PCs keep full profile choice.",
                    )).size(14));
                    col = col.push(
                        {
                            let mut row = Row::new();
                            row = row.push(
                                button(text(if profile == RuntimeProfile::Auto { "AUTO [aktiv]" } else { "AUTO" }))
                                    .padding([10, 16])
                                    .on_press(Message::RuntimeProfileSelected(RuntimeProfile::Auto))
                                    .style(if profile == RuntimeProfile::Auto { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(
                                button(text(if profile == RuntimeProfile::Balanced { "BALANCED [aktiv]" } else { "BALANCED" }))
                                    .padding([10, 16])
                                    .on_press(Message::RuntimeProfileSelected(RuntimeProfile::Balanced))
                                    .style(if profile == RuntimeProfile::Balanced { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(
                                button(text(if profile == RuntimeProfile::LowPower { "LOW-POWER [aktiv]" } else { "LOW-POWER" }))
                                    .padding([10, 16])
                                    .on_press(Message::RuntimeProfileSelected(RuntimeProfile::LowPower))
                                    .style(if profile == RuntimeProfile::LowPower { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(
                                button(text(if profile == RuntimeProfile::Legacy { "LEGACY [aktiv]" } else { "LEGACY" }))
                                    .padding([10, 16])
                                    .on_press(Message::RuntimeProfileSelected(RuntimeProfile::Legacy))
                                    .style(if profile == RuntimeProfile::Legacy { primary_button_style } else { secondary_button_style })
                            );
                            row.spacing(8)
                        }
                    );
                    col = col.push(info_card(
                        self.ui_text("Aktive Runtime-Parameter", "Active runtime parameters"),
                        &format!(
                            "{} {}\n{} {} ms\n{} {}",
                            self.ui_text("Profil:", "Profile:"),
                            self.runtime_profile_label(),
                            self.ui_text("Tick-Intervall:", "Tick interval:"),
                            self.tick_interval_ms(),
                            self.ui_text("Netzwerk-Tier:", "Network tier:"),
                            if self.hw_network_tier.is_empty() { "ermittelt..." } else { &self.hw_network_tier },
                        ),
                    ));
                    col = col.push(text(self.ui_text("Hybrid Runtime (Rust + Python + Symbiont)", "Hybrid runtime (Rust + Python + Symbiont)")).size(20));
                    col = col.push(text(self.ui_text(
                        "Hybrid Runtime bedeutet: Die Rust-Shell (diese App) läuft immer. Python-Module laufen optional im Hintergrund und kommunizieren über den Symbiont-Link. Das Python-Backend übernimmt rechenintensive Analyse-Schritte und gibt die Ergebnisse per IPC an die Shell zurück.",
                        "Hybrid Runtime: The Rust shell (this app) always runs. Python modules run optionally in the background and communicate via the Symbiont link. The Python backend handles compute-intensive analysis steps and passes results back to the shell via IPC.",
                    )).size(13).color(Color::from_rgb8(0x70, 0x90, 0xA8)));
                    col = col.push(text(self.ui_text(
                        "Symbiont Link AUS = nur lokale Rust-Analyse (schnell, eingeschränkt). Symbiont Link AN = volle AELab- und Pipeline-Tiefe.",
                        "Symbiont Link OFF = local Rust analysis only (fast, limited). Symbiont Link ON = full AELab and pipeline depth.",
                    )).size(12).color(Color::from_rgb8(0x50, 0x6A, 0x7A)));
                    col = col.push(
                        {
                            let mut row = Row::new();
                            row = row.push(
                                button(text(if self.hybrid_symbiont_enabled { "Symbiont Link [aktiv]" } else { "Symbiont Link" }))
                                    .padding([10, 16])
                                    .on_press(Message::HybridSymbiontEnabled(true))
                                    .style(if self.hybrid_symbiont_enabled { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(
                                button(text(if !self.hybrid_symbiont_enabled { "Symbiont Link [aus]" } else { "Symbiont Link aus" }))
                                    .padding([10, 16])
                                    .on_press(Message::HybridSymbiontEnabled(false))
                                    .style(if !self.hybrid_symbiont_enabled { primary_button_style } else { secondary_button_style })
                            );
                            row.spacing(8)
                        }
                    );
                    col = col.push(text(self.ui_text(
                        "Symbiont-Verbindungsport (Socket)",
                        "Symbiont connection port (socket)",
                    )).size(16));
                    col = col.push(text(self.ui_text(
                        "Ein Socket ist eine lokale Netzwerkadresse (127.0.0.1 = dieses Ger\u{e4}t), \u{fc}ber die Rust-Shell und Python-Backend miteinander sprechen. Der Port ist die Nummer des Kan\u{e4}ls \u{2014} beide Seiten m\u{fc}ssen denselben Port verwenden. Ports unter 1024 ben\u{f6}tigen Adminrechte.",
                        "A socket is a local network address (127.0.0.1 = this device) used for communication between the Rust shell and Python backend. The port is the channel number \u{2014} both sides must use the same port. Ports below 1024 require admin rights.",
                    )).size(12).color(Color::from_rgb8(0x50, 0x6A, 0x7A)));
                    col = col.push(
                        {
                            let mut row = Row::new();
                            row = row.push(
                                button(text(if self.symbiont_port == 38571 { "Socket 38571 [aktiv]" } else { "Socket 38571" }))
                                    .padding([10, 16])
                                    .on_press(Message::HybridSymbiontEndpointPreset("127.0.0.1".to_owned(), 38571))
                                    .style(if self.symbiont_port == 38571 { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(
                                button(text(if self.symbiont_port == 39571 { "Socket 39571 [aktiv]" } else { "Socket 39571" }))
                                    .padding([10, 16])
                                    .on_press(Message::HybridSymbiontEndpointPreset("127.0.0.1".to_owned(), 39571))
                                    .style(if self.symbiont_port == 39571 { primary_button_style } else { secondary_button_style })
                            );
                            row.spacing(8)
                        }
                    );
                    col = col.push(info_card(
                        self.ui_text("Hybrid Status", "Hybrid status"),
                        &format!(
                            "Bridge: {}\nSymbiont Runtime: {}\nEndpoint: {}:{}\n{}: {}",
                            if self.hybrid_bridge_running { "online" } else { "offline" },
                            if self.hybrid_symbiont_running { "online" } else { "offline" },
                            self.symbiont_host,
                            self.symbiont_port,
                            self.ui_text("Fehler", "Error"),
                            if self.hybrid_bridge_error.trim().is_empty() { "-" } else { &self.hybrid_bridge_error }
                        ),
                    ));
                    col = col.push(text(self.ui_text(
                        "Hilfe, Begriffe, Zielbild",
                        "Help, Concepts & Mission",
                    )).size(20));

                    // --- Zielbild / Mission ---
                    col = col.push(info_card(
                        self.ui_text("Was ist Aether?", "What is Aether?"),
                        self.ui_text(
                            "Aether ist ein lokales Analyse-\u{d6}kosystem: Dateien werden strukturell analysiert, \
in kompakten AEF-Deltas gespeichert und mit unver\u{e4}lschbaren Ankern verkn\u{fc}pft. \
Ziel: transparente, reproduzierbare Sicherheitsanalyse \u{2014} vollst\u{e4}ndig offline, ohne Cloud-Zwang.",
                            "Aether is a local analysis ecosystem: files are analysed structurally, \
stored as compact AEF deltas and linked to tamper-proof anchors. \
Goal: transparent, reproducible security analysis \u{2014} fully offline, no cloud required.",
                        )
                    ));

                    // --- Konkretes Beispiel / Concrete Example ---
                    col = col.push(info_card(
                        self.ui_text("Beispiel: eine Datei pr\u{fc}fen", "Example: analysing a file"),
                        self.ui_text(
                            "Du hast eine ausf\u{fc}hrbare Datei (z.\u{a0}B. setup.exe) erhalten und wei\u{df}t nicht ob sie sicher ist.\n\
1. Datei in den Data-Tab ziehen \u{2192} Aether berechnet einen Struktur-Fingerabdruck (Delta + Residual).\n\
2. Im ADE-Tab auf Analyse starten klicken \u{2192} Obfuskationsscore und Policy-Treffer erscheinen.\n\
3. Ist der Obf-Score > 0,6 oder gibt es Block-Hits? \u{2192} Sofort in Logs wechseln, Details lesen.\n\
4. Aether speichert einen Anker: beim n\u{e4}chsten Mal erkennst du sofort ob die Datei ver\u{e4}ndert wurde \u{2014} auch ohne Netzwerk.\n\
Ergebnis: du wei\u{df}t genau was die Datei tut, ohne dass eine Kopie je das Ger\u{e4}t verl\u{e4}sst.",
                            "You have received an executable (e.g. setup.exe) and do not know if it is safe.\n\
1. Drop the file into the Data tab \u{2192} Aether computes a structural fingerprint (delta + residual).\n\
2. In the ADE tab click Start analysis \u{2192} obfuscation score and policy hits appear.\n\
3. Obf score > 0.6 or block hits? \u{2192} Switch to Logs immediately and read the details.\n\
4. Aether stores an anchor: next time you instantly know if the file was modified \u{2014} even offline.\n\
Result: you know exactly what the file does without any copy ever leaving your device.",
                        )
                    ));

                    // --- Begriffe / Concepts ---
                    col = col.push(info_card(
                        self.ui_text("Begriffe kurz erkl\u{e4}rt", "Key concepts"),
                        self.ui_text(
                            "AEF: lokales Delta-Format \u{2014} speichert Ver\u{e4}nderungen statt Rohdaten.\n\
Anker: stabiler Strukturpunkt \u{2014} beweist Unver\u{e4}ndertheit ohne die Originaldatei.\n\
Residual/Delta: der messbare Unterschied zwischen zwei Zust\u{e4}nden.\n\
Swarm: mehrere lokale Knoten teilen Invarianten \u{2014} ohne zentrale Koordination.\n\
Capability-Score: wie bereit und leistungsf\u{e4}hig das laufende System gerade ist (0-100 %).",
                            "AEF: local delta format \u{2014} stores changes instead of raw data.\n\
Anchor: stable structural checkpoint \u{2014} proves integrity without keeping the original file.\n\
Residual / Delta: the measurable difference between two states.\n\
Swarm: multiple local nodes share invariants \u{2014} without central coordination.\n\
Capability score: how ready and capable the running system currently is (0-100 %).",
                        )
                    ));

                    // --- Malware lesen / Reading threat results ---
                    col = col.push(info_card(
                        self.ui_text("Bedrohungswerte lesen", "Reading threat scores"),
                        self.ui_text(
                            "Obf-Score: h\u{f6}her = verd\u{e4}chtiger (> 0,6 = Warnung, > 0,8 = Block-Kandidat).\n\
Policy-Hits: ausgel\u{f6}ste Regeln (allow / warn / block).\n\
Cascade: kombiniert Ethics + Obf + Signatur-Treffer zu einem Gesamtwert.\n\
Bei Warnung: immer zus\u{e4}tzlich Logs und ADE pr\u{fc}fen.",
                            "Obf score: higher = more suspicious (> 0.6 = warning, > 0.8 = block candidate).\n\
Policy hits: triggered rules (allow / warn / block).\n\
Cascade: combines ethics + obf + signature hits into one overall score.\n\
On warning: always check Logs and ADE for details.",
                        )
                    ));

                    // --- Schnell-Workflow / Quick workflow ---
                    col = col.push(info_card(
                        self.ui_text("Schnell-Workflow", "Quick workflow"),
                        self.ui_text(
                            "1) Datei in Data droppen.\n\
2) Preview und Cascade-Score pr\u{fc}fen.\n\
3) Bei Warnung: ADE (Threat Analysis) und Logs \u{f6}ffnen.\n\
4) Anker best\u{e4}tigen dass die Datei unver\u{e4}ndert ist.\n\
5) Leistenmodus (oben) f\u{fc}r Schnellzugriff ohne Tab-Wechsel nutzen.",
                            "1) Drop file into Data.\n\
2) Check preview and Cascade score.\n\
3) On warning: open ADE (Threat Analysis) and Logs.\n\
4) Confirm anchor proves the file is unchanged.\n\
5) Use strip mode (top bar) for quick access without switching tabs.",
                        )
                    ));
                    // ── Dauerbetrieb / Persistent mode ────────────────────────────────
                    col = col.push(text(self.ui_text("Dauerbetrieb & Leistenmodus", "Persistent mode & overlay bar")).size(20));
                    col = col.push(text(self.ui_text(
                        "Im Dauerbetrieb wird das Fenster beim Klick auf X nicht beendet, sondern zur immer-sichtbaren Leiste (Always-on-Top) minimiert. Escape oder Klick auf die Leiste öffnet die Vollansicht wieder.",
                        "In persistent mode, clicking X does not quit — the window collapses to an always-on-top overlay bar. Pressing Escape or clicking the bar restores the full view.",
                    )).size(13).color(c(TEXT_M())));
                    col = col.push(
                        {
                            let mut row = Row::new();
                            row = row.push(
                                button(text(if self.persistent_mode {
                                    self.ui_text("\u{25a0} DAUERBETRIEB AKTIV", "\u{25a0} PERSISTENT ON")
                                } else {
                                    self.ui_text("\u{25a1} DAUERBETRIEB EIN", "\u{25a1} ENABLE PERSISTENT")
                                }))
                                .padding([10, 18])
                                .on_press(Message::PersistentModeToggle(true))
                                .style(if self.persistent_mode { primary_button_style } else { secondary_button_style })
                            );
                            row = row.push(
                                button(text(if !self.persistent_mode {
                                    self.ui_text("\u{25a0} NORMALMODUS AKTIV", "\u{25a0} NORMAL MODE ON")
                                } else {
                                    self.ui_text("\u{25a1} NORMALMODUS", "\u{25a1} NORMAL MODE")
                                }))
                                .padding([10, 18])
                                .on_press(Message::PersistentModeToggle(false))
                                .style(if !self.persistent_mode { primary_button_style } else { secondary_button_style })
                            );
                            row.spacing(8)
                        }
                    );
                    col = col.push(
                        button(text(self.ui_text("\u{26a0} Programm jetzt beenden", "\u{26a0} Quit program now"))
                            .size(13)
                            .color(c(DANGER())))
                            .padding([8, 16])
                            .on_press(Message::ForceQuit)
                            .style(secondary_button_style)
                    );
                    col.spacing(16)
                }
            )
            .height(Length::Fill)
        )
        .padding(12)
        .style(panel_frame_style)
        .into()
    }

    fn view_logs(&self) -> Element<'_, Message> {
        let mut items = Column::new()
            .push(text("\u{25a3} LOGS \u{2014} Audit & Security").size(22))
            .push(text("Lokale technische Meldungen fuer Audit und Security.").size(13))
            .spacing(12);
        if self.security_audit_events.is_empty() {
            items = items.push(
                container(
                    Column::new()
                        .push(text("\u{25cb} Noch keine Logs").size(16))
                        .push(text("Nach Anmeldung oder Security-Recheck erscheinen hier Ereignisse.").size(14))
                        .spacing(6)
                )
                .style(|_theme: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
                    border: Border {
                        color: Color::from_rgb8(0x2A, 0x28, 0x44),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                })
                .padding(16)
                .width(Length::Fill)
            );
        } else {
            for event in &self.security_audit_events {
                let trust_upper = event.trust_state.to_uppercase();
                let (badge, border_col) =
                    if trust_upper.contains("HIGH") || trust_upper.contains("OK") || trust_upper.contains("SECURE") {
                        ("\u{25cf} OK", Color::from_rgb8(0x70, 0xB3, 0x92))
                    } else if trust_upper.contains("WARN") || trust_upper.contains("MED") {
                        ("\u{25d0} WARN", Color::from_rgb8(0xD4, 0xA0, 0x50))
                    } else if trust_upper.contains("ERR") || trust_upper.contains("CRIT") {
                        ("\u{25cf} CRIT", Color::from_rgb8(0xC6, 0x6A, 0x6A))
                    } else {
                        ("\u{25cb} INFO", Color::from_rgb8(0x48, 0x90, 0xFF))
                    };
                let summary = event.summary.clone();
                let reason = event.reason.clone();
                let trust_state = event.trust_state.clone();
                let mode = event.mode.clone();
                let maze = event.maze_state.clone();
                items = items.push(
                    container(
                        Column::new()
                            .push({
                                let mut row = Row::new();
                                row = row.push(text(badge).size(13));
                                row = row.push(text(format!("  {} | {}", reason, trust_state)).size(14));
                                row.spacing(6)
                            })
                            .push(text(summary).size(13))
                            .push(text(format!("Mode: {} | Maze: {}", mode, maze)).size(12))
                            .spacing(4)
                    )
                    .width(Length::Fill)
                    .style(move |_theme: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
                        border: Border {
                            color: border_col,
                            width: 1.5,
                            radius: 6.0.into(),
                        },
                        ..Default::default()
                    })
                    .padding([12, 16])
                    .width(Length::Fill)
                );
            }
        }
        container(scrollable(items).height(Length::Fill))
            .padding(12)
            .style(panel_frame_style)
            .into()
    }

    fn view_anchors(&self) -> Element<'_, Message> {
        let clusters = self.anchor_clusters();

        // Guard: leere Vault beim Erststart — zeige Onboarding-Hinweis statt Panic
        if clusters.is_empty() {
            return container(
                column![
                    text("◆ ANCHOR VAULT").size(22),
                    text("Was sind Anker?").size(16).color(Color::from_rgb8(0x9A, 0x67, 0xFF)),
                    text("Anker (Anchors) sind unveränderliche Strukturabdrücke einer Datei — ähnlich einem kryptografischen Fingerabdruck, aber rein aus mathematischen Strukturmerkmalen abgeleitet, nicht aus dem Inhalt selbst.").size(13),
                    text("Artefakte sind analysierte Dateien, gespeichert mit ihrem Anker im Vault. Je mehr Artefakte bekannt sind, desto schneller und genauer werden neue Analysen — weil bekannte Muster nicht erneut berechnet werden.").size(13),
                    text("Analysiere eine Datei um erste Strukturanker zu erzeugen.").size(13).color(Color::from_rgb8(0x50, 0x6A, 0x7A)),
                ]
                .spacing(10),
            )
            .padding(20)
            .into();
        }

        let selected = clusters
            .get(self.selected_anchor_group)
            .cloned()
            .unwrap_or_else(|| clusters[0].clone());
        let mut list = Column::new()
            .push(text("\u{25c6} ANCHOR VAULT — Strukturanker und Artefakte").size(22))
            .push(text("Anker sind strukturelle Fingerabdrücke von Dateien. Artefakte sind analysierte Dateien im Vault. Je mehr vorhanden, desto effizienter werden neue Analysen.").size(12).color(Color::from_rgb8(0x50, 0x6A, 0x7A)))
            .push(text("Cluster entstehen automatisch datengetrieben aus Strukturmerkmalen — nicht aus Dateinamen oder Typen.").size(12).color(Color::from_rgb8(0x50, 0x6A, 0x7A)))
            .spacing(10);
        for (index, cluster) in clusters.iter().enumerate() {
            let is_sel = index == self.selected_anchor_group;
            let bar = make_sparkline((cluster.item_count.min(20) as f32) / 20.0_f32);
            let title = cluster.title.clone();
            let descriptor = cluster.descriptor.clone();
            let item_count = cluster.item_count;
            list = list.push(
                container(
                    button(
                        Column::new()
                            .push(text(format!("\u{25c6} {}", title)).size(15))
                            .push(text(descriptor).size(12))
                            .push(text(format!("{} [{}]", bar, item_count)).size(12))
                            .spacing(3),
                    )
                    .padding([10, 12])
                    .width(Length::Fill)
                    .on_press(Message::AnchorGroupSelected(index)),
                )
                .style(move |_theme: &Theme| {
                    if is_sel {
                        container::Style {
                            background: Some(Background::Color(Color::from_rgb8(0x12, 0x5A, 0x68))),
                            border: Border {
                                color: Color::from_rgb8(0x78, 0x44, 0xD8),
                                width: 1.5,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }
                    } else {
                        container::Style {
                            background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
                            border: Border {
                                color: Color::from_rgb8(0x2A, 0x28, 0x44),
                                width: 1.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }
                    }
                })
                .width(Length::Fill),
            );
        }
        let detail_fill = if selected.total_bytes == 0 {
            0.0_f32
        } else {
            (selected.total_bytes.min(10_000_000) as f32) / 10_000_000.0
        };
        let observation_summary = if selected.observation_count == 0 {
            "FlowSphere-History: noch keine Zeitbeobachtungen fuer dieses Cluster.".to_owned()
        } else {
            format!(
                "FlowSphere-History: {} Beobachtungen | Erste Sicht {} | Letzte Sicht {}",
                selected.observation_count,
                selected
                    .first_seen
                    .map(format_unix_date)
                    .unwrap_or_else(|| "unbekannt".to_owned()),
                selected
                    .last_seen
                    .map(format_unix_date)
                    .unwrap_or_else(|| "unbekannt".to_owned())
            )
        };
        container(
            Row::new()
                .push(
                    container(scrollable(list).height(Length::Fill))
                        .padding(12)
                        .style(panel_frame_style)
                        .width(Length::FillPortion(1))
                )
                .push(
                    container(
                        Column::new()
                            .push(text(format!("\u{25c6} {}", selected.title)).size(22))
                            .push(text(selected.descriptor.clone()).size(15))
                            .push(text(format!("Artefakte: {}", selected.item_count)).size(14))
                            .push(progress_bar(0.0..=1.0, detail_fill))
                            .push(text(make_sparkline(detail_fill)).size(13))
                            .push(text(format!("Gr\u{f6}\u{df}e: {} B", selected.total_bytes)).size(14))
                            .push(text(observation_summary).size(13))
                            .push(text(selected.sample_note.clone()).size(13))
                            .push(button(text("Download anfragen")).padding([10, 18]).style(secondary_button_style))
                            .spacing(10)
                    )
                    .style(accent_card_style)
                    .padding(22)
                    .width(Length::FillPortion(2))
                )
                .spacing(14),
        )
        .padding(12)
        .style(panel_frame_style)
        .into()
    }

    fn view_imprint(&self) -> Element<'_, Message> {
        let symbiont_count = self.auth_store.user_count();
        let accent  = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let teal    = Color::from_rgb8(0x3F, 0xBA, 0xC2);
        let mid     = Color::from_rgb8(0xA8, 0xC4, 0xD8);
        let dim     = Color::from_rgb8(0x50, 0x6A, 0x7A);
        let panel_s = Color::from_rgb8(0x05, 0x10, 0x1C);

        let section = |title: &'static str, body: &'static str| -> Element<'_, Message> {
            container(
                Column::new()
                    .push(text(title).size(15).color(accent))
                    .push(text(body).size(13).color(mid))
                    .spacing(6),
            )
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(panel_s)),
                border: Border { color: dim, width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
            .padding(16)
            .width(Length::Fill)
            .into()
        };

        container(
            scrollable(
                Column::new()
                    .push(text("Aether \u{2014} Was ist das?").size(26).color(c(TEXT_H())))
                    .push(text(format!("Version: lokal  \u{b7}  Registrierte Nutzer: {symbiont_count}")).size(12).color(teal))
                    .push(section(
                        "Ziel und Kernidee",
                        "Aether ist ein signalagnostisches Beobachter- und Verdichtungssystem. Es lernt strukturelle Muster aus beliebigen Datenquellen \u{2014} Dateien, Sensoren, Klimamessreihen, Audiodaten, Spielsequenzen \u{2014} ohne eine zentrale Infrastruktur zu ben\u{f6}tigen. Jedes Ger\u{e4}t ist ein vollst\u{e4}ndiger Knoten.",
                    ))
                    .push(section(
                        "Dezentralit\u{e4}t und Datenschutz",
                        "Kein Konto bei einem Drittanbieter. Kein Cloud-Upload. Alle Daten, Analysen, Anker und Schl\u{fc}ssel bleiben auf dem Ger\u{e4}t. Rekonstruktion und Zugang sind an den lokalen Vault gebunden. Es gibt keine zentrale Wiederherstellung \u{2014} das ist kein Fehler, sondern das Grundprinzip.",
                    ))
                    .push(section(
                        "Demokratisierung von Wissen und Technik",
                        "Leistungsf\u{e4}hige Analyse und Mustererkennung sind keine Privilegien von Rechenzentren. Aether verhilft auch alter Hardware zu aussagekr\u{e4}ftigen Ergebnissen, weil die Effizienz mit jedem gespeicherten Muster w\u{e4}chst \u{2014} es wird nicht mehr Strom ben\u{f6}tigt, sondern weniger. Veraltete Ger\u{e4}te werden durch neues Wissen wertvoller.",
                    ))
                    .push(section(
                        "Kampf gegen Obsoleszenz durch Struktur",
                        "Das System behandelt jede weitere Analyse nicht als neue Last, sondern als zus\u{e4}tzliches Wissen das zuk\u{fc}nftige Analysen beschleunigt. Bekannte Muster werden nicht erneut berechnet, sondern aus dem Vault abgeglichen. Je gr\u{f6}\u{df}er der Vault, desto geringer der Rechenaufwand pro neuer Datei.",
                    ))
                    .push(section(
                        "Signalagnostik \u{2014} eine Meta-Schicht \u{fc}ber jedem OS und jeder Hardware",
                        "Aether unterscheidet nicht zwischen Dateitypen, Protokollen oder Systemarchitekturen. Es sucht nach mathematischen Invarianten \u{2014} Strukturen, die sich unver\u{e4}ndert verhalten unabh\u{e4}ngig davon ob das Signal ein Genome-Datensatz, ein JPEG, eine Audiodatei oder ein Netzwerkpaket ist. Das macht es zu einer Metalayer die \u{fc}ber jedem OS und jeder Hardware funktioniert.",
                    ))
                    .push(section(
                        "Shannon-Erweiterung durch Beobachternetzwerke",
                        "Klassische Informationstheorie (Shannon) berechnet Entropie f\u{fc}r bekannte Alphabete. Aether erweitert diesen Ansatz: ein verteiltes Netzwerk von Beobachtern sucht signalartübergreifende Invarianten, kommuniziert sie, verbessert sie und l\u{e4}sst lossless Kompression emergieren \u{2014} nicht durch Regelwerke, sondern durch Strukturkonvergenz. Muster entstehen, nach denen niemand explizit gesucht hat.",
                    ))
                    .push(section(
                        "Symbiotische Metalayer OS",
                        "Aether greift nicht in das laufende Betriebssystem ein. Es legt sich als Beobachtungsschicht dar\u{fc}ber: liest Signale, analysiert, verdichtet, ankert und gibt strukturierte R\u{fc}ckmeldungen. Die Hardware-Ressourcen die es nutzt, nutzt es effizienter als zuvor \u{2014} weil jede verarbeitete Datei das gesamte System ein kleines Bisschen schneller macht.",
                    ))
                    .push(section(
                        "Technische Grundformeln",
                        "P(n) = base + (1-base) \u{d7} ln(1+n) / ln(1+N\u{2098}\u{2090}\u{2093})\n\u{2192} Wahrscheinlichkeit eines Vault-Treffers nach n gespeicherten Mustern. Skaliert logarithmisch.\n\nC(t) = vault_hits / total_chunks\n\u{2192} Kompressions-Effizienz zu Zeitpunkt t. Steigt monoton mit Vault-Gr\u{f6}\u{df}e.\n\nH\u{03bb} = H(X) \u{2212} I(X;vault)\n\u{2192} Restunsicherheit nach Abzug des strukturellen Vorwissens.",
                    ))
                    .push(info_card("Status", "Die Kernlogik ist vollst\u{e4}ndig implementiert. Die signalagnostische Skalierung ist vorbereitet. Der verteilte Netzwerkbetrieb (Swarm) ist aktiv. Vollst\u{e4}ndig end-to-end operationalisiert wird das System mit wachsendem Vault automatisch leistungsf\u{e4}higer."))
                    .push(info_card("Datenschutz", "Account, Schl\u{fc}ssel, Deltas und Vault-Inhalte verbleiben auf diesem Ger\u{e4}t. Es gibt keine Telemetrieverbindung, keine Cloud-Synchronisation und keinen zentralen Server."))
                    .spacing(12),
            )
            .height(Length::Fill),
        )
        .padding(12)
        .style(panel_frame_style)
        .into()
    }

    // -----------------------------------------------------------------------
    // Aether.Rekonstruktion – lokale AEF-Dateien rekonstruieren
    // -----------------------------------------------------------------------

    fn view_rekonstruktion(&self) -> Element<'_, Message> {
        let entries = self.entries();

        let header = Row::new()
            .push(text("Rekonstruktion").size(22).color(Color::from_rgb8(0xD0, 0xE8, 0xF8)))
            .push(text(" \u{2014} lokale AEF-Artefakte wiederherstellen").size(14)
                .color(Color::from_rgb8(0x60, 0x88, 0xA8)))
            .spacing(8)
            .align_y(Alignment::Center);

        // File list
        let list: Element<'_, Message> = if entries.is_empty() {
            container(
                text("Keine Artefakte vorhanden. Datei in das Fenster ziehen, um zu beginnen.")
                    .size(14)
                    .color(Color::from_rgb8(0x60, 0x88, 0xA8)),
            )
            .padding(20)
            .into()
        } else {
            let rows: Vec<_> = entries
                .into_iter()
                .map(|entry| {
                    let is_selected = self.rekonstruktion_selected == Some(entry.id);
                    let gain_color = if entry.compression_gain_percent > 0.0 {
                        Color::from_rgb8(0x4C, 0xD9, 0x6E)
                    } else {
                        Color::from_rgb8(0xD9, 0x7A, 0x4C)
                    };
                    let row_style = move |_: &Theme| container::Style {
                        background: Some(Background::Color(if is_selected {
                            Color::from_rgba(0.59, 0.34, 0.96, 0.18)
                        } else {
                            Color::from_rgb8(0x12, 0x11, 0x1E)
                        })),
                        border: Border {
                            color: if is_selected { Color::from_rgb8(0xA0, 0x70, 0xFF) } else { Color::from_rgb8(0x2E, 0x2C, 0x4C) },
                            width: 1.0,
                            radius: 10.0.into(),
                        },
                        ..Default::default()
                    };
                    let entry_id = entry.id;
                    let size_kb = entry.original_size / 1024;
                    let gain = entry.compression_gain_percent;
                    container(
                        button(
                            Row::new()
                                .push(text("\u{25a4}").size(14).color(Color::from_rgb8(0x80, 0xBC, 0xE8)))
                                .push(
                                    Column::new()
                                        .push(text(entry.file_name).size(14).color(Color::from_rgb8(0xD0, 0xE8, 0xF8)))
                                        .push(text(format!(
                                            "{} KB  \u{2192}  {:.1}% Gewinn",
                                            size_kb,
                                            gain
                                        ))
                                        .size(12)
                                        .color(gain_color))
                                        .spacing(2)
                                )
                                .spacing(10)
                                .align_y(Alignment::Center),
                        )
                        .on_press(Message::ReconstructPressed(entry_id))
                        .style(secondary_button_style)
                        .width(Length::Fill),
                    )
                    .style(row_style)
                    .padding([6, 10])
                    .width(Length::Fill)
                    .into()
                })
                .collect();
            scrollable(Column::with_children(rows).spacing(4))
                .height(Length::Fixed(320.0))
                .into()
        };

        // Status / result panel
        let status_panel: Element<'_, Message> = if self.rekonstruktion_running {
            container(
                Row::new()
                    .push(text("\u{21ba}").size(18).color(Color::from_rgb8(0x80, 0xBC, 0xE8)))
                    .push(text("Rekonstruktion laeuft …").size(14)
                        .color(Color::from_rgb8(0x80, 0xBC, 0xE8)))
                    .spacing(8)
                    .align_y(Alignment::Center),
            )
            .padding(16)
            .style(panel_frame_style)
            .width(Length::Fill)
            .into()
        } else if let Some(result) = &self.rekonstruktion_result {
            match result {
                Ok((file_name, aef_result)) => {
                    let hash_icon = if aef_result.original_hash_verified { "\u{2714}" } else { "\u{2718}" };
                    let complete_icon = if aef_result.reconstruction_complete { "\u{2714}" } else { "\u{2718}" };
                    let hash_color = if aef_result.original_hash_verified {
                        Color::from_rgb8(0x4C, 0xD9, 0x6E)
                    } else {
                        Color::from_rgb8(0xD9, 0x7A, 0x4C)
                    };
                    let complete_color = if aef_result.reconstruction_complete {
                        Color::from_rgb8(0x4C, 0xD9, 0x6E)
                    } else {
                        Color::from_rgb8(0xD9, 0x7A, 0x4C)
                    };
                    let selected_id = self.rekonstruktion_selected.unwrap_or(0);
                    let export_btn: Element<'_, Message> = if aef_result.reconstruction_complete {
                        button(
                            text("\u{2b07} Exportieren").size(14)
                                .color(Color::from_rgb8(0xD0, 0xE8, 0xF8)),
                        )
                        .on_press(Message::ExportPressed(selected_id))
                        .padding([8, 18])
                        .style(primary_button_style)
                        .into()
                    } else {
                        iced::widget::Space::new(Length::Shrink, Length::Shrink).into()
                    };
                    container(
                        Column::new()
                            .push(text(format!("Datei: {file_name}")).size(14).color(Color::from_rgb8(0xD0, 0xE8, 0xF8)))
                            .push(Row::new()
                                .push(text(hash_icon).size(14).color(hash_color))
                                .push(text("Hash verifiziert").size(13).color(Color::from_rgb8(0x90, 0xB8, 0xD8)))
                                .spacing(6)
                            )
                            .push(Row::new()
                                .push(text(complete_icon).size(14).color(complete_color))
                                .push(text("Rekonstruktion vollstaendig").size(13).color(Color::from_rgb8(0x90, 0xB8, 0xD8)))
                                .spacing(6)
                            )
                            .push(text(format!("Kohaerenz: {:.3}", aef_result.coherence_index)).size(13)
                                .color(Color::from_rgb8(0x80, 0xA8, 0xC8)))
                            .push(text(format!("Fehlende Vault-Refs: {}", aef_result.missing_vault_refs.len())).size(13)
                                .color(Color::from_rgb8(0x80, 0xA8, 0xC8)))
                            .push(export_btn)
                            .spacing(6),
                    )
                    .padding(16)
                    .style(panel_frame_style)
                    .width(Length::Fill)
                    .into()
                }
                Err(err) => {
                    let is_aef_err = err.contains("Magic Bytes")
                        || err.contains("ungültig")
                        || err.contains("droppen");
                    let mut col = column![
                        row![
                            text("\u{2718}").size(14).color(Color::from_rgb8(0xD9, 0x7A, 0x4C)),
                            text(format!("Fehler: {err}")).size(13)
                                .color(Color::from_rgb8(0xD9, 0x7A, 0x4C)),
                        ]
                        .spacing(8),
                    ]
                    .spacing(8);
                    if is_aef_err {
                        col = col.push(
                            container(
                                column![
                                    text("\u{26a0} Diese Datei ist noch kein AEF-Artefakt.")
                                        .size(13)
                                        .color(Color::from_rgb8(0xFF, 0xCC, 0x44)),
                                    text("AEF (Aether Encoded Format) ist das interne Artefakt-Format, das bei einer ersten Analyse erzeugt wird. Es enth\u{e4}lt strukturelle Anker, Delta-Werte und Metadaten f\u{fc}r die sp\u{e4}tere Rekonstruktion.")
                                        .size(12)
                                        .color(Color::from_rgb8(0xCC, 0xAA, 0x44)),
                                    text("L\u{f6}sung: Ziehe die Originaldatei zun\u{e4}chst in den Analyse-Tab um sie zu erfassen. Danach ist sie im Vault und kann hier rekonstruiert werden.")
                                        .size(12)
                                        .color(Color::from_rgb8(0xAA, 0x88, 0x44)),
                                ]
                                .spacing(6),
                            )
                            .padding([8, 12])
                            .style(|_: &Theme| container::Style {
                                background: Some(Background::Color(Color::from_rgb8(0x2A, 0x18, 0x00))),
                                border: Border { color: Color::from_rgb8(0x88, 0x66, 0x00), width: 1.0, radius: 4.0.into() },
                                ..Default::default()
                            }),
                        );
                    }
                    container(col)
                    .padding(16)
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgb8(0x1C, 0x06, 0x06))),
                        border: Border { color: Color::from_rgb8(0xA8, 0x44, 0x44), width: 1.0, radius: 10.0.into() },
                        ..Default::default()
                    })
                    .width(Length::Fill)
                    .into()
                }
            }
        } else {
            let hint = if self.rekonstruktion_selected.is_some() {
                "Eintrag ausgewaehlt. Rekonstruieren druecken um zu starten."
            } else {
                "Eintrag auswaehlen, dann Rekonstruieren druecken."
            };
            container(
                text(hint).size(13).color(Color::from_rgb8(0x60, 0x88, 0xA8)),
            )
            .padding(16)
            .style(panel_frame_style)
            .width(Length::Fill)
            .into()
        };

        // Action button
        let reconstruct_btn = button(
            text("\u{21ba} Rekonstruieren").size(15)
                .color(Color::from_rgb8(0xD0, 0xE8, 0xF8)),
        )
        .on_press_maybe(
            self.rekonstruktion_selected
                .filter(|_| !self.rekonstruktion_running)
                .map(Message::ReconstructPressed),
        )
        .padding([10, 22])
        .style(primary_button_style);

        container(
            column![
                header,
                list,
                reconstruct_btn,
                status_panel,
            ]
            .spacing(14),
        )
        .padding(16)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(panel_frame_style)
        .into()
    }

    // -----------------------------------------------------------------------
    // Aether.StructureMap – Ockham-gefilterter fraktaler 3D-Suchbaum
    // Reine Visualisierung. Keine Steuerlogik. Keine Systemeingriffe.
    // -----------------------------------------------------------------------

    fn step_structure_map(&mut self) {
        use rand::{Rng, SeedableRng};
        use rand::rngs::StdRng;
        use std::f32::consts::TAU;

        let mut rng = StdRng::seed_from_u64(
            self.tick_counter.wrapping_mul(7919).wrapping_add(3),
        );
        const N_RINGS: usize = 10;
        let mut nodes: Vec<Vec<f32>> = Vec::with_capacity(N_RINGS);

        // Ring 1 – Rohdaten: 6 zufällige Positionen
        let ring1: Vec<f32> = (0..6).map(|_| rng.gen_range(0.0f32..TAU)).collect();
        nodes.push(ring1);

        // Ring 2–6 – Verarbeitung: Verzweigung mit Variation
        for ring in 1..6 {
            let prev = nodes[ring - 1].clone();
            let mut curr: Vec<f32> = Vec::new();
            for &t in &prev {
                curr.push((t + rng.gen_range(-0.26f32..0.26f32)).rem_euclid(TAU));
                if ring >= 2 && rng.gen::<f32>() < 0.38 {
                    curr.push((t + rng.gen_range(-0.52f32..0.52f32)).rem_euclid(TAU));
                }
            }
            curr.truncate(24);
            nodes.push(curr);
        }

        // Ring 7 – Ockham-Schnitt: probabilistischer Ast-Kollaps
        let prev7 = nodes.last().unwrap().clone();
        let rate = 0.35 + 0.18 * ((self.tick_counter as f32 * 0.42).sin());
        let filtered: Vec<f32> = prev7.into_iter()
            .filter(|_| rng.gen::<f32>() < rate)
            .collect();
        let ring7: Vec<f32> = if filtered.is_empty() {
            (0..3).map(|_| rng.gen_range(0.0f32..TAU)).collect()
        } else {
            filtered.into_iter()
                .map(|t| (t + rng.gen_range(-0.04f32..0.04f32)).rem_euclid(TAU))
                .collect()
        };
        nodes.push(ring7);

        // Ring 8–9 – Kompression: Konvergenz zu 4 Anker-Clustern
        let anchors = [0.0f32, TAU / 4.0, TAU / 2.0, 3.0 * TAU / 4.0];
        for _ in 0..2 {
            let prev = nodes.last().unwrap().clone();
            let mut curr: Vec<f32> = Vec::with_capacity(prev.len());
            for t in prev {
                let near = anchors.iter().copied()
                    .min_by(|&a, &b| {
                        let da = (a - t).abs().min(TAU - (a - t).abs());
                        let db = (b - t).abs().min(TAU - (b - t).abs());
                        da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .unwrap_or(0.0);
                curr.push(
                    (t + 0.74 * (near - t) + rng.gen_range(-0.022f32..0.022f32))
                        .rem_euclid(TAU),
                );
            }
            nodes.push(curr);
        }

        // Ring 10 – Anker: 4 feste Diamant-Knoten
        nodes.push(anchors.to_vec());
        self.structure_map_nodes = nodes;

        // Anker-Dichte-Historie
        let n = self.structure_map_nodes.last().map_or(0, |v| v.len());
        self.structure_map_anchor_hist
            .push(n as f32 + rng.gen_range(-0.25f32..0.25f32));
        if self.structure_map_anchor_hist.len() > 30 {
            self.structure_map_anchor_hist.remove(0);
        }

        // Mutations-Histogramm (Ring 5)
        let m = ((12.0 + rng.gen_range(-3.2f32..3.2f32)).max(0.0)) as u32;
        self.structure_map_mutation_hist.push(m);
        if self.structure_map_mutation_hist.len() > 20 {
            self.structure_map_mutation_hist.remove(0);
        }

        // Lossless-Compression-Ratio (wächst bis 100%, rastet ein)
        if !self.structure_map_locked {
            self.structure_map_compression = (self.structure_map_compression
                + rng.gen_range(3.8f32..7.2f32))
                .min(100.0);
            if self.structure_map_compression >= 100.0 {
                self.structure_map_compression = 100.0;
                self.structure_map_locked = true;
            }
        }
    }

    fn view_flow_sphere(&self) -> Element<'_, Message> {
        use std::f32::consts::TAU;

        let cyan       = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let dim        = Color::from_rgb8(0x50, 0x6A, 0x7A);
        let soft       = Color::from_rgb8(0x8F, 0xA7, 0xBA);
        let surf_bg    = Color::from_rgb8(0x03, 0x09, 0x12);
        let panel_bg   = Color::from_rgb8(0x05, 0x0F, 0x1C);
        let green      = Color::from_rgb8(0x4C, 0xD9, 0x6E);
        let amber      = Color::from_rgb8(0xFF, 0xD7, 0x00);
        let red        = Color::from_rgb8(0xD9, 0x50, 0x50);

        // Derived metrics from live data
        let entropy = self
            .capsule_state
            .as_ref()
            .map(|capsule| (capsule.entropy / 8.0).clamp(0.0, 1.0))
            .unwrap_or((self.structure_map_compression / 100.0).clamp(0.0, 1.0));
        let stability = self
            .structure_map_state
            .as_ref()
            .map(|state| if state.locked { 1.0f32 } else { state.coherence_score.clamp(0.0, 1.0) })
            .unwrap_or_else(|| if self.structure_map_locked { 1.0f32 } else { entropy * 0.82 });
        let anchor_count = self
            .structure_map_state
            .as_ref()
            .map(|state| state.anchor_count)
            .unwrap_or_else(|| self.structure_map_nodes.last().map_or(4, |v| v.len()));
        let info_growth = entropy;
        let delta_convergence = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.delta_convergence as f32)
            .unwrap_or_else(|| {
                if self.live_render_last_delta_ratio > 0.0 {
                    (1.0 - self.live_render_last_delta_ratio).clamp(0.0, 1.0)
                } else {
                    // synthetic: grows from 0 → 1 as step_structure_map runs
                    (self.structure_map_compression / 100.0).clamp(0.0, 1.0)
                }
            });
        let compression_gain = self
            .compression_state
            .as_ref()
            .map(|state| (state.gain_percent / 100.0).clamp(0.0, 1.0))
            .unwrap_or((1.0 - entropy).clamp(0.0, 1.0));
        let reconstruction_quality = self
            .reconstruction_state
            .as_ref()
            .map(|state| state.quality_score.clamp(0.0, 1.0))
            .unwrap_or(stability);
        let aelab_coupling = self
            .aelab_state
            .as_ref()
            .map(|state| state.seed_coupling.clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let reconstruction_path = self
            .reconstruction_state
            .as_ref()
            .map(|state| {
                if state.path_steps.is_empty() {
                    "capsule.metrics -> structure_map.snapshot".to_owned()
                } else {
                    state.path_steps.join(" -> ")
                }
            })
            .unwrap_or_else(|| "capsule.metrics -> structure_map.snapshot".to_owned());

        let zipf_alpha = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.zipf_alpha as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.zipf_alpha))
            .unwrap_or(0.0);
        let benford_score = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.benford_score as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.benford_score))
            .unwrap_or(0.0);
        let katz_dimension = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.katz_dimension as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.katz_dimension))
            .unwrap_or(0.0);
        let noether_consistency = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.noether_consistency as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.noether_consistency))
            .unwrap_or(stability);
        let trust_score = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.trust_score as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.trust_score))
            .unwrap_or(stability);
        let fourier_period = self
            .cascade_metrics
            .as_ref()
            .map(|metrics| metrics.fourier_period as f32)
            .or_else(|| self.capsule_state.as_ref().map(|capsule| capsule.periodicity))
            .unwrap_or(0.0);
        let bayes_confidence = self
            .capsule_state
            .as_ref()
            .map(|capsule| capsule.bayes_confidence)
            .unwrap_or(0.0);
        // Weitere Mustererkennungsmetriken direkt aus capsule_state (unveraenderte Pipeline-Rohwerte)
        let perm_entropy = self
            .capsule_state
            .as_ref()
            .map(|c| c.perm_entropy.clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let symmetry = self
            .capsule_state
            .as_ref()
            .map(|c| c.symmetry.clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let h_lambda = self
            .capsule_state
            .as_ref()
            .map(|c| c.h_lambda.clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let sce_score = self
            .capsule_state
            .as_ref()
            .map(|c| c.sce_score.clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let anomaly_flags = self
            .capsule_state
            .as_ref()
            .map(|capsule| capsule.anomaly_flags.clone())
            .unwrap_or_default();
        let anomaly_level = (
            (anomaly_flags.len() as f32 / 4.0).clamp(0.0, 1.0) * 0.55
                + (1.0 - trust_score).clamp(0.0, 1.0) * 0.25
                + (1.0 - noether_consistency).clamp(0.0, 1.0) * 0.20
        )
        .clamp(0.0, 1.0);
        let external_link_strength = if self.backend_swarm_node_count == 0 {
            0.0
        } else {
            ((self.backend_swarm_reachable_node_count as f32 / self.backend_swarm_node_count as f32) * 0.7
                + (self.backend_swarm_candidate_count as f32 / (self.backend_swarm_node_count.max(1) as f32)).min(1.0) * 0.3)
                .clamp(0.0, 1.0)
        };
        let internal_headline = if stability > 0.78 && delta_convergence > 0.68 {
            "Innen bleibt das Muster ruhig und gut gebuendelt."
        } else if entropy > 0.68 && stability < 0.52 {
            "Im Inneren ist viel Bewegung; das Muster streut sichtbar."
        } else {
            "Im Inneren gibt es Bewegung, aber noch klare Musterkerne."
        };
        let external_headline = if self.backend_swarm_node_count == 0 {
            "Aktuell liegen keine externen Verbindungen fuer den Vergleich vor."
        } else if external_link_strength > 0.7 {
            "Nach aussen ist das Bild gut verbunden; Aussenmuster lassen sich sinnvoll vergleichen."
        } else {
            "Nach aussen gibt es nur lockere Verbindungen; Unterschiede sind wichtiger als Gleichlauf."
        };
        let anomaly_headline = if anomaly_flags.is_empty() {
            "Derzeit sticht nichts stark aus dem Gesamtbild heraus.".to_owned()
        } else {
            format!("Auffaellig sind vor allem: {}.", anomaly_flags.join(", "))
        };
        let (focus_title, focus_summary, focus_detail, focus_accent) =
            self.flow_sphere_focus_details(&self.flow_sphere_focus_key);
        let (broadcast_gate_ok, broadcast_gate_summary, broadcast_gate_detail) =
            self.flow_sphere_broadcast_gate_details();
        let view_accent = if self.flow_sphere_view_mode {
            Color::from_rgb8(0x9A, 0x67, 0xFF)
        } else {
            Color::from_rgb8(0x59, 0xD5, 0xE9)
        };

        let summary_card = |title: &'static str, headline: String, detail: String, accent: Color| {
            container(
                column![
                    text(title).size(10).color(soft),
                    text(headline).size(14).color(c(TEXT_H())),
                    text(detail).size(11).color(dim),
                ]
                .spacing(4),
            )
            .padding([10, 12])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.10, 0.14, 0.22, 0.86))),
                border: Border { color: accent, width: 1.0, radius: 10.0.into() },
                ..Default::default()
            })
        };

        let metric_hint = |title: &'static str, value: String, accent: Color, meaning: &'static str, detail: String| {
            container(
                column![
                    text(title).size(10).color(soft),
                    text(value).size(15).color(accent),
                    text(meaning).size(11).color(c(TEXT_H())),
                    text(detail).size(10).color(dim),
                ]
                .spacing(4),
            )
            .padding([9, 11])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.08, 0.12, 0.18, 0.90))),
                border: Border { color: Color::from_rgba(accent.r, accent.g, accent.b, 0.75), width: 1.0, radius: 9.0.into() },
                ..Default::default()
            })
        };

        let focus_button = |label: &'static str, key: &'static str, accent: Color| {
            let is_active = self.flow_sphere_focus_key == key;
            button(
                column![
                    text(label).size(12).color(if is_active { c(TEXT_H()) } else { accent }),
                    text(match key {
                        "internal_core" => "Kern lesen",
                        "overlay" => "Ueberlagerung lesen",
                        "anomaly" => "Bruchstellen lesen",
                        "external_links" => "Aussenbezug lesen",
                        _ => "Details",
                    })
                    .size(10)
                    .color(if is_active { c(TEXT_H()) } else { soft }),
                ]
                .spacing(2)
            )
            .on_press(Message::FlowSphereExplain(key.to_owned()))
            .padding([9, 12])
            .style(move |_: &Theme, _| button::Style {
                background: Some(Background::Color(if is_active {
                    Color::from_rgba(accent.r, accent.g, accent.b, 0.26)
                } else {
                    Color::from_rgba(0.08, 0.11, 0.16, 0.96)
                })),
                border: Border {
                    color: accent,
                    width: if is_active { 1.6 } else { 1.0 },
                    radius: 10.0.into(),
                },
                text_color: if is_active { c(TEXT_H()) } else { accent },
                ..Default::default()
            })
        };

        let attractor_lons = [0.0f32, TAU / 6.0, TAU / 3.0, TAU / 2.0, 2.0 * TAU / 3.0, 5.0 * TAU / 6.0];

        // Externe Peers bleiben fuer die Aussenebene verfuegbar, auch wenn Lokalmodus aktiv ist.
        let swarm_nodes = if self.backend_swarm_node_count > 0 {
            (0..(self.backend_swarm_node_count.min(12) as usize))
                .map(|i| {
                    let angle = (i as f32) * 0.5 + (self.tick_counter as f32) * 0.001;
                    let coherence = 0.4 + 0.6 * ((entropy * (i as f32)).sin().abs());
                    (format!("Peer-{}", i + 1), angle.cos() * 0.6, angle, coherence)
                })
                .collect()
        } else {
            Vec::new()
        };

        let delta_phases: [f32; 5] = {
            let m = &self.structure_map_mutation_hist;
            [
                m.get(m.len().saturating_sub(1)).copied().unwrap_or(8) as f32 * 0.41,
                m.get(m.len().saturating_sub(3)).copied().unwrap_or(6) as f32 * 0.63,
                m.get(m.len().saturating_sub(7)).copied().unwrap_or(10) as f32 * 0.27,
                m.get(m.len().saturating_sub(12)).copied().unwrap_or(7) as f32 * 0.55,
                m.get(m.len().saturating_sub(18)).copied().unwrap_or(9) as f32 * 0.34,
            ]
        };

        // h_t inspector side panel
        let ht_panel = {
            let i_ht = 0.5 + 0.5 * entropy; // approximated I(h_t)
            let anchor_spark: String = {
                let h = &self.structure_map_anchor_hist;
                let max = h.iter().cloned().fold(0.1f32, f32::max);
                h.iter().take(16).map(|&v| {
                    let p = (v / max).clamp(0.0, 1.0);
                    if p > 0.75 { '\u{2588}' } else if p > 0.50 { '\u{2593}' }
                    else if p > 0.25 { '\u{2592}' } else { '\u{2591}' }
                }).collect()
            };
            let mut_spark: String = self.structure_map_mutation_hist.iter().take(16).map(|&v| {
                if v >= 12 { '\u{2588}' } else if v >= 8 { '\u{2593}' }
                else if v >= 4 { '\u{2592}' } else { '\u{2591}' }
            }).collect();

            // Pre-compute history element before column! macro to satisfy iced type inference
            let history_el: Element<'_, Message> = {
                let entries: &Vec<FlowSphereEntry> = match self.flow_sphere_subtab {
                    FlowSphereSubTab::Session => &self.flow_sphere_session_entries,
                    FlowSphereSubTab::History | FlowSphereSubTab::Global => &self.flow_sphere_history,
                };
                let entry_rows: Vec<Element<'_, Message>> = if entries.is_empty() {
                    let empty_msg: &'static str = match self.flow_sphere_subtab {
                        FlowSphereSubTab::Session => "Noch keine Analysen in dieser Sitzung.",
                        FlowSphereSubTab::History => "Noch keine gespeicherten Analysen.",
                        FlowSphereSubTab::Global => "Keine Swarm-Vergleichsdaten.",
                    };
                    vec![text(empty_msg).size(10).color(dim).into()]
                } else {
                    entries.iter().enumerate()
                        .rev()
                        .take(30)
                        .map(|(idx, entry)| {
                            let is_selected = self.flow_sphere_compare_idx == Some(idx);
                            let ts = format_unix_date(
                                entry.visual_timestamp_secs(self.temporal_metadata_consent),
                            );
                            let ts_origin = entry.visual_timestamp_origin(self.temporal_metadata_consent);
                            let domain = if entry.domain_hint.is_empty() {
                                String::new()
                            } else {
                                format!(" [{}]", entry.domain_hint)
                            };
                            let has_anomaly = !entry.anomaly_flags.is_empty();
                            let origin_color = match ts_origin {
                                "meta" => Color::from_rgb8(0x7F, 0xD9, 0xFF),
                                "manual" => Color::from_rgb8(0xFF, 0xC8, 0x6B),
                                _ => dim,
                            };
                            button(
                                column![
                                    text(format!("{}{}", entry.source_label.chars().take(22).collect::<String>(), domain))
                                        .size(10).color(if is_selected { Color::WHITE } else { Color::from_rgb8(0xC0, 0xD6, 0xE8) }),
                                    row![
                                        text(format!("{} {}", ts, if has_anomaly { "\u{26a0}" } else { "" }))
                                            .size(9)
                                            .color(if has_anomaly { Color::from_rgb8(0xFF, 0xD7, 0x00) } else { dim }),
                                        text(format!("· {}", ts_origin))
                                            .size(9)
                                            .color(origin_color),
                                    ]
                                    .spacing(4),
                                ]
                                .spacing(1)
                            )
                            .on_press(Message::FlowSphereCompareSelected(idx))
                            .padding([5, 8])
                            .width(Length::Fill)
                            .style(move |_: &Theme, _| button::Style {
                                background: Some(Background::Color(if is_selected {
                                    Color::from_rgba(0.38, 0.22, 0.72, 0.45)
                                } else {
                                    Color::from_rgba(0.06, 0.10, 0.16, 0.90)
                                })),
                                border: Border {
                                    color: if is_selected { Color::from_rgb8(0x9A, 0x67, 0xFF) } else { Color::from_rgba(0.20, 0.28, 0.38, 0.60) },
                                    width: if is_selected { 1.2 } else { 0.6 },
                                    radius: 6.0.into(),
                                },
                                text_color: Color::WHITE,
                                ..Default::default()
                            })
                            .into()
                        })
                        .collect()
                };
                column(entry_rows).spacing(3).into()
            };

            container(
                scrollable(
                    column![
                        text("FLOWSPHERE LESEHILFE").size(11).color(cyan),
                        // --- Sub-Tab-Bar: Sitzung | History | Global ---
                        {
                            let mk_tab = |label: &'static str, tab: FlowSphereSubTab| {
                                let active = self.flow_sphere_subtab == tab;
                                button(text(label).size(11))
                                    .on_press(Message::FlowSphereSubTabSelected(tab))
                                    .padding([5, 10])
                                    .style(move |_: &Theme, _| button::Style {
                                        background: Some(Background::Color(if active {
                                            Color::from_rgba(0.38, 0.22, 0.72, 0.55)
                                        } else {
                                            Color::from_rgba(0.08, 0.11, 0.18, 0.90)
                                        })),
                                        border: Border {
                                            color: if active { Color::from_rgb8(0x9A, 0x67, 0xFF) }
                                                   else { Color::from_rgba(0.35, 0.45, 0.55, 0.40) },
                                            width: if active { 1.4 } else { 0.8 },
                                            radius: 7.0.into(),
                                        },
                                        text_color: if active { Color::WHITE } else { Color::from_rgb8(0x8F, 0xA7, 0xBA) },
                                        ..Default::default()
                                    })
                            };
                            Row::new()
                                .push(mk_tab("Sitzung", FlowSphereSubTab::Session))
                                .push(mk_tab("History", FlowSphereSubTab::History))
                                .push(mk_tab("Global", FlowSphereSubTab::Global))
                                .spacing(4)
                        },
                        // --- Radar-Grafik: alle 12 Pipeline-Metriken, unveraendert ---
                        // Normierungsregeln (auditierbar, invertierbar):
                        //   Shannon: Rohwert/8.0  | KatzFD: /2.0  | Zipf: /3.0
                        //   Fourier: ln(1+x)/3.912 | alle anderen: direkt [0,1]
                        {
                            // Vergleichs-Entry aus History (falls ausgewaehlt)
                            let compare_entry = match self.flow_sphere_subtab {
                                FlowSphereSubTab::Session => self.flow_sphere_compare_idx
                                    .and_then(|i| self.flow_sphere_session_entries.get(i)),
                                FlowSphereSubTab::History | FlowSphereSubTab::Global => self.flow_sphere_compare_idx
                                    .and_then(|i| self.flow_sphere_history.get(i)),
                            };
                            let values_a: [f32; 12] = [
                                entropy,
                                perm_entropy,
                                (katz_dimension / 2.0).clamp(0.0, 1.0),
                                (zipf_alpha / 3.0).clamp(0.0, 1.0),
                                benford_score,
                                (fourier_period.ln_1p() / 3.912).clamp(0.0, 1.0),
                                noether_consistency,
                                h_lambda,
                                symmetry,
                                sce_score,
                                delta_convergence,
                                bayes_confidence,
                            ];
                            let values_b = compare_entry.map(|e| e.metrics);
                            let contradiction_axes: Vec<usize> = compare_entry
                                .map(|e| e.contradiction_axes(&values_a))
                                .unwrap_or_default();
                            let cosine_sim: f32 = compare_entry
                                .map(|e| e.cosine_similarity(&values_a))
                                .unwrap_or(0.0);
                            let has_compare = compare_entry.is_some();
                            let label_a = self.capsule_state.as_ref()
                                .map(|c| c.source_label.clone())
                                .unwrap_or_else(|| "Aktuell".to_owned());
                            let label_b = compare_entry
                                .map(|e| e.source_label.clone())
                                .unwrap_or_default();
                            let canvas_elem = canvas::Canvas::new(MetricRadarScene {
                                values_a,
                                values_b,
                                contradiction_axes,
                                tick: self.tick_counter,
                                label_a,
                                label_b,
                            })
                            .width(Length::Fill)
                            .height(Length::Fixed(220.0));
                            let sim_elem: Element<'_, Message> = if has_compare {
                                let sim_pct = cosine_sim * 100.0;
                                let sim_color = if sim_pct >= 85.0 {
                                    Color::from_rgb8(0x4C, 0xD9, 0x6E)
                                } else if sim_pct >= 60.0 {
                                    Color::from_rgb8(0xD4, 0xA0, 0x42)
                                } else {
                                    Color::from_rgb8(0xD9, 0x50, 0x50)
                                };
                                text(format!("\u{2248} Kosinus-\u{00c4}hnlichkeit: {:.1}%", sim_pct))
                                    .size(11)
                                    .color(sim_color)
                                    .into()
                            } else {
                                text("").size(1).into()
                            };
                            column![canvas_elem, sim_elem].spacing(4)
                        },
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        summary_card(
                            "IM INNEREN",
                            internal_headline.to_owned(),
                            format!("Shannon {:.2} bit | Noether {:.0}% | Delta {:.0}%", entropy * 7.83, noether_consistency * 100.0, delta_convergence * 100.0),
                            cyan,
                        ),
                        summary_card(
                            "NACH AUSSEN",
                            external_headline.to_owned(),
                            if self.backend_swarm_node_count == 0 {
                                "Ohne externe Knoten bleibt die Ansicht auf dem aktuellen Bereich.".to_owned()
                            } else {
                                format!("{} erreichbare Knoten | Verbindung {:.0}%", self.backend_swarm_reachable_node_count, external_link_strength * 100.0)
                            },
                            Color::from_rgb8(0x7F, 0xD9, 0xFF),
                        ),
                        summary_card(
                            "AUFFAELLIGKEITEN",
                            anomaly_headline.clone(),
                            if anomaly_flags.is_empty() {
                                format!("Auffaelligkeitsdruck {:.0}%", anomaly_level * 100.0)
                            } else {
                                format!("Druck {:.0}% | {} Marker", anomaly_level * 100.0, anomaly_flags.len())
                            },
                            if anomaly_level > 0.65 { red } else { amber },
                        ),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        metric_hint(
                            "SHANNON-ENTROPIE",
                            format!("{:.4} bit", entropy * 7.83),
                            Color::from_rgb8(0xAF, 0x86, 0xFF),
                            "zeigt, wie ruhig oder verstreut das Muster wirkt",
                            "Hohe Werte sprechen eher fuer viel Mischung; niedrigere Werte eher fuer klare Ordnung.".to_owned(),
                        ),
                        progress_bar(0.0..=1.0, entropy).height(5),
                        metric_hint(
                            "KATZ FD",
                            format!("{:.4}", katz_dimension),
                            amber,
                            "zeigt, wie verschlungen ein Verlauf ist",
                            "Hoeher kann bedeuten, dass Wege, Konturen oder Signale viele Richtungswechsel haben.".to_owned(),
                        ),
                        metric_hint(
                            "NOETHER-INVARIANTE",
                            format!("{:.1}%", noether_consistency * 100.0),
                            green,
                            "zeigt, wie stabil Grundmuster trotz Veraenderung bleiben",
                            "Hohe Werte sprechen fuer wiederkehrende Ordnung; niedrige Werte eher fuer Bruch oder Umordnung.".to_owned(),
                        ),
                        metric_hint(
                            "ZIPF ALPHA",
                            format!("{:.4}", zipf_alpha),
                            Color::from_rgb8(0x7F, 0xD9, 0xFF),
                            "zeigt, ob Haeufigkeiten einem natuerlichen Rhythmus folgen",
                            "Das ist oft interessant bei Texten, Ereignissen oder wiederkehrenden Mustern im Ablauf.".to_owned(),
                        ),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        metric_hint(
                            "BENFORD",
                            format!("{:.4}", benford_score),
                            Color::from_rgb8(0xC0, 0x8D, 0xFF),
                            "zeigt, ob fuehrende Zahlen natuerlich verteilt wirken",
                            "Das kann helfen zu sehen, ob Zahlen eher gewachsen wirken oder ungewoehnlich haeufig kippen.".to_owned(),
                        ),
                        metric_hint(
                            "BAYES",
                            format!("{:.4}", bayes_confidence),
                            cyan,
                            "zeigt, wie gut neue Hinweise zum bisherigen Bild passen",
                            "Hohe Werte heissen nicht automatisch richtig, aber sie sprechen fuer ein stimmiges Gesamtbild.".to_owned(),
                        ),
                        metric_hint(
                            "FOURIER-PERIODE",
                            format!("{:.4}", fourier_period),
                            amber,
                            "zeigt, ob sich ein Takt oder eine Wiederholung abzeichnet",
                            "Das ist nuetzlich, wenn etwas in Wellen, Schleifen oder festen Abstaenden wiederkommt.".to_owned(),
                        ),
                        metric_hint(
                            "TRUST SCORE",
                            format!("{:.1}%", trust_score * 100.0),
                            if trust_score > 0.65 { green } else if trust_score > 0.4 { amber } else { red },
                            "fasst zusammen, wie tragfaehig das aktuelle Gesamtbild wirkt",
                            "Er steigt, wenn mehrere Werte in dieselbe Richtung deuten und wenig dagegen spricht.".to_owned(),
                        ),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("DYNAMIK UND SPUREN").size(10).color(dim),
                        text(format!("Musterkerne: {} | Innenruhe {:.0}%", anchor_count, stability * 100.0)).size(13).color(Color::WHITE),
                        text(format!("Veraenderung \u{0394}: {:.0}% | Rekonstruktion {:.0}%", delta_convergence * 100.0, reconstruction_quality * 100.0)).size(12).color(soft),
                        text(anchor_spark).size(10).color(Color::from_rgb8(0x9B, 0xD4, 0xFF)),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("I(h\u{209c})").size(10).color(dim),
                        text(format!("{:.4}", i_ht)).size(18).color(Color::from_rgb8(0xC0, 0xF0, 0xFF)),
                        text(make_sparkline(i_ht)).size(9).color(Color::from_rgb8(0x7B, 0x8F, 0xB3)),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("STABILITAET").size(10).color(dim),
                        text(format!("{:.1}%", stability * 100.0)).size(16).color(
                            if stability > 0.8 { green }
                            else if stability > 0.5 { amber }
                            else { red }
                        ),
                        progress_bar(0.0..=1.0, stability).height(5),
                        text(if self.structure_map_locked { "\u{25cf} Muster hat sich eingependelt" } else { "\u{25cc} Muster ist noch in Bewegung" })
                            .size(10)
                            .color(if self.structure_map_locked { green } else { dim }),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("VERLAUF").size(10).color(dim),
                        text(mut_spark).size(10).color(Color::from_rgb8(0xFF, 0xA5, 0x00)),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        // --- History-Eintraege je nach Sub-Tab (pre-computed above) ---
                        history_el,
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        button(text("EXPORT JSON").size(11))
                            .on_press(Message::FlowSphereExportPressed)
                            .padding([6, 12])
                            .style(|_: &Theme, _| button::Style {
                                background: Some(Background::Color(Color::from_rgb8(0x05, 0x28, 0x30))),
                                border: Border { color: Color::from_rgb8(0x8E, 0x5A, 0xF4), width: 1.0, radius: 4.0.into() },
                                text_color: Color::from_rgb8(0xB6, 0x8D, 0xFF),
                                ..Default::default()
                            }),
                    ]
                    .spacing(5)
                    .padding(12),
                )
                .height(Length::Fill),
            )
            .width(Length::Fixed(210.0))
            .height(Length::Fill)
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(panel_bg)),
                border: Border { color: Color::from_rgb8(0x0A, 0x28, 0x38), width: 1.0, radius: 0.0.into() },
                ..Default::default()
            })
        };

        // Timeline snapshots (up to 20 markers)
        let snap_count = (self.tick_counter / 60).min(20) as usize;
        let selected_snap = self.flow_sphere_snapshot_idx;
        let timeline: Vec<Element<'_, Message>> = (0..snap_count.max(1))
            .map(|i| {
                let is_sel = i == selected_snap;
                button(
                    text(if is_sel { "\u{25cf}" } else { "\u{25cb}" })
                        .size(14)
                        .color(if is_sel { cyan } else { dim }),
                )
                .on_press(Message::FlowSphereSnapshotSelected(i))
                .padding([2, 4])
                .style(move |_: &Theme, _| button::Style {
                    background: Some(Background::Color(if is_sel {
                        Color::from_rgba(0.59, 0.34, 0.96, 0.16)
                    } else {
                        Color::TRANSPARENT
                    })),
                    border: Border {
                        color: if is_sel { cyan } else { Color::TRANSPARENT },
                        width: if is_sel { 1.0 } else { 0.0 },
                        radius: 3.0.into(),
                    },
                    text_color: if is_sel { cyan } else { dim },
                    ..Default::default()
                })
                .into()
            })
            .collect();

        let timeline_row = container(
            Column::new()
                .push(text("TEMPORAL LAYER  \u{2500}  Session-Verlauf").size(10).color(dim))
                .push(Row::with_children(timeline).spacing(2))
                .spacing(4)
                .padding([6, 10]),
        )
        .width(Length::Fill)
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x03, 0x07, 0x0F))),
            border: Border { color: Color::from_rgb8(0x0A, 0x20, 0x30), width: 1.0, radius: 0.0.into() },
            ..Default::default()
        });

        let sphere_scene = FlowSphereScene {
            tick: self.tick_counter,
            entropy,
            stability,
            delta_phases,
            attractor_lons,
            info_growth,
            zoom: self.flow_sphere_zoom,
            manual_rotation_offset: self.flow_sphere_rotation_offset,
            view_mode: self.flow_sphere_view_mode,
            swarm_nodes,
            anomaly_level,
            external_link_strength,
            noether_consistency,
            active_focus_key: self.flow_sphere_focus_key.clone(),
            show_internal: self.flow_sphere_show_internal,
            show_external: self.flow_sphere_show_external,
            domain_names: self.flow_sphere_domain_names.clone(),
            broadcast_visible: self.flow_sphere_broadcast_visible.clone(),
        };

        let sphere_canvas = canvas::Canvas::new(sphere_scene)
            .width(Length::Fill)
            .height(Length::Fill);

        // Main layout
        let header = Row::new()
            .push(text("\u{25ce} FLOWSPHERE").size(13).color(view_accent))
            .push(text("  \u{00b7}  Muster sehen  \u{00b7}  Bewegung lesen  \u{00b7}  Auffaelligkeiten frueh erkennen").size(10).color(dim))
            .spacing(0);

        let anchor_input = |idx: usize| {
            let current = self
                .flow_sphere_domain_names
                .get(idx)
                .map(String::as_str)
                .unwrap_or("");
            text_input("optional: z.B. Word-Dokument oder Genomsequenz", current)
                .on_input(move |value| Message::FlowSphereDomainRename(idx, value))
                .padding([6, 8])
                .size(11)
                .width(Length::FillPortion(1))
        };

        let broadcast_panel: Element<'_, Message> = if let Some(proposal) = &self.flow_sphere_broadcast_proposal {
            Row::new()
                .push(container(text(format!("Anfrage: {}", proposal)).size(10).color(c(TEXT_H())))
                    .padding([8, 10])
                    .width(Length::Fill)
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgba(0.10, 0.16, 0.24, 0.92))),
                        border: Border { color: Color::from_rgba(0.35, 0.80, 0.92, 0.55), width: 1.0, radius: 8.0.into() },
                        ..Default::default()
                    }))
                .push(button(text("Zustimmen").size(11))
                    .on_press(Message::FlowSphereBroadcastApprove)
                    .padding([6, 10])
                    .style(primary_button_style))
                .push(button(text("Verwerfen").size(11))
                    .on_press(Message::FlowSphereBroadcastReject)
                    .padding([6, 10])
                    .style(secondary_button_style))
                .spacing(8)
                .align_y(Alignment::Center)
                .into()
        } else if let Some(visible) = &self.flow_sphere_broadcast_visible {
            {
                let already_outbound = self.flow_sphere_broadcast_outbound.as_deref() == Some(visible.as_str());
                let last_sent = self.flow_sphere_broadcast_last_sent_at.clone().unwrap_or_default();
                let outbound_note = if already_outbound && !last_sent.is_empty() {
                    format!("Outbound markiert: {}", last_sent)
                } else {
                    "Noch nicht outbound versendet.".to_owned()
                };
                let dispatch_button = if already_outbound {
                    button(text("Bereits outbound markiert").size(11))
                        .padding([6, 10])
                        .style(secondary_button_style)
                } else {
                    button(text("Swarm-Anfrage senden").size(11))
                        .on_press(Message::FlowSphereBroadcastDispatch)
                        .padding([6, 10])
                        .style(primary_button_style)
                };
                Row::new()
                    .push(container(column![
                            text(format!("Lokal freigegeben: {}", visible)).size(10).color(c(TEXT_H())),
                            text(outbound_note).size(10).color(soft),
                        ]
                        .spacing(4))
                        .padding([8, 10])
                        .width(Length::Fill)
                        .style(|_: &Theme| container::Style {
                            background: Some(Background::Color(Color::from_rgba(0.08, 0.18, 0.14, 0.92))),
                            border: Border { color: Color::from_rgba(0.30, 0.85, 0.45, 0.60), width: 1.0, radius: 8.0.into() },
                            ..Default::default()
                        }))
                    .push(dispatch_button)
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .into()
            }
        } else {
            text("Noch kein Broadcast sichtbar. Erst Vorschlag aus Analyse finden, dann Zustimmung geben.")
                .size(10)
                .color(soft)
                .into()
        };

        let interaction_bar = Row::new()
            .push(text("Ansicht:").size(11).color(dim))
            .push(button(text("Zoom +").size(11))
                .on_press(Message::FlowSphereZoomIn)
                .padding([5, 10])
                .style(secondary_button_style))
            .push(button(text("Zoom -").size(11))
                .on_press(Message::FlowSphereZoomOut)
                .padding([5, 10])
                .style(secondary_button_style))
            .push(button(text("Drehung links").size(11))
                .on_press(Message::FlowSphereRotateLeft)
                .padding([5, 10])
                .style(secondary_button_style))
            .push(button(text("Drehung rechts").size(11))
                .on_press(Message::FlowSphereRotateRight)
                .padding([5, 10])
                .style(secondary_button_style))
            .push(button(text("Reset").size(11))
                .on_press(Message::FlowSphereResetView)
                .padding([5, 10])
                .style(primary_button_style))
            .push(button(text(if self.flow_sphere_view_mode { "Lokalansicht" } else { "Globalansicht" }).size(11))
                .on_press(Message::FlowSphereToggleViewMode)
                .padding([5, 10])
                .style(secondary_button_style))
            .push(button(text(if self.flow_sphere_show_internal { "Intern an" } else { "Intern aus" }).size(11))
                .on_press(Message::FlowSphereToggleInternal)
                .padding([5, 10])
                .style(secondary_button_style))
            .push(button(text(if self.flow_sphere_show_external { "Extern an" } else { "Extern aus" }).size(11))
                .on_press(Message::FlowSphereToggleExternal)
                .padding([5, 10])
                .style(secondary_button_style))
            .push(iced::widget::Space::new(Length::Fill, Length::Shrink))
            .push(text(format!("Tick {}", self.tick_counter)).size(11).color(view_accent))
            .push(text(format!("Iterationen {}", self.structure_map_anchor_hist.len())).size(11).color(soft))
            .push(text(format!("Delta {:.0}%", delta_convergence * 100.0)).size(11).color(amber))
            .push(text(format!("Zoom {:.0}%", self.flow_sphere_zoom * 100.0)).size(11).color(c(TEXT_M())))
            .spacing(8)
            .align_y(Alignment::Center);

        let legend_chip = |title: &'static str, detail: &'static str, accent: Color| {
            container(
                column![
                    text(title).size(10).color(accent),
                    text(detail).size(10).color(soft),
                ]
                .spacing(3),
            )
            .padding([8, 10])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.09, 0.13, 0.19, 0.90))),
                border: Border { color: Color::from_rgba(accent.r, accent.g, accent.b, 0.55), width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
        };

        let legend_panel = Row::new()
            .push(legend_chip("Violette Baender", "Verteilungsdichte im Innenraum", Color::from_rgb8(0x9A, 0x67, 0xFF)))
            .push(legend_chip("Gruene Kerne", "stabile Verdichtungspunkte", Color::from_rgb8(0x4C, 0xD9, 0x6E)))
            .push(legend_chip("Goldpulse", "Ueberlagerung und Takt", Color::from_rgb8(0xFF, 0xD7, 0x00)))
            .push(legend_chip("Cyan-Orbit", "Peer-Verteilung und Aussenkopplung", Color::from_rgb8(0x7F, 0xD9, 0xFF)))
            .push(legend_chip("Rotmarker", "Bruch oder Stoerdruck", Color::from_rgb8(0xD9, 0x50, 0x50)))
            .spacing(8);

        let classification_panel = container(
            column![
                text("Anker haben keine Vorabbezeichnung. Du kannst sie nach einer Analyse nur grob benennen, zum Beispiel als Word-Dokument oder Genomsequenz.")
                    .size(11)
                    .color(dim),
                Row::new()
                    .push(anchor_input(0))
                    .push(anchor_input(1))
                    .push(anchor_input(2))
                    .spacing(8),
                Row::new()
                    .push(anchor_input(3))
                    .push(anchor_input(4))
                    .push(anchor_input(5))
                    .spacing(8),
                Row::new()
                    .push(button(text(if self.flow_sphere_broadcast_opt_in { "Broadcast freigegeben" } else { "Broadcast gesperrt" }).size(11))
                        .on_press(Message::FlowSphereBroadcastConsentToggled)
                        .padding([6, 10])
                        .style(secondary_button_style))
                    .push(button(text("Vorschlag finden").size(11))
                        .on_press(Message::FlowSphereBroadcastSuggest)
                        .padding([6, 10])
                        .style(secondary_button_style))
                    .push(text_input("optional: interessanten Aussenbezug als Broadcast-Vorschlag benennen", &self.flow_sphere_broadcast_name)
                        .on_input(Message::FlowSphereBroadcastNameChanged)
                        .padding([6, 8])
                        .size(11)
                        .width(Length::Fill))
                    .spacing(8)
                    .align_y(Alignment::Center),
                broadcast_panel,
                container(
                    column![
                        text(if broadcast_gate_ok { "Broadcast-Schwellen: erfuellt" } else { "Broadcast-Schwellen: noch nicht erfuellt" })
                            .size(10)
                            .color(if broadcast_gate_ok { green } else { amber }),
                        text(broadcast_gate_summary.clone()).size(10).color(c(TEXT_H())),
                        text(broadcast_gate_detail.clone()).size(10).color(dim),
                    ]
                    .spacing(3)
                )
                .padding([8, 10])
                .style(move |_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgba(0.08, 0.11, 0.16, 0.92))),
                    border: Border { color: if broadcast_gate_ok { green } else { amber }, width: 1.0, radius: 8.0.into() },
                    ..Default::default()
                }),
                text("Lokal oder Global waehlt die Leseperspektive. Intern und Extern schalten die Ebenen sichtbar. Broadcast bleibt bis zur Zustimmung rein lokal.")
                    .size(10)
                    .color(soft),
            ]
            .spacing(8),
        )
        .padding([10, 12])
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.08, 0.12, 0.18, 0.92))),
            border: Border { color: Color::from_rgba(view_accent.r, view_accent.g, view_accent.b, 0.55), width: 1.0, radius: 10.0.into() },
            ..Default::default()
        });

        let audit_chip = |title: &'static str, value: String, accent: Color| {
            container(
                column![
                    text(title).size(10).color(dim),
                    text(value).size(14).color(accent),
                ]
                .spacing(3),
            )
            .padding([8, 12])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.10, 0.14, 0.22, 0.82))),
                border: Border { color: accent, width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
        };

        let audit_row = Row::new()
            .push(audit_chip("DELTA", format!("{:.1}%", delta_convergence * 100.0), Color::from_rgb8(0xFF, 0xD7, 0x00)))
            .push(audit_chip("KOMPRESSION", format!("{:.1}%", compression_gain * 100.0), Color::from_rgb8(0x4C, 0xD9, 0x6E)))
            .push(audit_chip("REKONSTRUKTION", format!("{:.1}%", reconstruction_quality * 100.0), Color::from_rgb8(0x7F, 0xD9, 0xFF)))
            .push(audit_chip("AELAB-KOPPLUNG", format!("{:.1}%", aelab_coupling * 100.0), Color::from_rgb8(0xC0, 0x8D, 0xFF)))
            .spacing(8);

        let overview_row = Row::new()
            .push(
                container(summary_card(
                    "IM INNEREN",
                    internal_headline.to_owned(),
                    format!("Shannon {:.2} bit | Katz FD {:.2}", entropy * 7.83, katz_dimension),
                    cyan,
                ))
                .width(Length::FillPortion(1))
            )
            .push(
                container(summary_card(
                    "NACH AUSSEN",
                    external_headline.to_owned(),
                    if self.backend_swarm_node_count == 0 {
                        "Noch keine Aussenknoten fuer einen Vergleich sichtbar.".to_owned()
                    } else {
                        format!("{} Knoten | Verbindung {:.0}%", self.backend_swarm_node_count, external_link_strength * 100.0)
                    },
                    Color::from_rgb8(0x7F, 0xD9, 0xFF),
                ))
                .width(Length::FillPortion(1))
            )
            .push(
                container(summary_card(
                    "AUFFAELLIGKEITEN",
                    if anomaly_flags.is_empty() {
                        "Im Moment kein harter Bruch im Musterbild.".to_owned()
                    } else {
                        format!("{} Marker springen gerade ins Auge.", anomaly_flags.len())
                    },
                    if anomaly_flags.is_empty() {
                        format!("Benford {:.2} | Trust {:.0}%", benford_score, trust_score * 100.0)
                    } else {
                        anomaly_flags.join(", ")
                    },
                    if anomaly_level > 0.65 { red } else { amber },
                ))
                .width(Length::FillPortion(1))
            )
            .spacing(8);

        let focus_row = Row::new()
            .push(focus_button("Kernmuster", "internal_core", Color::from_rgb8(0x9A, 0x67, 0xFF)))
            .push(focus_button("Ueberlagerung", "overlay", Color::from_rgb8(0xFF, 0xC8, 0x3A)))
            .push(focus_button("Auffaelligkeit", "anomaly", Color::from_rgb8(0xE0, 0x5A, 0x5A)))
            .push(focus_button("Aussenbezug", "external_links", Color::from_rgb8(0x59, 0xD5, 0xE9)))
            .spacing(8);

        let broadcast_gate_preview = if self.flow_sphere_broadcast_proposal.is_some() {
            "Vorschau: Die Analyse hat einen Broadcast-Vorschlag gefunden, wartet aber noch auf deine Zustimmung.".to_owned()
        } else if self.flow_sphere_broadcast_outbound.is_some() {
            "Vorschau: Eine explizit freigegebene Broadcast-Anfrage wurde als outbound markiert; Kontakt bleibt trotzdem ein separater Zustimmungspfad.".to_owned()
        } else if self.flow_sphere_broadcast_visible.is_some() {
            "Vorschau: Ein Broadcast ist lokal freigegeben, aber noch nicht als outbound Anfrage versendet.".to_owned()
        } else {
            broadcast_gate_detail.clone()
        };

        let focus_panel = container(
            Row::new()
                .push(
                    container(text("\u{25cf}").size(26).color(focus_accent))
                        .width(Length::Fixed(24.0))
                )
                .push(
                    column![
                        text(format!("ANGEKLICKT: {}", focus_title)).size(11).color(soft),
                        text(focus_summary).size(15).color(c(TEXT_H())),
                        text(focus_detail).size(11).color(dim),
                        text(broadcast_gate_summary.clone()).size(10).color(if broadcast_gate_ok { Color::from_rgb8(0x7F, 0xD9, 0xFF) } else { amber }),
                        text(broadcast_gate_preview)
                        .size(10)
                        .color(soft),
                        text("Tipp: Farbchips oder Knoten direkt anklicken, um den Fokus zu wechseln.").size(10).color(soft),
                    ]
                    .spacing(4)
                )
                .spacing(10)
                .align_y(Alignment::Start),
        )
        .padding([10, 12])
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.07, 0.11, 0.17, 0.95))),
            border: Border { color: focus_accent, width: 1.2, radius: 10.0.into() },
            ..Default::default()
        });

        container(
            Column::new()
                .push(header)
                .push(interaction_bar)
                .push(legend_panel)
                .push(overview_row)
                .push(focus_row)
                .push(focus_panel)
                .push(classification_panel)
                .push(audit_row)
                .push(
                    text(format!(
                        "Sichtbarer Pfad: {}{}",
                        reconstruction_path,
                        if self.live_render_mode {
                            " | Live Render bewegt nur die Ansicht, nicht die Wertekarte."
                        } else {
                            ""
                        }
                    ))
                    .size(11)
                    .color(dim)
                )
                .push(text(if self.flow_sphere_view_mode {
                    "Lokalansicht: zeigt Anker, Verdichtung, Musterkerne und Bruchstellen im aktuellen Bereich."
                } else {
                    "Globalansicht: zeigt externe Verbindungen, Drift, zustimmbare Broadcast-Hinweise und Beziehungen ueber Bereichsgrenzen hinweg."
                })
                    .size(11)
                    .color(dim))
                .push(Row::new()
                    .push(sphere_canvas)
                    .push(ht_panel)
                    .height(Length::Fill))
                .push(timeline_row)
                .spacing(8)
                .height(Length::Fill),
        )
        .padding(10)
        .width(Length::Fill)
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(surf_bg)),
            ..Default::default()
        })
        .into()
    }

    fn view_delta_convergence(&self) -> Element<'_, Message> {
        let panel_s = Color::from_rgb8(0x05, 0x10, 0x1C);
        let cyan    = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let red     = Color::from_rgb8(0xD9, 0x50, 0x50);
        let green   = Color::from_rgb8(0x4C, 0xD9, 0x6E);
        let dim     = Color::from_rgb8(0x50, 0x6A, 0x7A);
        let amber   = Color::from_rgb8(0xD4, 0xA0, 0x42);

        let metric_help_panel = container(
            column![
                text("Metriken direkt erklaeren").size(14).color(c(TEXT_H())),
                Row::new()
                    .push(metric_help_chip("Entropie", "ENTROPY", cyan))
                    .push(metric_help_chip("Periodizitaet", "PERIODICITY", amber))
                    .push(metric_help_chip("Zipf", "ZIPF", Color::from_rgb8(0x7F, 0xD9, 0xFF)))
                    .push(metric_help_chip("Benford", "BENFORD", Color::from_rgb8(0xC0, 0x8D, 0xFF)))
                    .spacing(8),
                Row::new()
                    .push(metric_help_chip("Katz FD", "KATZ", amber))
                    .push(metric_help_chip("Noether", "NOETHER", green))
                    .push(metric_help_chip("Delta Ratio", "DELTA", red))
                    .push(metric_help_chip("Coherence", "COHERENCE", green))
                    .push(metric_help_chip("Kompression", "COMPRESSION", cyan))
                    .spacing(8),
            ]
            .spacing(8)
        )
        .padding([10, 12])
        .style(panel_frame_style);

        let capsule_panel = if let Some(capsule) = &self.capsule_state {
            let mut rows = column![
                text(format!("source: {}", capsule.source_label)).size(14).color(cyan),
                text(format!("trigger: {} | type: {} | domain: {}", capsule.trigger, capsule.source_type, capsule.domain_hint)).size(13).color(dim),
                text(format!("scope: {} | privacy: {} | artifact: {} | segments: {}", capsule.source_scope, capsule.privacy_class, capsule.artifact_class, capsule.segment_count)).size(13).color(dim),
                text(format!("Trust Score: {:.3}", capsule.trust_score)).size(16).color(if capsule.trust_score > 0.65 { green } else { red }),
                text(format!("Entropy: {:.4}", capsule.entropy)).size(14).color(dim),
                text(format!("H_lambda: {:.4}", capsule.h_lambda)).size(14).color(dim),
                text(format!("Symmetry: {:.4}", capsule.symmetry)).size(14).color(dim),
                text(format!("Periodicity: {:.4}", capsule.periodicity)).size(14).color(dim),
                text(format!("Zipf Alpha: {:.4}", capsule.zipf_alpha)).size(14).color(dim),
                text(format!("Benford Score: {:.4}", capsule.benford_score)).size(14).color(dim),
                text(format!("Katz Dimension: {:.4}", capsule.katz_dimension)).size(14).color(dim),
                text(format!("SCE Score: {:.4}", capsule.sce_score)).size(14).color(dim),
                text(format!("Bayes Confidence: {:.4}", capsule.bayes_confidence)).size(14).color(dim),
                text(format!("Noether Consistency: {:.4}", capsule.noether_consistency)).size(14).color(dim),
                text(format!("Delta Ratio: {:.4} | Changed Bytes: {}", capsule.delta_ratio, capsule.changed_bytes)).size(14).color(dim),
            ];
            if !capsule.segment_manifest_hash.is_empty() {
                let short_manifest: String = capsule.segment_manifest_hash.chars().take(16).collect();
                rows = rows.push(text(format!("segment manifest: {}", short_manifest)).size(13).color(dim));
            }
            if !capsule.anomaly_flags.is_empty() {
                let flags = capsule.anomaly_flags.join(", ");
                rows = rows.push(text(format!("Anomalies: {}", flags)).size(14).color(red));
            }
            ade_subpanel("CAPSULE · DETERMINISTIC AUDIT", rows.into(), panel_s)
        } else {
            ade_subpanel("CAPSULE · DETERMINISTIC AUDIT", text("No capsule result available").size(13).color(dim).into(), panel_s)
        };

        let structure_map_panel = if let Some(state) = &self.structure_map_state {
            let rows = column![
                text(format!("region: {}", state.region_label)).size(14).color(cyan),
                text(format!("nodes: {} | edges: {}", state.node_count, state.edge_count)).size(14).color(dim),
                text(format!("anchors: {} | anomalies: {}", state.anchor_count, state.anomaly_count)).size(14).color(dim),
                text(format!("coherence: {:.4} | trust: {:.4}", state.coherence_score, state.trust_score)).size(14).color(dim),
                text(format!("locked: {}", if state.locked { "yes" } else { "no" })).size(14).color(if state.locked { green } else { dim }),
            ];
            ade_subpanel("STRUCTURE MAP · SNAPSHOT", rows.into(), panel_s)
        } else {
            ade_subpanel("STRUCTURE MAP · SNAPSHOT", text("No structure-map snapshot available").size(13).color(dim).into(), panel_s)
        };

        let aelab_panel = if let Some(aelab) = &self.aelab_state {
            let signature_preview: String = aelab.signature.chars().take(16).collect();
            let seed_preview = if aelab.seed_label.is_empty() {
                "no active seed".to_owned()
            } else {
                format!("{} | {} | used {}x", aelab.seed_label, aelab.seed_bucket, aelab.seed_times_used)
            };
            let operator_flags = [
                if aelab.has_sequence { "sequence" } else { "-" },
                if aelab.has_bridge { "bridge" } else { "-" },
                if aelab.has_xor { "xor" } else { "-" },
                if aelab.has_interfere { "interfere" } else { "-" },
            ]
            .join(" | ");
            let rows = column![
                text(format!("fitness: {:.4} | lossless: {:.1}%", aelab.fitness, aelab.lossless * 100.0)).size(14).color(cyan),
                // "operators / depth" = AE-Baum-Schritte — KEINE Netz-Nodes (Nodes = User im System)
                text(format!("operators: {} | depth: {} | anchor: {} | evolved: {}", aelab.nodes, aelab.depth, aelab.has_anchor, aelab.evolved)).size(14).color(dim),
                text(format!("seed: {}", seed_preview)).size(13).color(dim),
                text(format!("coupling: {:.3} | coherence: {:.3} | utility: {:.3}", aelab.seed_coupling, aelab.seed_coherence, aelab.seed_utility)).size(13).color(dim),
                text(format!("ops: {}", operator_flags)).size(13).color(dim),
                text(format!("vault main/inactive/recovered: {}/{}/{}", aelab.vault_main_entries, aelab.vault_inactive_entries, aelab.vault_recovered_entries)).size(13).color(dim),
                text(format!("vault total: {} | integrity: {}", aelab.vault_total_entries, if aelab.vault_integrity_ok { "ok" } else { "check" })).size(13).color(if aelab.vault_integrity_ok { green } else { red }),
                text(format!("vault root: {}", aelab.vault_root)).size(12).color(dim),
                text(format!("signature: {}", signature_preview)).size(12).color(dim),
            ];
            ade_subpanel("AELAB · MOTOR / VAULT COUPLING", rows.into(), panel_s)
        } else {
            ade_subpanel("AELAB · MOTOR / VAULT COUPLING", text("No AELab coupling available yet").size(13).color(dim).into(), panel_s)
        };

        let compression_panel = if let Some(compression) = &self.compression_state {
            let rows = column![
                text(format!("format: {}", compression.format)).size(14).color(cyan),
                text(format!("original: {} B | changed: {} B", compression.original_bytes, compression.changed_bytes)).size(14).color(dim),
                text(format!("compressed: {} B | ratio: {:.4}", compression.compressed_bytes, compression.ratio)).size(14).color(dim),
                text(format!("gain: {:.2}%", compression.gain_percent)).size(16).color(if compression.gain_percent > 0.0 { green } else { dim }),
            ];
            ade_subpanel("COMPRESSION · AUDIT", rows.into(), panel_s)
        } else {
            ade_subpanel("COMPRESSION · AUDIT", text("No compression summary available").size(13).color(dim).into(), panel_s)
        };

        let reconstruction_panel = if let Some(reconstruction) = &self.reconstruction_state {
            let path_text = if reconstruction.path_steps.is_empty() {
                "capsule.metrics -> structure_map.snapshot".to_owned()
            } else {
                reconstruction.path_steps.join(" -> ")
            };
            let error_text = if reconstruction.error_fields.is_empty() {
                "none".to_owned()
            } else {
                reconstruction.error_fields.join(", ")
            };
            let rows = column![
                text(format!("quality: {:.2}% | verified: {}", reconstruction.quality_score * 100.0, reconstruction.verified)).size(14).color(if reconstruction.verified { green } else { red }),
                text(format!("compressibility: {:.2}% | anchor coverage: {:.2}%", reconstruction.compressibility * 100.0, reconstruction.anchor_coverage * 100.0)).size(13).color(dim),
                text(format!("error count: {} | fields: {}", reconstruction.error_count, error_text)).size(13).color(dim),
                text(format!("path: {}", path_text)).size(13).color(cyan),
            ];
            ade_subpanel("RECONSTRUCTION · PATH", rows.into(), panel_s)
        } else {
            ade_subpanel("RECONSTRUCTION · PATH", text("No reconstruction audit available").size(13).color(dim).into(), panel_s)
        };

        let lineage_panel = {
            let delta_value = self
                .cascade_metrics
                .as_ref()
                .map(|metrics| metrics.delta_convergence * 100.0)
                .unwrap_or(0.0);
            let lineage = if let Some(reconstruction) = &self.reconstruction_state {
                if reconstruction.path_steps.is_empty() {
                    "capsule.metrics -> structure_map.snapshot -> operator review".to_owned()
                } else {
                    reconstruction.path_steps.join(" -> ")
                }
            } else {
                "capsule.metrics -> structure_map.snapshot -> operator review".to_owned()
            };
            let rows = column![
                text(format!("lineage: {}", lineage)).size(13).color(cyan),
                text(format!("delta convergence: {:.2}% | flow lock: {}", delta_value, self.structure_map_locked)).size(13).color(dim),
                text(if self.live_render_mode {
                    "Live Render updates the audit metrics in place and keeps the shell layout fixed."
                } else {
                    "Live Render is off; file drops remain the current deterministic source of truth."
                })
                .size(13)
                .color(dim),
            ];
            ade_subpanel("AUDIT CHAIN · DETERMINISTIC LINEAGE", rows.into(), panel_s)
        };

        // ── VIER THEORETISCHE LIMITS · Shannon / Kolmogorov / MDL / TDL ──────
        // Rein observational — kein Einfluss auf Analyse-Pipeline, Trust-Score oder
        // delta_ratio. Alles wird aus bereits berechneten Werten abgelesen.
        let ipe_panel = {
            let bpj = self.live_render_bits_per_joule;
            let bpj_history = &self.live_render_bpj_history;

            // ── Shannon-Limit-Annäherung aus Capsule ────────────────────────
            let (h_lambda, shannon_limit, shannon_gap_pct) = if let Some(cap) = &self.capsule_state {
                let gap = if cap.entropy > 0.0 {
                    ((cap.h_lambda - cap.entropy * 0.15) / cap.entropy * 100.0).max(0.0)
                } else { 0.0 };
                (cap.h_lambda, cap.entropy * 0.15, gap)
            } else {
                (0.0_f32, 0.0_f32, 100.0_f32)
            };

            // ── Kolmogorov-Proxy aus sce_signature ─────────────────────────
            let kolmogorov_k = self.capsule_state.as_ref().map(|c| c.kolmogorov_k).unwrap_or(0.0);

            // ── MDL: Modellabdeckung (AnchorPack/DeltaPack) ─────────────────
            // MDL-Kosten = L(Modell) + L(Rest) = anchor_coverage_ratio + delta_ratio
            // Minimum wenn anchor_coverage_ratio → 1 und delta_ratio → 0
            let mdl_model_cov = self.capsule_state.as_ref().map(|c| c.anchor_coverage_ratio).unwrap_or(0.0);
            let mdl_residual = self.capsule_state.as_ref().map(|c| c.delta_ratio).unwrap_or(1.0);
            let mdl_total = (mdl_model_cov + mdl_residual).min(2.0); // normaliert auf [0,2]

            // ── TDL: Thermodynamische Tiefe (Bits/Joule → Landauer-Grenze) ─
            // Landauer-Limit bei 300K: ~2.9 × 10^-21 J/bit → ~3.4 × 10^20 bit/J
            // Wir zeigen relativen Abstand (wir sind noch weit entfernt, aber der Trend zählt)
            let bpj_str = if bpj >= 1_000_000.0 {
                format!("{:.2} Mb/J", bpj / 1_000_000.0)
            } else if bpj >= 1_000.0 {
                format!("{:.1} kb/J", bpj / 1_000.0)
            } else if bpj > 0.0 {
                format!("{:.0} b/J", bpj)
            } else {
                "\u{2014} b/J".to_owned()
            };

            // IPE-Trend aus Rolling-History
            let (ipe_slope, ipe_trend) = if bpj_history.len() >= 4 {
                let n = bpj_history.len();
                let x_mean = (n as f32 - 1.0) / 2.0;
                let y_mean: f32 = bpj_history.iter().sum::<f32>() / n as f32;
                let num: f32 = bpj_history.iter().enumerate()
                    .map(|(i, v)| (i as f32 - x_mean) * (v - y_mean)).sum();
                let den: f32 = bpj_history.iter().enumerate()
                    .map(|(i, _)| (i as f32 - x_mean).powi(2)).sum();
                let slope = if den > 0.0 { num / den } else { 0.0 };
                let label = if slope > 1000.0 { "IMPROVING \u{2191}\u{2191}" }
                    else if slope > 100.0 { "IMPROVING \u{2191}" }
                    else if slope < -1000.0 { "DEGRADING \u{2193}" }
                    else { "STABLE \u{2192}" };
                (slope, label)
            } else {
                (0.0_f32, "collecting\u{2026}")
            };

            let _delta_ratio_now = self.live_render_last_delta_ratio;

            let rows = column![
                // Kopfzeile
                text("Das System n\u{00e4}hert sich gleichzeitig vier theoretischen Grenzen.")
                    .size(12).color(dim),

                // Trennlinie: Shannon
                text("\u{25b6}  SHANNON-LIMIT  \u{2014}  H_\u{03bb}(X, M_t) \u{2192} H_min(X)")
                    .size(13).color(cyan),
                row![
                    text("H\u{03bb} (Restunsicherheit):").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(format!("{:.4} bit/byte", h_lambda)).size(13).color(amber),
                    text(format!("  Limit: {:.4}", shannon_limit)).size(12).color(dim),
                ].spacing(8),
                row![
                    text("Abstand zum Shannon-Limit:").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(format!("{:.2}%", shannon_gap_pct)).size(13)
                        .color(if shannon_gap_pct < 10.0 { green } else if shannon_gap_pct < 40.0 { amber } else { red }),
                    text("  (0% = Shannon-Limit erreicht)").size(11).color(dim),
                ].spacing(8),

                // Trennlinie: Kolmogorov
                text("\u{25b6}  KOLMOGOROV-KOMPLEXITÄT  \u{2014}  K(X) via zlib-Proxy")
                    .size(13).color(cyan),
                row![
                    text("Komprimierbarkeit K:").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(format!("{:.4}", kolmogorov_k)).size(13)
                        .color(if kolmogorov_k > 0.7 { green } else if kolmogorov_k > 0.4 { amber } else { dim }),
                    text("  (1.0 = maximal strukturiert / minimale Beschreibung)").size(11).color(dim),
                ].spacing(8),
                row![
                    // "Operatoren" = AE-Baum-Knoten (Algorithmus-Schritte), NICHT User-Nodes
                    text("AE-Programm (Operatoren):").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(if let Some(ae) = &self.aelab_state {
                        format!("{} Ops, Tiefe {} | fitness {:.4} | lossless {:.1}%",
                            ae.nodes, ae.depth, ae.fitness, ae.lossless * 100.0)
                    } else {
                        "\u{2014}".to_owned()
                    }).size(13).color(amber),
                ].spacing(8),
                row![
                    text("").width(Length::Fixed(240.0)),
                    text(if let Some(ae) = &self.aelab_state {
                        format!("evolved: {} | anchor: {} | ops: {}{}{}{}",
                            ae.evolved, ae.has_anchor,
                            if ae.has_sequence { "seq " } else { "" },
                            if ae.has_bridge { "bridge " } else { "" },
                            if ae.has_xor { "xor " } else { "" },
                            if ae.has_interfere { "interfere" } else { "" })
                    } else { "\u{2014}".to_owned() }).size(11).color(dim),
                ].spacing(8),

                row![
                    text("").width(Length::Fixed(240.0)),
                    text("(weniger Ops + gleiche Fitness = näher an K-Minimum)").size(11).color(dim),
                ].spacing(8),

                // Trennlinie: Gödel-Selbstreferenz
                text("\u{25b6}  GÖDEL-SELBSTREFERENZ  \u{2014}  Probe: Signal \u{2192} Metrik \u{2192} Signal \u{2192} \u{2026}")
                    .size(13).color(cyan),
                text("Iterativer Fixpunkt-Test: konvergiert das System wenn es sich selbst beschreibt?")
                    .size(11).color(dim),
                row![
                    text("Gödel-Probe Tiefe:").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(if self.live_render_mode {
                        format!("{} / 3", self.live_render_last_godel_level)
                    } else {
                        "\u{2014}".to_owned()
                    }).size(13)
                        .color(if self.live_render_last_godel_level < 3 { green }
                               else { amber }),
                    text(if self.live_render_mode && self.live_render_last_godel_level < 3 {
                        "  \u{2713} Fixpunkt erreicht (nat\u{00fc}rliche Konvergenz)"
                    } else if self.live_render_mode {
                        "  \u{26a0} max_depth erzwungen (Gödel-Rest > 0)"
                    } else {
                        "  (Live Render inaktiv)"
                    }).size(11).color(dim),
                ].spacing(8),
                row![
                    text("Konvergenz-Delta:").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(if self.live_render_mode {
                        format!("{:.2}%", self.live_render_last_godel_delta)
                    } else {
                        "\u{2014}".to_owned()
                    }).size(13)
                        .color(if self.live_render_last_godel_delta < 1.0 { green }
                               else if self.live_render_last_godel_delta < 5.0 { amber }
                               else { red }),
                    text("  (< 1% = Fixpunkt, System beschreibt sich stabil selbst)").size(11).color(dim),
                ].spacing(8),
                row![
                    text("Gödelstop (äußere Schleife):").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(if self.live_render_godel_stop_skip > 0 {
                        format!("AKTIV (skip-zähler={})", self.live_render_godel_stop_skip)
                    } else {
                        "inaktiv".to_owned()
                    }).size(13)
                        .color(if self.live_render_godel_stop_skip > 0 { green } else { dim }),
                    text("  (verhindert endlose Selbstanalyse wenn Signal stabil)").size(11).color(dim),
                ].spacing(8),

                // Trennlinie: MDL
                text("\u{25b6}  MDL  \u{2014}  L(Modell) + L(Daten|Modell) \u{2192} Minimum")
                    .size(13).color(cyan),
                row![
                    text("Modell-Abdeckung (AnchorPack):").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(format!("{:.2}%", mdl_model_cov * 100.0)).size(13)
                        .color(if mdl_model_cov > 0.85 { green } else if mdl_model_cov > 0.5 { amber } else { dim }),
                ].spacing(8),
                row![
                    text("Residual (DeltaPack / delta_ratio):").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(format!("{:.4}", mdl_residual)).size(13)
                        .color(if mdl_residual < 0.2 { green } else if mdl_residual < 0.6 { amber } else { red }),
                    text("  (MDL-Minimum: Modell erkl\u{00e4}rt alles, Residual = 0)").size(11).color(dim),
                ].spacing(8),
                row![
                    text("MDL-Gesamtkosten:").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(format!("{:.4} / 2.0", mdl_total)).size(13)
                        .color(if mdl_total < 1.2 { green } else if mdl_total < 1.6 { amber } else { red }),
                    text("  (L(Modell) + L(Rest) \u{2192} 0 ideal)").size(11).color(dim),
                ].spacing(8),

                // Trennlinie: TDL (Thermodynamic Depth)
                text("\u{25b6}  TDL \u{2014} THERMODYNAMISCHE TIEFE  \u{2014}  Bits / Joule \u{2192} Landauer-Grenze")
                    .size(13).color(cyan),
                row![
                    text("Bits / Joule (live):").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(bpj_str).size(14).color(if bpj > 10_000.0 { green } else if bpj > 1_000.0 { amber } else { dim }),
                ].spacing(8),
                row![
                    text("IPE-Trend:").size(13).color(dim).width(Length::Fixed(240.0)),
                    text(ipe_trend).size(13)
                        .color(if ipe_slope > 100.0 { green } else if ipe_slope < -100.0 { red } else { amber }),
                    text(format!("  (slope {:.0} b/J per tick)", ipe_slope)).size(11).color(dim),
                ].spacing(8),

                // Footer
                text("Alle Werte werden aus bereits berechneten Metriken abgelesen. Pipeline und Trust-Score sind davon v\u{00f6}llig unabh\u{00e4}ngig.")
                    .size(11).color(dim),
            ].spacing(6);
            ade_subpanel("VIER LIMITS \u{b7} SHANNON / KOLMOGOROV / MDL / TDL \u{2014} OBSERVATIONAL", rows.into(), panel_s)
        };

        let main_content = scrollable(
            column![
                metric_help_panel,
                capsule_panel,
                structure_map_panel,
                aelab_panel,
                compression_panel,
                reconstruction_panel,
                lineage_panel,
                ipe_panel,
            ]
            .spacing(12)
            .padding([0.0f32, 8.0]),
        );

        main_content.into()
    }

    fn view_ade(&self) -> Element<'_, Message> {
        let panel_s  = Color::from_rgb8(0x05, 0x10, 0x1C);
        let accent   = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let green    = Color::from_rgb8(0x4C, 0xD9, 0x6E);
        let warn     = Color::from_rgb8(0xD4, 0xA0, 0x42);
        let dim      = Color::from_rgb8(0x50, 0x6A, 0x7A);
        let mid      = Color::from_rgb8(0xA8, 0xC4, 0xD8);

        // ── helper: renders a single use-case card ───────────────────────────
        // layout: coloured heading, scenario line, then labelled metric rows
        let scenario_card = |
            heading: &'static str,
            heading_color: Color,
            scenario: &'static str,
            rows: Vec<(&'static str, &'static str, Color)>,
            note: &'static str,
        | -> Element<'_, Message> {
            let mut col = Column::new()
                .push(text(heading).size(14).color(heading_color))
                .push(text(scenario).size(12).color(mid))
                .spacing(6);
            for (label, value, color) in rows {
                col = col.push(
                    row![
                        text(label).size(12).color(dim).width(Length::Fixed(190.0)),
                        text(value).size(12).color(color),
                    ]
                    .spacing(8),
                );
            }
            if !note.is_empty() {
                col = col.push(text(note).size(11).color(dim));
            }
            container(col.spacing(4))
                .style(move |_: &Theme| container::Style {
                    background: Some(Background::Color(panel_s)),
                    border: Border { color: c(BORDER()), width: 1.0, radius: 8.0.into() },
                    ..Default::default()
                })
                .padding(14)
                .width(Length::Fill)
                .into()
        };

        // ── intro header ─────────────────────────────────────────────────────
        let intro = ade_subpanel(
            "DELTA-ANALYSE \u{b7} STRUKTURELLE METRIKEN \u{2014} THEORIE UND ANWENDUNG",
            column![
                text("Jede Datei erzeugt eine Kapsel mit strukturellen Messwerten. Diese Metriken sind signalagnostisch \u{2014} sie sagen nichts \u{fc}ber den Inhalt, aber sehr viel \u{fc}ber die Struktur. Das er\u{f6}ffnet ein breites Anwendungsspektrum.").size(13).color(mid),
                text("Alle Beispiele sind synthetisch \u{2014} keine echten Personendaten.").size(11).color(dim),
            ].spacing(6).into(),
            panel_s,
        );

        // ── capabilities overview ─────────────────────────────────────────────
        let uc_overview = ade_subpanel(
            "THEORETISCHES ANWENDUNGSSPEKTRUM DER METRIKEN",
            column![
                text("Diese Metriken k\u{f6}nnen \u{2014} einzeln oder kombiniert \u{2014} folgende Klassen von Ph\u{e4}nomenen sichtbar machen:").size(13).color(mid),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Manipulation & F\u{e4}lschung \u{2014} absichtliche Ver\u{e4}nderung von Dateiinhalten, auch wenn Dateigr\u{f6}\u{df}e identisch bleibt").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Ausrei\u{df}er-Erkennung \u{2014} einzelne Dateien/Datens\u{e4}tze die strukturell aus einer Menge herausfallen (defekte Sensoren, Glitches, Batch-Fehler)").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Strukturelle Anomalien \u{2014} Diskontinuit\u{e4}ten, Symmetriebrueche, Entropiespr\u{fc}nge die auf Format-Fehler, Korruption oder unerwartete \u{c4}nderungen hinweisen").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Software-Regression \u{2014} unbeabsichtigte \u{c4}nderungen in Build-Artefakten (Debug-Symbole, Supply-Chain, Abh\u{e4}ngigkeits-Drift)").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Log-Gesundheit & Schleifen \u{2014} Feedback-Loops, Stuck-Processes, Injection in Log-Streams erkennbar ohne eine Zeile zu lesen").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Informationsverlust \u{2014} ob eine Konvertierung (OCR, Transkodierung, Kompression) strukturell verlustfrei war oder Signifikanz vernichtet hat").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Synthetische & KI-generierte Inhalte \u{2014} LLM-Text, synthetische Datens\u{e4}tze und maschinell generierte Bin\u{e4}rdaten hinterlassen strukturelle Signaturen").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Wissenschaftliche Reproduzierbarkeit \u{2014} ob zwei Versionen eines Datensatzes wirklich identisch sind oder ob zwischen Archiven Drift entstanden ist").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Kryptographische Anomalien \u{2014} ob ein Dateiabschnitt echte Verschl\u{fc}sselung, schwache Verschl\u{fc}sselung oder Steganographie aufweist (Entropie-Profil per Segment)").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                row![
                    text("\u{25aa}").size(12).color(accent).width(Length::Fixed(14.0)),
                    text("Firmware & Embedded-Integrit\u{e4}t \u{2014} IoT-Firmware gegen signierte Baseline; Sektionsprofil (Bootloader vs. Payload) strukturell messbar").size(12).color(mid),
                ].spacing(4).align_y(Alignment::Start),
                text("Entscheidend ist immer die Kombination: keine einzelne Metrik ist ein Beweis. Ihre Signaturmuster zusammen erzeugen das Signal.").size(12).color(dim),
            ].spacing(7).into(),
            panel_s,
        );

        // ── use case 1: ausreißer in sensor-/zeitreihendaten ─────────────────
        let uc_outlier = ade_subpanel(
            "FALLBEISPIEL 1 \u{b7} AUSREI\u{df}ER IN ZEITREIHENDATEN (SENSOR-BATCH)",
            column![
                text("Szenario: 30 CSV-Dateien einer Fertigungsanlage, jede enth\u{e4}lt Temperatur- und Druckmesswerte eines Tages. 29 Dateien sind unauf\u{e4}llig \u{2014} zwei zeigen Sensor-Fehlerbilder. Kein Betrug, keine Manipulation \u{2014} einfache Hardware-Ausrei\u{df}er, erkennbar in Sekunden \u{fc}ber Metriken ohne jeden Messwert manuell zu pr\u{fc}fen.").size(12).color(mid),
            ].spacing(6)
            .push(scenario_card(
                "Normale Messtage (Referenz-Profil)",
                green,
                "sensor_tag_001.csv bis sensor_tag_012.csv \u{b7} je ~180 kB",
                vec![
                    ("Entropie",             "3.4\u{2013}3.7 bit/byte \u{b7} typisch f\u{fc}r Dezimalzahlen in CSV", mid),
                    ("Noether Consistency",  "0.91\u{2013}0.96 \u{b7} saisonale und maschinenzyklische Symmetrie erhalten", green),
                    ("Periodizit\u{e4}t",    "0.30\u{2013}0.45 \u{b7} moderate Periode durch Maschinenzyklen", mid),
                    ("Benford Score",        "0.88\u{2013}0.95 \u{b7} Messwerte folgen nat\u{fc}rlicher Ziffernverteilung", green),
                    ("Anomaly Flags",        "(keine)", dim),
                ],
                "",
            ))
            .push(scenario_card(
                "Ausrei\u{df}er: Stuck-at-Fault (Sensor liefert Konstantwert)",
                warn,
                "sensor_tag_014.csv \u{b7} 42 kB",
                vec![
                    ("Entropie",             "0.31 bit/byte \u{b7} extrem niedrig \u{2014} Sensor liefert dieselbe Zahl in jeder Zeile", warn),
                    ("Noether Consistency",  "0.04 \u{b7} Symmetrie komplett aufgel\u{f6}st \u{2014} keine Variation mehr", warn),
                    ("Periodizit\u{e4}t",    "0.99 \u{b7} maximale Wiederholung \u{2014} identische Zeilen", warn),
                    ("Benford Score",        "0.12 \u{b7} eine Ziffer dominiert alles", warn),
                    ("Anomaly Flags",        "stuck_signal, zero_variance, benford_deviation", warn),
                ],
                "Kein Angriff \u{2014} einfach ein defekter Sensor. Dieser Dateityp f\u{e4}llt im Batch sofort durch extrem niedrige Entropie + maximale Periodizit\u{e4}t heraus.",
            ))
            .push(scenario_card(
                "Ausrei\u{df}er: Impuls-Glitch (Spike-Fault)",
                accent,
                "sensor_tag_022.csv \u{b7} 181 kB",
                vec![
                    ("Entropie",             "4.12 bit/byte \u{b7} h\u{f6}her als Referenz \u{2014} Spikes erh\u{f6}hen Zuf\u{e4}lligkeit lokal", accent),
                    ("Noether Consistency",  "0.54 \u{b7} teil-gebrochen \u{2014} lokale Diskontinuit\u{e4}t in einzelnen Bl\u{f6}cken", accent),
                    ("Periodizit\u{e4}t",    "0.38 \u{b7} normal \u{2014} kein globales Muster gest\u{f6}rt", mid),
                    ("Delta Ratio",          "0.03 \u{b7} zum Vortags-Log \u{2014} kleine Byte-Menge, aber strukturell abweichend", accent),
                    ("Anomaly Flags",        "entropy_spike, noether_local_break", accent),
                ],
                "Impuls-Glitches sind schwerer erkennbar als Stuck-Faults. Der Noether-Abfall in Kombination mit gestiegener Entropie zeigt, dass einzelne Bl\u{f6}cke aus dem Rahmen fallen. Delta-Vergleich zum Referenztag isoliert die betroffenen Segmente.",
            ))
            .spacing(8)
            .into(),
            panel_s,
        );

        // ── use case 2: manipulation / datenverfälschung ──────────────────────
        let uc_tamper = ade_subpanel(
            "FALLBEISPIEL 2 \u{b7} MANIPULATION UND DATEI-VERF\u{c4}LSCHUNG",
            column![
                text("Szenario: Die offizielle ausf\u{fc}hrbare Datei eines bekannten Tools und eine Kopie aus einer Drittquelle. Der Strukturvergleich zeigt Abweichungen \u{2014} ohne den Quellcode zu kennen, ohne die Datei auszuf\u{fc}hren.").size(12).color(mid),
            ].spacing(6)
            .push(scenario_card(
                "Original (Referenz)",
                green,
                "setup.exe \u{b7} 3,2 MB \u{b7} Hersteller-Download",
                vec![
                    ("Entropie",             "6.12 bit/byte \u{b7} normal f\u{fc}r komprimierte Bin\u{e4}rdatei", mid),
                    ("Delta Ratio",          "0.000 \u{b7} kein bekannter Ver\u{e4}nderungspfad", dim),
                    ("Trust Score",          "0.82 \u{b7} hohe Strukturkonsistenz", green),
                    ("Noether Consistency",  "0.978 \u{b7} Blockstruktur symmetrisch stabil", green),
                    ("Katz Dimension",       "1.52 \u{b7} stabile fraktale Komplexit\u{e4}t", green),
                    ("Anomaly Flags",        "(keine)", dim),
                ],
                "",
            ))
            .push(scenario_card(
                "Verd\u{e4}chtige Kopie",
                warn,
                "setup.exe \u{b7} 3,4 MB \u{b7} Drittquelle",
                vec![
                    ("Entropie",             "7.91 bit/byte \u{b7} n\u{e4}hert sich Maximum \u{2014} m\u{f6}gliche Verschleierung", warn),
                    ("Delta Ratio",          "0.34 \u{b7} 34% der Bytes weichen vom Original ab", warn),
                    ("Trust Score",          "0.29 \u{b7} niedrige Konsistenz", warn),
                    ("Noether Consistency",  "0.41 \u{b7} Blockstruktur stark gebrochen", warn),
                    ("Katz Dimension",       "1.78 \u{b7} Komplexit\u{e4}tsklasse angestiegen", warn),
                    ("Anomaly Flags",        "high_entropy_segment, structural_break, katz_shift", warn),
                ],
                "Hohe Entropie allein ist kein Beweis \u{2014} komprimierte legitime Dateien erreichen \u{e4}hnliche Werte. Entscheidend ist die Kombination: hohe Entropie + gro\u{df}e Delta-Abweichung + gebrochene Noether-Symmetrie + Katz-Klassen-Sprung. Jede einzelne Metrik ist ein Hinweis, zusammen erh\u{e4}rten sie ein Signal.",
            ))
            .spacing(8)
            .into(),
            panel_s,
        );

        // ── use case 3: software-regression / build-drift ────────────────────
        let uc_regression = ade_subpanel(
            "FALLBEISPIEL 3 \u{b7} SOFTWARE-REGRESSION UND BUILD-DRIFT",
            column![
                text("Szenario: Zwei aufeinanderfolgende Releases desselben Tools. Kein Angriff \u{2014} aber zwischen v2.1 und v2.2 wurden ungeplant Debug-Symbole eingelinkt. Ohne Quellcode-Zugriff durch reinen Strukturvergleich sichtbar.").size(12).color(mid),
            ].spacing(6)
            .push(scenario_card(
                "Release v2.1 (Baseline)",
                green,
                "tool_v2.1_release.bin \u{b7} 8,4 MB",
                vec![
                    ("Entropie",             "5.88 bit/byte \u{b7} typisch f\u{fc}r optimierten Release-Build", mid),
                    ("Delta Ratio",          "0.000 \u{b7} Referenz", dim),
                    ("Noether Consistency",  "0.961 \u{b7} stabile Sektionsstruktur", green),
                    ("Katz Dimension",       "1.44 \u{b7} erwartete fraktale Komplexit\u{e4}t", green),
                    ("Anomaly Flags",        "(keine)", dim),
                ],
                "",
            ))
            .push(scenario_card(
                "Release v2.2 (ungewollte Debug-Symbole)",
                accent,
                "tool_v2.2_release.bin \u{b7} 14,1 MB",
                vec![
                    ("Entropie",             "4.31 bit/byte \u{b7} deutlich gesunken \u{2014} Debug-Strings sind hochredundanter Klartext", accent),
                    ("Delta Ratio",          "0.41 \u{b7} 41% des Dateiinhalts neu \u{2014} f\u{fc}r eine Minor-Version unplausibel", accent),
                    ("Noether Consistency",  "0.73 \u{b7} neue Sektionen st\u{f6}ren Sektions-Symmetrie", accent),
                    ("Katz Dimension",       "1.21 \u{b7} Komplexit\u{e4}tsklasse gesunken \u{2014} Datei strukturell einfacher geworden", accent),
                    ("Changed Bytes",        "~5,7 MB zus\u{e4}tzlicher Inhalt hinzugekommen", accent),
                    ("Anomaly Flags",        "entropy_drop, size_increase, delta_volume_high", accent),
                ],
                "Sinkende Entropie bei steigender Dateigr\u{f6}\u{df}e ist das klassische Signal f\u{fc}r hinzugef\u{fc}gte redundante Informationen (Debug-Symbole, Logs, Padding). Hohe Delta-Ratio f\u{fc}r eine Minor-Version: hier ist mehr ge\u{e4}ndert worden als erwartet war. Kein Security-Alarm, aber ein CI/CD-Qualit\u{e4}tssignal.",
            ))
            .spacing(8)
            .into(),
            panel_s,
        );

        // ── use case 4: log-anomalie / feedback-schleife ──────────────────────
        let uc_log = ade_subpanel(
            "FALLBEISPIEL 4 \u{b7} LOG-DATEI ANOMALIE UND FEEDBACK-SCHLEIFE",
            column![
                text("Szenario: T\u{e4}gliche Anwendungslogs eines Servers. An einem Tag l\u{e4}uft eine Endlosschleife und schreibt Millionen identischer Zeilen. Erkennbar ohne eine einzige Zeile lesen zu m\u{fc}ssen.").size(12).color(mid),
            ].spacing(6)
            .push(scenario_card(
                "Normaler Log-Tag (Referenz)",
                green,
                "app.log.2024-10-15 \u{b7} 82 MB",
                vec![
                    ("Entropie",        "4.82 bit/byte \u{b7} typische Sprachdichte mit Zeitstempeln und Werten", mid),
                    ("Zipf Alpha",      "0.97 \u{b7} nat\u{fc}rliche Wortfrequenz \u{2014} Log-Tokens folgen Zipf", green),
                    ("Periodizit\u{e4}t", "0.28 \u{b7} geringe Wiederholung \u{2014} nat\u{fc}rliche Variation", mid),
                    ("Noether Score",   "0.89 \u{b7} Zeilenstruktur gleichm\u{e4}\u{df}ig verteilt", green),
                    ("Anomaly Flags",   "(keine)", dim),
                ],
                "",
            ))
            .push(scenario_card(
                "Feedback-Schleife (Absturztag)",
                warn,
                "app.log.2024-11-03 \u{b7} 18,4 GB",
                vec![
                    ("Entropie",        "0.76 bit/byte \u{b7} minimale Informationsdichte \u{2014} tausende identische Zeilen", warn),
                    ("Zipf Alpha",      "0.09 \u{b7} Zipf komplett gebrochen \u{2014} ein Token \u{fc}berw\u{e4}ltigt alle anderen", warn),
                    ("Periodizit\u{e4}t", "0.99 \u{b7} maximale Periode \u{2014} dieselbe Zeile unaufh\u{f6}rlich", warn),
                    ("Noether Score",   "0.03 \u{b7} Struktursymmetrie aufgel\u{f6}st", warn),
                    ("Anomaly Flags",   "stuck_signal, zipf_collapse, periodicity_max", warn),
                ],
                "Feedback-Schleife erzeugt dieselbe Signatur wie ein Stuck-Sensor: extremer Entropieabfall, Zipf-Kollaps, maximale Periodizit\u{e4}t. Mit dem Delta-Vergleich zum Vortags-Log wird zus\u{e4}tzlich sichtbar ab welchem Byte die Schleife startete.",
            ))
            .spacing(8)
            .into(),
            panel_s,
        );

        // ── use case 5: ki-generierte vs. echte inhalte ───────────────────────
        let uc_ai = ade_subpanel(
            "FALLBEISPIEL 5 \u{b7} KI-GENERIERTE INHALTE VS. ECHTE DATEN",
            column![
                text("Szenario: Zwei Textdateien \u{2014} eine von einem Menschen, eine von einem Sprachmodell. Und ein synthetisch erzeugter ML-Trainingsdatensatz gegen\u{fc}ber echten Messwerten.").size(12).color(mid),
            ].spacing(6)
            .push(scenario_card(
                "Menschlicher Text (Referenz)",
                green,
                "abstract_human.txt \u{b7} 4,2 kB",
                vec![
                    ("Entropie",      "4.71 bit/byte \u{b7} mittlere Sprachdichte", mid),
                    ("Zipf Alpha",    "1.03 \u{b7} nat\u{fc}rliches Wortfrequenzgesetz gut erf\u{fc}llt", green),
                    ("Benford Score", "0.91 \u{b7} eingebettete Zahlen folgen nat\u{fc}rlicher Ziffernverteilung", green),
                    ("Periodizit\u{e4}t", "0.22 \u{b7} geringe strukturelle Wiederholung", mid),
                    ("SCE Score",     "0.67 \u{b7} normale Komplexit\u{e4}tsdichte", mid),
                ],
                "",
            ))
            .push(scenario_card(
                "LLM-generierter Text",
                accent,
                "abstract_llm.txt \u{b7} 4,5 kB",
                vec![
                    ("Entropie",      "4.68 bit/byte \u{b7} \u{e4}hnlich \u{2014} Entropie allein unterscheidet kaum", mid),
                    ("Zipf Alpha",    "0.78 \u{b7} schw\u{e4}cher \u{2014} LLMs gl\u{e4}tten die Verteilung", accent),
                    ("Benford Score", "0.71 \u{b7} leicht abweichend bei eingebetteten Zahlen", accent),
                    ("Periodizit\u{e4}t", "0.61 \u{b7} markant h\u{f6}her \u{b7} strukturelle Satzwiederholungen", accent),
                    ("SCE Score",     "0.88 \u{b7} hohe Fl\u{e4}che \u{b7} \u{e4}hnliche Satzkomplexe", accent),
                    ("Anomaly Flags", "zipf_deviation, high_periodicity", accent),
                ],
                "LLM-Text tendiert zu h\u{f6}herer Periodizit\u{e4}t (Sampling aus Wahrscheinlichkeitsverteilungen \u{2192} Wiederholungsmuster) und gl\u{e4}tterer Zipf-Kurve. Als statistisches Indiz hilfreich, kein juristischer Beweis.",
            ))
            .spacing(8)
            .into(),
            panel_s,
        );

        // ── use case 6: wissenschaftliche reproduzierbarkeit / datensatz-drift ─
        let uc_integrity = ade_subpanel(
            "FALLBEISPIEL 6 \u{b7} WISSENSCHAFTLICHE REPRODUZIERBARKEIT UND DATENSATZ-DRIFT",
            column![
                text("Szenario: Zwei Versionen desselben Datensatzes aus zwei verschiedenen Archiven \u{2014} beide behaupten, der Original-Datensatz einer Publikation zu sein. Gleiche Dateigr\u{f6}\u{df}e \u{2014} sind sie strukturell identisch?").size(12).color(mid),
            ].spacing(6)
            .push(scenario_card(
                "Version A (Original-Repository)",
                green,
                "experiment_data_v1.csv \u{b7} 22 MB",
                vec![
                    ("Entropie",             "3.91 bit/byte \u{b7} typisch f\u{fc}r physikalische Messwerte in CSV", mid),
                    ("Benford Score",        "0.94 \u{b7} Messwerte folgen Benford-Gesetz \u{2014} nat\u{fc}rliche Daten", green),
                    ("Noether Consistency",  "0.972 \u{b7} Messreihen-Symmetrie vollst\u{e4}ndig erhalten", green),
                    ("Delta Ratio",          "0.000 \u{b7} Referenz", dim),
                ],
                "",
            ))
            .push(scenario_card(
                "Version B (Zweitarchiv \u{2014} abweichend trotz gleicher Dateigr\u{f6}\u{df}e)",
                warn,
                "experiment_data_v1.csv \u{b7} 22 MB \u{b7} identische Dateigr\u{f6}\u{df}e",
                vec![
                    ("Entropie",             "3.89 bit/byte \u{b7} kaum erkennbar anders", mid),
                    ("Benford Score",        "0.63 \u{b7} abweichend \u{2014} Ziffernf\u{fc}hrung wurde ver\u{e4}ndert", warn),
                    ("Noether Consistency",  "0.71 \u{b7} Teilsymmetrie gebrochen \u{2014} nicht alle Messreihen konsistent", warn),
                    ("Delta Ratio",          "0.07 \u{b7} 7% der Bytes unterscheiden sich trotz gleicher Dateigr\u{f6}\u{df}e", warn),
                    ("Changed Bytes",        "~1,5 MB inhaltlich unterschiedlich", warn),
                    ("Anomaly Flags",        "benford_deviation, noether_break, delta_mismatch", warn),
                ],
                "Gleiche Dateigr\u{f6}\u{df}e bedeutet nichts \u{2014} Inhalte k\u{f6}nnen ausgetauscht worden sein. Benford-Abweichung zeigt: Zahlen wurden bearbeitet (gerundet, skaliert). Noether-Break + 7% Delta-Ratio bei sonst identischem Erscheinungsbild ist ein starkes Signal f\u{fc}r Datensatz-Drift oder absichtliche Modifikation. Relevant f\u{fc}r wissenschaftliche Reproduzierbarkeit.",
            ))
            .spacing(8)
            .into(),
            panel_s,
        );

        // ── live capsule (if available) ───────────────────────────────────────
        let live_panel: Element<'_, Message> = if let Some(capsule) = &self.capsule_state {
            let red   = Color::from_rgb8(0xD9, 0x50, 0x50);
            let mut rows = Column::new()
                .push(text(format!("Quelle: {}  \u{b7}  Typ: {}  \u{b7}  Domain: {}",
                    capsule.source_label, capsule.source_type, capsule.domain_hint))
                    .size(13).color(mid))
                .push(
                    row![
                        text("Trust Score").size(12).color(dim).width(Length::Fixed(190.0)),
                        text(format!("{:.3}", capsule.trust_score)).size(13)
                            .color(if capsule.trust_score > 0.65 { green } else { warn }),
                    ]
                )
                .push(
                    row![
                        text("Entropie").size(12).color(dim).width(Length::Fixed(190.0)),
                        text(format!("{:.4} bit/byte", capsule.entropy)).size(13).color(mid),
                    ]
                )
                .push(
                    row![
                        text("Delta Ratio").size(12).color(dim).width(Length::Fixed(190.0)),
                        text(format!("{:.4}", capsule.delta_ratio)).size(13).color(mid),
                    ]
                )
                .push(
                    row![
                        text("Noether Consistency").size(12).color(dim).width(Length::Fixed(190.0)),
                        text(format!("{:.4}", capsule.noether_consistency)).size(13).color(mid),
                    ]
                )
                .push(
                    row![
                        text("Benford / Zipf / Katz").size(12).color(dim).width(Length::Fixed(190.0)),
                        text(format!("{:.3}  /  {:.3}  /  {:.3}",
                            capsule.benford_score, capsule.zipf_alpha, capsule.katz_dimension))
                            .size(13).color(mid),
                    ]
                )
                .push(
                    row![
                        text("Periodizit\u{e4}t / SCE").size(12).color(dim).width(Length::Fixed(190.0)),
                        text(format!("{:.4}  /  {:.4}", capsule.periodicity, capsule.sce_score))
                            .size(13).color(mid),
                    ]
                )
                .spacing(5);
            if !capsule.anomaly_flags.is_empty() {
                rows = rows.push(
                    row![
                        text("Anomalie-Flags").size(12).color(dim).width(Length::Fixed(190.0)),
                        text(capsule.anomaly_flags.join(", ")).size(12).color(red),
                    ]
                );
            }
            let recon: Element<'_, Message> = button(
                    text("\u{2192} Rekonstruktion pr\u{fc}fen").size(12).color(Color::from_rgb8(0xD0, 0xE8, 0xF8))
                )
                .on_press(Message::TabSelected(Tab::Rekonstruktion))
                .padding([6, 14])
                .style(primary_button_style)
                .into();
            ade_subpanel(
                "AKTUELLE KAPSEL \u{b7} ZULETZT ANALYSIERTE DATEI",
                Column::new().push(rows).push(recon).spacing(10).into(),
                panel_s,
            )
        } else {
            ade_subpanel(
                "AKTUELLE KAPSEL \u{b7} ZULETZT ANALYSIERTE DATEI",
                text("Noch keine Datei analysiert. Datei auf das Fenster ziehen um eine Kapsel zu erzeugen.").size(13).color(dim).into(),
                panel_s,
            )
        };

        scrollable(
            Column::new()
                .push(intro)
                .push(uc_overview)
                .push(live_panel)
                .push(uc_outlier)
                .push(uc_tamper)
                .push(uc_regression)
                .push(uc_log)
                .push(uc_ai)
                .push(uc_integrity)
                .spacing(12)
                .padding([0.0f32, 8.0]),
        )
        .into()
    }

    fn view_shell(&self) -> Element<'_, Message> {
        let main = match self.active_tab {
            Tab::Home => self.view_home(),
            Tab::Control => self.view_control_center(),
            Tab::Symbiont => self.view_symbiont(),
            Tab::SwarmOps => self.view_swarm_ops(),
            Tab::Privacy => self.view_privacy_ops(),
            Tab::Chat => self.view_chat(),
            Tab::Data => self.view_data(),
            Tab::Settings => self.view_settings(),
            Tab::Logs => self.view_logs(),
            Tab::Anchors => self.view_anchors(),
            Tab::FlowSphere => self.view_flow_sphere(),
            Tab::StructureMap => self.view_delta_convergence(),
            Tab::Gaming => self.view_gaming_world(),
            Tab::Media => self.view_media_world(),
            Tab::Research => self.view_research_world(),
            Tab::ADE => self.view_ade(),
            Tab::Imprint => self.view_imprint(),
            Tab::Rekonstruktion => self.view_rekonstruktion(),
            Tab::Launcher => self.view_launcher(),
        };

        let nav_item = |label: &'static str, tab: Tab, active_tab: Tab| {
            let active = tab == active_tab;
            button(text(label).size(13).color(if active { c(TEXT_H()) } else { c(TEXT_M()) }))
                .on_press(Message::TabSelected(tab))
                .padding([8, 10])
                .style(move |_: &Theme, _| button::Style {
                    background: Some(Background::Color(if active {
                        Color::from_rgba(0.55, 0.25, 0.95, 0.65)
                    } else {
                        Color::TRANSPARENT
                    })),
                    border: Border {
                        color: if active { Color::from_rgb8(0x8B, 0x52, 0xF6) } else { Color::TRANSPARENT },
                        width: if active { 1.0 } else { 0.0 },
                        radius: 8.0.into(),
                    },
                    ..Default::default()
                })
        };

        let action_item = |label: String, message: Message| {
            button(text(label).size(13).color(c(TEXT_H())))
                .on_press(message)
                .padding([8, 10])
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(Color::from_rgba(0.22, 0.33, 0.60, 0.25))),
                    border: Border {
                        color: Color::from_rgb8(0x5A, 0x8C, 0xE8),
                        width: 1.0,
                        radius: 8.0.into(),
                    },
                    ..Default::default()
                })
        };

        let shell_sidebar = container(
            column![
                text("AetherGuard").size(26).color(Color::from_rgb8(0xD3, 0xC6, 0xFF)),
                text("Security is a process, not a product.").size(11).color(c(TEXT_D())),
                text("Quick Start").size(12).color(c(TEXT_D())),
                nav_item("1. Overview", Tab::Home, self.active_tab),
                nav_item("2. Control Center", Tab::Control, self.active_tab),
                nav_item("3. Files", Tab::Data, self.active_tab),
                nav_item("4. Chat", Tab::Chat, self.active_tab),
                nav_item("5. Logs", Tab::Logs, self.active_tab),
                text("Operations").size(12).color(c(TEXT_D())),
                nav_item("6. Swarm Ops", Tab::SwarmOps, self.active_tab),
                nav_item("7. Privacy", Tab::Privacy, self.active_tab),
                text("Analysis").size(12).color(c(TEXT_D())),
                nav_item("8. Delta-Analyse", Tab::ADE, self.active_tab),
                nav_item("9. FlowSphere", Tab::FlowSphere, self.active_tab),
                nav_item("10. Delta Convergence", Tab::StructureMap, self.active_tab),
                nav_item("11. Symbiont", Tab::Symbiont, self.active_tab),
                action_item(
                    if self.live_render_mode {
                        "12. Live Render deaktivieren".to_owned()
                    } else {
                        "12. Live Render aktivieren".to_owned()
                    },
                    Message::LiveRenderToggle,
                ),
                nav_item("13. Anchors", Tab::Anchors, self.active_tab),
                text("Worlds").size(12).color(c(TEXT_D())),
                nav_item("14. Gaming", Tab::Gaming, self.active_tab),
                nav_item("15. Media", Tab::Media, self.active_tab),
                text("Workspace").size(12).color(c(TEXT_D())),
                nav_item("16. Reconstruction", Tab::Rekonstruktion, self.active_tab),
                nav_item("17. Info", Tab::Imprint, self.active_tab),
                text("System").size(12).color(c(TEXT_D())),
                nav_item("18. Runtime", Tab::Settings, self.active_tab),
                nav_item("19. Launcher", Tab::Launcher, self.active_tab),
            ]
            .spacing(8)
        )
        .padding(16)
        .width(Length::Fixed(220.0))
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x0D, 0x14, 0x2A))),
            border: Border { color: Color::from_rgb8(0x1E, 0x2A, 0x46), width: 1.0, radius: 14.0.into() },
            ..Default::default()
        });

        let shell_sidebar = container(
            scrollable(shell_sidebar)
                .height(Length::Fill)
        )
        .width(Length::Fixed(220.0))
        .height(Length::Fill);

        let shell_header = container(
            row![
                column![
                    text(match self.active_tab {
                        Tab::Home => "Overview",
                        Tab::Control => "Control Center",
                        Tab::Symbiont => "Symbiont",
                        Tab::SwarmOps => "Swarm Ops",
                        Tab::Privacy => "Privacy",
                        Tab::Chat => "Chat",
                        Tab::Data => "Files",
                        Tab::Settings => "Runtime",
                        Tab::Logs => "Logs",
                        Tab::Anchors => "Anchors",
                        Tab::FlowSphere => "FlowSphere",
                        Tab::StructureMap => "Delta Convergence",
                        Tab::Gaming => "Gaming",
                        Tab::Media => "Media",
                        Tab::Research => "Research",
                        Tab::ADE => "Delta-Analyse",
                        Tab::Imprint => "Info",
                        Tab::Rekonstruktion => "Reconstruction",
                        Tab::Launcher => "Launcher",
                    }).size(24).color(c(TEXT_H())),
                    text(self.tab_subtitle()).size(12).color(c(TEXT_M())),
                ]
                .spacing(3),
                container(
                    text_input(self.dashboard_search_placeholder(), &self.dashboard_search)
                        .on_input(Message::DashboardSearchChanged)
                        .padding([9, 14])
                        .size(13)
                        .width(Length::Fixed(330.0)),
                )
                .padding([0, 8]),
                iced::widget::Space::new(Length::Fill, Length::Shrink),
                container(
                    text(if self.backend_state_loaded && self.backend_cpu_pct > 0.0 {
                        format!("CPU {:.1}%", self.backend_cpu_pct)
                    } else {
                        "CPU n/a".to_owned()
                    })
                    .size(12)
                    .color(c(TEXT_M())),
                )
                .padding([8, 12])
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgba(0.24, 0.70, 0.76, 0.12))),
                    border: Border { color: Color::from_rgb8(0x3F, 0xBA, 0xC2), width: 1.0, radius: 10.0.into() },
                    ..Default::default()
                }),
                container(
                    text(if self.backend_state_loaded && self.backend_mem_used_gb > 0.0 {
                        format!("RAM {:.2} GB", self.backend_mem_used_gb)
                    } else {
                        "RAM n/a".to_owned()
                    })
                    .size(12)
                    .color(c(TEXT_M())),
                )
                .padding([8, 12])
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgba(0.24, 0.70, 0.76, 0.12))),
                    border: Border { color: Color::from_rgb8(0x3F, 0xBA, 0xC2), width: 1.0, radius: 10.0.into() },
                    ..Default::default()
                }),
                button(text(format!("Performance {}", self.runtime_profile_label())).size(12).color(c(TEXT_H())))
                    .on_press(Message::TabSelected(Tab::Settings))
                    .padding([8, 12])
                    .style(|_: &Theme, _| button::Style {
                        background: Some(Background::Color(Color::from_rgba(0.59, 0.34, 0.96, 0.18))),
                        border: Border { color: Color::from_rgb8(0xA0, 0x70, 0xFF), width: 1.1, radius: 10.0.into() },
                        ..Default::default()
                    }),
                container(
                    text(if self.live_render_mode {
                        format!(
                            "Live ON | d={:.3} px={:.3} g={} p={}{}",
                            self.live_render_last_delta_ratio,
                            self.live_render_last_pixeldynamics,
                            self.live_render_last_godel_level,
                            self.live_render_saved_patterns,
                            if self.live_render_anchor_boost { " | AnchorBoost" } else { "" }
                        )
                    } else {
                        "LiveRender OFF".to_owned()
                    })
                    .size(12)
                    .color(if self.live_render_mode {
                        Color::from_rgb8(0x9F, 0xF2, 0xA8)
                    } else {
                        c(TEXT_M())
                    }),
                )
                .padding([8, 12])
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgba(0.19, 0.42, 0.24, 0.20))),
                    border: Border {
                        color: Color::from_rgb8(0x4C, 0xA8, 0x5A),
                        width: 1.0,
                        radius: 10.0.into(),
                    },
                    ..Default::default()
                }),
                button(text(if self.live_render_mode { "Live Render: AUS" } else { "Live Render: AN" }).size(12).color(c(TEXT_H())))
                    .on_press(Message::LiveRenderToggle)
                    .padding([8, 12])
                    .style(|_: &Theme, _| button::Style {
                        background: Some(Background::Color(Color::from_rgba(0.19, 0.42, 0.24, 0.28))),
                        border: Border { color: Color::from_rgb8(0x5E, 0xBE, 0x6E), width: 1.1, radius: 10.0.into() },
                        ..Default::default()
                    }),
                button(text(self.ui_text("▼ Leistenmodus", "▼ Overlay Bar")).size(12).color(c(TEXT_H())))
                    .on_press(Message::ToggleMode)
                    .padding([8, 12])
                    .style(|_: &Theme, _| button::Style {
                        background: Some(Background::Color(Color::from_rgba(0.22, 0.33, 0.60, 0.25))),
                        border: Border { color: Color::from_rgb8(0x5A, 0x8C, 0xE8), width: 1.1, radius: 10.0.into() },
                        ..Default::default()
                    }),
            ]
            .align_y(Alignment::Center)
            .spacing(12)
        )
        .padding([10, 14])
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x0E, 0x1A, 0x31))),
            border: Border { color: Color::from_rgb8(0x1F, 0x2B, 0x49), width: 1.0, radius: 12.0.into() },
            ..Default::default()
        });

        let status_strip: Element<'_, Message> = if self.status_line.is_empty() {
            iced::widget::Space::new(Length::Fill, Length::Fixed(0.0)).into()
        } else {
            container(
                text(format!("\u{24d8}  {}", &self.status_line))
                    .size(12)
                    .color(Color::from_rgb8(0xFF, 0xD7, 0x00)),
            )
            .padding([4, 16])
            .width(Length::Fill)
            .style(|_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.22, 0.14, 0.0, 0.96))),
                border: Border { color: Color::from_rgb8(0xD4, 0xA0, 0x42), width: 1.0, radius: 0.0.into() },
                ..Default::default()
            })
            .into()
        };

        let live_bottom_bar: Element<'_, Message> = container(
            row![
                // ● Live-Indikator
                button(
                    text(if self.live_render_mode {
                        format!("● LIVE  p={}  δ={:.3}  px={:.3}  {}",
                            self.live_render_saved_patterns,
                            self.live_render_last_delta_ratio,
                            self.live_render_last_pixeldynamics,
                            {
                                let bpj = self.live_render_bits_per_joule;
                                if bpj >= 1_000_000.0 {
                                    format!("{:.1} Mb/J", bpj / 1_000_000.0)
                                } else if bpj >= 1_000.0 {
                                    format!("{:.0} kb/J", bpj / 1_000.0)
                                } else if bpj > 0.0 {
                                    format!("{:.0} b/J", bpj)
                                } else {
                                    "— b/J".to_owned()
                                }
                            },
                        )
                    } else {
                        "○ Live Render".to_owned()
                    })
                    .size(12)
                    .color(if self.live_render_mode {
                        Color::from_rgb8(0x9F, 0xF2, 0xA8)
                    } else {
                        c(TEXT_M())
                    })
                )
                .on_press(Message::LiveRenderToggle)
                .padding([5, 14])
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(if self.live_render_mode {
                        Color::from_rgba(0.10, 0.38, 0.16, 0.55)
                    } else {
                        Color::from_rgba(0.10, 0.14, 0.22, 0.55)
                    })),
                    border: Border {
                        color: if self.live_render_mode {
                            Color::from_rgb8(0x4C, 0xBE, 0x6A)
                        } else {
                            Color::from_rgb8(0x30, 0x40, 0x60)
                        },
                        width: 1.2,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                }),
                iced::widget::Space::new(Length::Fill, Length::Shrink),
                // Schnellzugriff Rekonstruktion
                button(text("Vault Reconstruction").size(11).color(c(TEXT_M())))
                    .on_press(Message::TabSelected(Tab::Rekonstruktion))
                    .padding([5, 10])
                    .style(|_: &Theme, _| button::Style {
                        background: Some(Background::Color(Color::from_rgba(0.14, 0.20, 0.36, 0.55))),
                        border: Border { color: c(BORDER()), width: 1.0, radius: 6.0.into() },
                        ..Default::default()
                    }),
            ]
            .align_y(Alignment::Center)
            .spacing(10),
        )
        .padding([4, 12])
        .width(Length::Fill)
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x08, 0x10, 0x22))),
            border: Border { color: Color::from_rgb8(0x1A, 0x26, 0x42), width: 1.0, radius: 0.0.into() },
            ..Default::default()
        })
        .into();

        container(
            row![
                shell_sidebar,
                Column::new()
                    .push(shell_header)
                    .push(status_strip)
                    .push(
                        container(main)
                            .padding(6)
                            .style(standard_card_style)
                            .width(Length::Fill)
                            .height(Length::Fill)
                    )
                    .push(live_bottom_bar)
                    .spacing(6)
                    .width(Length::Fill),
            ]
            .spacing(10),
        )
        .padding(10)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x06, 0x0D, 0x1F))),
            ..Default::default()
        })
        .into()
    }

    fn view_global_control_bar(&self) -> Element<'_, Message> {
        let quick_button = |label: &'static str, tab: Tab| {
            button(text(label).size(11).color(c(TEXT_H())))
                .on_press(Message::TabSelected(tab))
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(c(BG_CARD2()))),
                    border: Border {
                        color: c(BORDER()),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    text_color: c(TEXT_M()),
                    ..Default::default()
                })
                .padding([3, 8])
        };

        let bar = row![
            text("⬡ AETHER").size(12).color(c(ACCENT())),
            quick_button("Control", Tab::Control),
            quick_button("Files", Tab::Data),
            quick_button("Chat", Tab::Chat),
            quick_button("Swarm Ops", Tab::SwarmOps),
            quick_button("Privacy", Tab::Privacy),
            quick_button("FlowSphere", Tab::FlowSphere),
            quick_button("Delta Conv", Tab::StructureMap),
            quick_button("Delta", Tab::ADE),
            quick_button("Anchors", Tab::Anchors),
            quick_button("Settings", Tab::Settings),
            quick_button("Logs", Tab::Logs),
            quick_button("Symbiont", Tab::Symbiont),
            quick_button("Gaming ↓", Tab::Gaming),
            quick_button("Media ↓", Tab::Media),
            iced::widget::Space::new(Length::Fill, Length::Shrink),
            button(text(if self.live_render_mode { "Live Render: AUS" } else { "Live Render: AN" }).size(11).color(c(TEXT_H())))
                .on_press(Message::LiveRenderToggle)
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(c(BG_CARD2()))),
                    border: Border {
                        color: c(BORDER_ACT()),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    text_color: c(TEXT_M()),
                    ..Default::default()
                })
                .padding([3, 8]),
            button(text("▼ Kompaktleiste").size(11).color(c(TEXT_H())))
                .on_press(Message::ToggleMode)
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(c(BG_CARD2()))),
                    border: Border {
                        color: c(BORDER_ACT()),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    text_color: c(ACCENT()),
                    ..Default::default()
                })
                .padding([3, 8]),
        ]
        .spacing(12)
        .align_y(iced::Alignment::Center)
        .padding([0, 12]);

        container(bar)
            .width(Length::Fill)
            .height(Length::Fixed(34.0))
            .style(|_: &Theme| container::Style {
                background: Some(Background::Color(c(BG_BASE()))),
                border: Border { color: c(BORDER()), width: 1.0, radius: 0.0.into() },
                ..Default::default()
            })
            .into()
    }

    fn send_private_message(&mut self) {
        let Some(author) = self.current_username() else {
            self.status_line = "Private Nachrichten erfordern eine Anmeldung.".to_owned();
            return;
        };
        let Some(partner) = self.active_private_partner() else {
            self.status_line = "Bitte zuerst einen Nutzer waehlen.".to_owned();
            return;
        };
        let body = self.private_message_draft.trim().to_owned();
        if body.is_empty() {
            self.status_line = "Leere Nachrichten werden nicht gespeichert.".to_owned();
            return;
        }
        if self.state_store.is_blocked_between(&author, &partner) {
            self.status_line = format!(
                "Privater Thread mit {} ist blockiert. Nachricht wurde nicht gespeichert.",
                partner
            );
            return;
        }
        if let Err(err) = self
            .state_store
            .add_private_message(&author, &partner, &author, &body)
        {
            self.status_line = err;
            return;
        }
        if self
            .auth_store
            .usernames()
            .into_iter()
            .any(|username| username == partner)
        {
            let _ = self
                .state_store
                .add_private_message(&partner, &author, &author, &body);
        }
        self.selected_private_partner = Some(partner.clone());
        self.private_message_draft.clear();
        self.status_line = format!("Private Nachricht an {partner} lokal gespeichert.");
    }

    fn send_group_message(&mut self) {
        let Some(author) = self.current_username() else {
            self.status_line = "Gruppennachrichten erfordern eine Anmeldung.".to_owned();
            return;
        };
        let Some(room) = self.active_group_room() else {
            self.status_line = "Bitte zuerst eine Gruppe auswaehlen oder anlegen.".to_owned();
            return;
        };
        let body = self.group_message_draft.trim().to_owned();
        if body.is_empty() {
            self.status_line = "Leere Gruppennachrichten werden nicht gespeichert.".to_owned();
            return;
        }
        match self
            .state_store
            .add_group_message(&room.id, &author, &body)
        {
            Ok(()) => {
                self.group_message_draft.clear();
                self.status_line = format!("Gruppennachricht in '{}' gespeichert.", room.name);
            }
            Err(err) => self.status_line = err,
        }
    }

    fn create_group_room(&mut self) {
        let Some(owner) = self.current_username() else {
            self.status_line = "Gruppen erfordern eine Anmeldung.".to_owned();
            return;
        };
        let group_name = self.chat_group_name.trim().to_owned();
        if group_name.is_empty() {
            self.status_line = "Bitte zuerst einen Gruppennamen eingeben.".to_owned();
            return;
        }
        match self.state_store.create_group_room(&owner, &group_name) {
            Ok(room_id) => {
                self.chat_group_name.clear();
                self.selected_group_room_id = Some(room_id);
                self.chat_context = ChatContext::Group;
                self.status_line = format!("Gruppe '{}' angelegt.", group_name);
            }
            Err(err) => self.status_line = err,
        }
    }

    fn add_member_to_active_group(&mut self) {
        let Some(owner) = self.current_username() else {
            self.status_line = "Mitgliederverwaltung erfordert eine Anmeldung.".to_owned();
            return;
        };
        let Some(room) = self.active_group_room() else {
            self.status_line = "Bitte zuerst eine Gruppe auswaehlen.".to_owned();
            return;
        };
        let member = self.group_member_username.trim().to_owned();
        if member.is_empty() {
            self.status_line = "Bitte zuerst einen Usernamen eingeben.".to_owned();
            return;
        }
        if !self.auth_store.usernames().into_iter().any(|username| username == member) {
            self.status_line = format!("Unbekannter Username: {}", member);
            return;
        }
        if self.state_store.is_blocked_between(&owner, &member) {
            self.status_line = format!(
                "{} kann wegen einer Blockliste nicht in die Gruppe aufgenommen werden.",
                member
            );
            return;
        }
        match self
            .state_store
            .add_group_member(&owner, &room.id, &member)
        {
            Ok(()) => {
                self.group_member_username.clear();
                self.status_line = format!("{} wurde zu '{}' hinzugefuegt.", member, room.name);
            }
            Err(err) => self.status_line = err,
        }
    }

    fn remove_member_from_active_group(&mut self, member: String) {
        let Some(owner) = self.current_username() else {
            self.status_line = "Mitgliederverwaltung erfordert eine Anmeldung.".to_owned();
            return;
        };
        let Some(room) = self.active_group_room() else {
            self.status_line = "Bitte zuerst eine Gruppe auswaehlen.".to_owned();
            return;
        };
        match self
            .state_store
            .remove_group_member(&owner, &room.id, &member)
        {
            Ok(()) => {
                self.status_line = format!("{} wurde aus '{}' entfernt.", member, room.name);
            }
            Err(err) => self.status_line = err,
        }
    }

    fn leave_active_group(&mut self) {
        let Some(username) = self.current_username() else {
            self.status_line = "Gruppen verlassen erfordert eine Anmeldung.".to_owned();
            return;
        };
        let Some(room) = self.active_group_room() else {
            self.status_line = "Bitte zuerst eine Gruppe auswaehlen.".to_owned();
            return;
        };
        let room_name = room.name.clone();
        match self.state_store.leave_group(&username, &room.id) {
            Ok(()) => {
                self.selected_group_room_id = self.group_rooms().into_iter().next().map(|next| next.id);
                self.status_line = format!("Gruppe '{}' verlassen.", room_name);
            }
            Err(err) => self.status_line = err,
        }
    }

    fn block_selected_partner(&mut self) {
        let Some(username) = self.current_username() else {
            self.status_line = "Blockieren erfordert eine Anmeldung.".to_owned();
            return;
        };
        let Some(partner) = self.active_private_partner() else {
            self.status_line = "Bitte zuerst einen privaten Kontakt waehlen.".to_owned();
            return;
        };
        match self.state_store.block_user(&username, &partner) {
            Ok(()) => {
                self.status_line = format!("{} wurde blockiert.", partner);
            }
            Err(err) => self.status_line = err,
        }
    }

    fn unblock_selected_partner(&mut self) {
        let Some(username) = self.current_username() else {
            self.status_line = "Entblocken erfordert eine Anmeldung.".to_owned();
            return;
        };
        let Some(partner) = self.active_private_partner() else {
            self.status_line = "Bitte zuerst einen privaten Kontakt waehlen.".to_owned();
            return;
        };
        match self.state_store.unblock_user(&username, &partner) {
            Ok(()) => {
                self.status_line = format!("{} wurde entblockt.", partner);
            }
            Err(err) => self.status_line = err,
        }
    }

    fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> String {
        if let Some(message) = payload.downcast_ref::<String>() {
            return message.clone();
        }
        if let Some(message) = payload.downcast_ref::<&str>() {
            return (*message).to_owned();
        }
        "unbekannter Panic-Payload".to_owned()
    }

    fn apply_live_render_mode(&mut self, enabled: bool) {
        self.live_render_mode = enabled;
        if !enabled {
            self.live_render_analysis_running = false;
            self.live_render_last_frame.clear();
            self.live_render_last_running_services.clear();
            self.live_render_last_os_processes.clear();
            self.live_render_prev_xor_delta.clear();
            self.live_render_invariant_streak = 0;
            self.live_render_last_delta_ratio = 0.0;
            self.live_render_last_pixeldynamics = 0.0;
            self.live_render_last_godel_level = 0;
            self.live_render_last_godel_delta = 0.0;
            self.live_render_anchor_boost = false;
            self.live_render_last_os_sample_tick = 0;
            self.live_render_noether_k = 1.0;
            self.live_render_noether_delta_k = 0.0;
            self.live_render_noether_symmetry_preserved = true;
            self.live_render_noether_prev_spectral = [0.0f32; 5];
            self.live_render_noether_prev_entropy = 0.0;
        }
    }

    fn live_entropy_bytes(bytes: &[u8]) -> f32 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for byte in bytes {
            counts[*byte as usize] += 1;
        }
        let total = bytes.len() as f32;
        let mut entropy = 0.0f32;
        for count in counts {
            if count == 0 {
                continue;
            }
            let p = count as f32 / total;
            entropy -= p * p.log2();
        }
        entropy
    }

    fn live_periodicity_bytes(bytes: &[u8]) -> f32 {
        if bytes.len() < 4 {
            return 0.0;
        }
        let mut best = 0.0f32;
        let max_lag = bytes.len().min(48);
        for lag in 1..max_lag {
            let mut matches = 0usize;
            let mut compared = 0usize;
            for idx in 0..(bytes.len() - lag) {
                compared += 1;
                if bytes[idx] == bytes[idx + lag] {
                    matches += 1;
                }
            }
            if compared > 0 {
                let score = matches as f32 / compared as f32;
                if score > best {
                    best = score;
                }
            }
        }
        best.clamp(0.0, 1.0)
    }

    fn run_live_godel_probe(&self, input: &[u8], max_depth: u8) -> (u8, f32) {
        let mut signal = input.to_vec();
        let mut last_hash = String::new();
        let mut prev_entropy = 0.0f32;
        let mut prev_periodicity = 0.0f32;
        let mut prev_size = 0.0f32;
        let mut has_prev = false;

        for level in 0..=max_depth {
            use sha2::{Digest, Sha256};
            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(&signal);
                let digest = hasher.finalize();
                digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
            };
            let entropy = Self::live_entropy_bytes(&signal);
            let periodicity = Self::live_periodicity_bytes(&signal);
            let size = signal.len() as f32;

            let mut delta_percent = 100.0f32;
            if has_prev {
                let e_delta = (entropy - prev_entropy).abs() / prev_entropy.max(1e-6);
                let p_delta = (periodicity - prev_periodicity).abs() / prev_periodicity.max(1e-6);
                let s_delta = (size - prev_size).abs() / prev_size.max(1.0);
                delta_percent = ((e_delta + p_delta + s_delta) / 3.0) * 100.0;
            }

            if has_prev && (delta_percent < 1.0 || hash == last_hash || level >= max_depth) {
                return (level, delta_percent);
            }

            let next = serde_json::json!({
                "entropy": entropy,
                "periodicity": periodicity,
                "size": size,
                "fingerprint": hash,
            });
            signal = serde_json::to_vec(&next).unwrap_or_default();
            last_hash = hash;
            prev_entropy = entropy;
            prev_periodicity = periodicity;
            prev_size = size;
            has_prev = true;
        }
        (max_depth, 0.0)
    }

    fn compute_byte_delta_ratio(previous: &[u8], current: &[u8]) -> f32 {
        if previous.is_empty() {
            return 1.0;
        }
        let max_len = previous.len().max(current.len());
        if max_len == 0 {
            return 0.0;
        }
        let mut changed = 0usize;
        for idx in 0..max_len {
            let a = previous.get(idx).copied().unwrap_or_default();
            let b = current.get(idx).copied().unwrap_or_default();
            if a != b {
                changed += 1;
            }
        }
        changed as f32 / max_len as f32
    }

    fn compute_pixeldynamics(previous: &[f32], current: &[f32]) -> f32 {
        if previous.is_empty() || current.is_empty() {
            return 0.0;
        }
        let len = previous.len().min(current.len());
        if len == 0 {
            return 0.0;
        }
        let sum: f32 = previous
            .iter()
            .zip(current.iter())
            .take(len)
            .map(|(a, b)| (a - b).abs())
            .sum();
        (sum / len as f32).clamp(0.0, 1.0)
    }

    /// Extrahiert 5 DFT-Magnitude-Bins (k=1..5) aus einem Byte-Slice.
    /// Arbeitet auf bis zu 256 Bytes, normalisiert durch N.
    /// Invariant: reiner Betrag, kein Phasenanteil – auditierbar.
    fn noether_spectral_5(data: &[u8]) -> [f32; 5] {
        let sample: Vec<f32> = data.iter().take(256).map(|b| *b as f32 / 255.0).collect();
        let n = sample.len();
        if n == 0 {
            return [0.0f32; 5];
        }
        let nf = n as f32;
        let mut out = [0.0f32; 5];
        for (ki, k) in (1usize..=5).enumerate() {
            let mut re = 0.0f32;
            let mut im = 0.0f32;
            for (idx, x) in sample.iter().enumerate() {
                let angle = std::f32::consts::TAU * k as f32 * idx as f32 / nf;
                re += x * angle.cos();
                im -= x * angle.sin();
            }
            out[ki] = (re * re + im * im).sqrt() / nf;
        }
        out
    }

    /// Kosinus-Ähnlichkeit zweier 5-Bin-Spektralvektoren [0, 1].
    /// Beide Nullvektoren gelten als identisch (sim = 1.0).
    fn noether_cosine_sim(a: &[f32; 5], b: &[f32; 5]) -> f32 {
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let mag_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let mag_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if mag_a < 1e-9 || mag_b < 1e-9 {
            return 1.0; // beide Null ≙ identisch
        }
        (dot / (mag_a * mag_b)).clamp(0.0, 1.0)
    }

    fn sample_os_processes() -> Vec<String> {
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("tasklist")
                .args(["/FO", "CSV", "/NH"])
                .output();
            if let Ok(output) = output {
                if output.status.success() {
                    let mut names: Vec<String> = String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .filter_map(|line| {
                            let first = line.split(',').next()?.trim().trim_matches('"');
                            if first.is_empty() {
                                None
                            } else {
                                Some(first.to_owned())
                            }
                        })
                        .collect();
                    names.sort();
                    names.dedup();
                    return names;
                }
            }
            Vec::new()
        }
        #[cfg(not(target_os = "windows"))]
        {
            let output = std::process::Command::new("ps")
                .args(["-eo", "comm="])
                .output();
            if let Ok(output) = output {
                if output.status.success() {
                    let mut names: Vec<String> = String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(|name| name.to_owned())
                        .collect();
                    names.sort();
                    names.dedup();
                    return names;
                }
            }
            Vec::new()
        }
    }

    fn capture_live_render_frame(&mut self) {
        // Sampling every tick can block UI on Windows (`tasklist`), so we throttle it.
        let os_sample_interval = self.live_render_os_sample_interval_ticks();
        let should_sample_os = self.live_render_last_os_processes.is_empty()
            || self.tick_counter.saturating_sub(self.live_render_last_os_sample_tick) >= os_sample_interval;
        let os_processes = if should_sample_os {
            self.live_render_last_os_sample_tick = self.tick_counter;
            Self::sample_os_processes()
        } else {
            self.live_render_last_os_processes.clone()
        };
        let mut running_services: Vec<String> = self
            .launcher_state
            .services
            .values()
            .filter(|service| {
                matches!(
                    service.status,
                    ServiceStatus::Running | ServiceStatus::Starting
                )
            })
            .map(|service| service.id.clone())
            .collect();
        running_services.sort();

        let mut process_rows: Vec<serde_json::Value> = self
            .launcher_state
            .services
            .values()
            .map(|service| {
                serde_json::json!({
                    "id": service.id,
                    "status": service.status.label(),
                    "pid": service.process_id,
                    "uptime_secs": service.uptime_secs,
                })
            })
            .collect();
        process_rows.sort_by(|a, b| {
            a.get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .cmp(b.get("id").and_then(|v| v.as_str()).unwrap_or_default())
        });

        let frame_payload = serde_json::json!({
            "tick": self.tick_counter,
            "runtime_profile": self.runtime_profile_label(),
            "services": process_rows,
            "backend": {
                "cpu_pct": self.backend_cpu_pct,
                "mem_gb": self.backend_mem_used_gb,
                "anchor_count": self.backend_anchor_count,
                "entropy_mean": self.backend_entropy_mean,
            },
            "os_processes": {
                "count": os_processes.len(),
                "sample": os_processes.iter().take(120).cloned().collect::<Vec<String>>(),
            },
            "xor_delta": self.last_xor_delta.clone(),
            "analysis_signal": {
                "progress": self.analysis_progress,
                "status": self.analysis_status,
                "delta_ratio": self.live_render_last_delta_ratio,
                "pixeldynamics": self.live_render_last_pixeldynamics,
            },
        });

        let frame_bytes = serde_json::to_vec(&frame_payload).unwrap_or_default();
        let delta_ratio = Self::compute_byte_delta_ratio(&self.live_render_last_frame, &frame_bytes);
        let pixeldynamics =
            Self::compute_pixeldynamics(&self.live_render_prev_xor_delta, &self.last_xor_delta);

        let stable_services = running_services
            .iter()
            .filter(|id| self.live_render_last_running_services.contains(id))
            .count();
        let stable_os_processes = os_processes
            .iter()
            .filter(|name| self.live_render_last_os_processes.contains(name))
            .count();
        if !running_services.is_empty()
            && stable_services == running_services.len()
            && (!should_sample_os
                || (!os_processes.is_empty()
                    && stable_os_processes >= (os_processes.len() / 2)))
        {
            self.live_render_invariant_streak = self.live_render_invariant_streak.saturating_add(1);
        } else {
            self.live_render_invariant_streak = 0;
        // Gödelstop-Zähler: konvergierte Probe = endlose Selbstanalyse vermeiden
        if godel_delta_percent < 1.0 && godel_level < 3 {
            self.live_render_godel_stop_skip = self.live_render_godel_stop_skip.saturating_add(1);
        } else {
            self.live_render_godel_stop_skip = 0;
        }
        }

        // --- Noether K: Zeitliche Erhaltungsgröße nach Noether-Theorem ---
        // K = 0.40 * spektrale_ähnlichkeit + 0.30 * (1 − entropiedrift) + 0.30 * (1 − deltavarianz)
        let noether_curr_spectral = Self::noether_spectral_5(&frame_bytes);
        let noether_curr_entropy = Self::live_entropy_bytes(&frame_bytes);
        let is_first_noether = self.live_render_noether_prev_spectral == [0.0f32; 5]
            && self.live_render_noether_prev_entropy == 0.0;
        let noether_spectral_sim = if is_first_noether {
            1.0f32
        } else {
            Self::noether_cosine_sim(&self.live_render_noether_prev_spectral, &noether_curr_spectral)
        };
        let noether_entropy_drift = if is_first_noether {
            0.0f32
        } else {
            ((noether_curr_entropy - self.live_render_noether_prev_entropy).abs()
                / self.live_render_noether_prev_entropy.max(1e-6))
            .min(1.0)
        };
        let noether_k = (0.40 * noether_spectral_sim
            + 0.30 * (1.0 - noether_entropy_drift)
            + 0.30 * (1.0 - delta_ratio.min(1.0)))
        .clamp(0.0, 1.0);
        let noether_delta_k = noether_k - self.live_render_noether_k;
        let noether_sym = noether_k >= 0.60;

        let structural_pattern = serde_json::json!({
            "tick": self.tick_counter,
            "frame_bytes": frame_bytes.len(),
            "delta_ratio": delta_ratio,
            "pixeldynamics": pixeldynamics,
            "invariants": {
                "stable_running_services": stable_services,
                "stable_os_processes": stable_os_processes,
                "invariant_streak": self.live_render_invariant_streak,
            },
            "running_services": running_services,
            "os_process_count": os_processes.len(),
            "noether": {
                "k": noether_k,
                "delta_k": noether_delta_k,
                "symmetry_preserved": noether_sym,
                "spectral_sim": noether_spectral_sim,
                "entropy_drift": noether_entropy_drift,
            },
        });

        let (godel_level, godel_delta_percent) = self.run_live_godel_probe(&frame_bytes, 3);
        self.live_render_last_godel_level = godel_level;
        self.live_render_last_godel_delta = godel_delta_percent;
        // Gödelstop-Zähler: konvergierte Probe = endlose Selbstanalyse vermeiden
        if godel_delta_percent < 1.0 && godel_level < 3 {
            self.live_render_godel_stop_skip = self.live_render_godel_stop_skip.saturating_add(1);
        } else {
            self.live_render_godel_stop_skip = 0;
        }
        self.live_render_anchor_boost = self.backend_anchor_count > 0
            && self.live_render_invariant_streak >= 3
            && godel_delta_percent < 1.0;

        let _ = fs::create_dir_all("logs");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("logs/live_render_patterns.jsonl")
        {
            if writeln!(file, "{}", structural_pattern).is_ok() {
                self.live_render_saved_patterns = self.live_render_saved_patterns.saturating_add(1);
            }
        }

        self.live_render_last_frame = frame_bytes;
        self.live_render_last_running_services = running_services;
        self.live_render_last_os_processes = os_processes;
        self.live_render_prev_xor_delta = self.last_xor_delta.clone();
        self.live_render_last_delta_ratio = delta_ratio;
        self.live_render_last_pixeldynamics = pixeldynamics;
        self.live_render_noether_k = noether_k;
        self.live_render_noether_delta_k = noether_delta_k;
        self.live_render_noether_symmetry_preserved = noether_sym;
        self.live_render_noether_prev_spectral = noether_curr_spectral;
        self.live_render_noether_prev_entropy = noether_curr_entropy;

        // Bits per Joule — live efficiency estimate.
        // bits_saved: the fraction of the raw frame that the delta codec eliminated
        // this tick, expressed in bits (conservative: only count non-delta payload).
        // joules: CPU-fraction × assumed 15 W TDP × ~33 ms frame period.
        // Result is intentionally approximate — its trend matters more than its absolute value.
        {
            let frame_bits = self.live_render_last_frame.len() as f32 * 8.0;
            let bits_saved = (1.0 - self.live_render_last_delta_ratio.clamp(0.0, 1.0)) * frame_bits;
            let cpu_fraction = (self.backend_cpu_pct / 100.0).clamp(0.005, 1.0);
            let joules_per_tick = cpu_fraction * 15.0_f32 * 0.033_f32;
            self.live_render_bits_per_joule = bits_saved / joules_per_tick;
            self.live_render_bpj_history.push(self.live_render_bits_per_joule);
            if self.live_render_bpj_history.len() > 60 {
                self.live_render_bpj_history.remove(0);
            }
        }
    }

    fn theme_definition(&self) -> Theme {
        Theme::custom(
            "Aether Petrol".to_owned(),
            Palette {
                background: Color::from_rgb8(0x12, 0x11, 0x1E),
                text: Color::from_rgb8(0xE4, 0xEE, 0xF2),
                primary: Color::from_rgb8(0x66, 0x40, 0xCD),
                success: Color::from_rgb8(0x70, 0xB3, 0x92),
                danger: Color::from_rgb8(0xC6, 0x6A, 0x6A),
            },
        )
    }

    fn runtime_profile_label(&self) -> &'static str {
        match self.runtime_profile {
            RuntimeProfile::Auto => "AUTO",
            RuntimeProfile::Balanced => "BALANCED",
            RuntimeProfile::LowPower => "LOW-POWER",
            RuntimeProfile::Legacy => "LEGACY",
        }
    }

    fn is_vault_first_tier(&self) -> bool {
        matches!(self.hw_network_tier.as_str(), "LocalOnly" | "LanBeacon")
    }

    fn launcher_poll_interval_ticks(&self) -> u64 {
        if self.is_vault_first_tier() {
            match self.runtime_profile {
                RuntimeProfile::Auto => 2,
                RuntimeProfile::Balanced => 3,
                RuntimeProfile::LowPower => 4,
                RuntimeProfile::Legacy => 5,
            }
        } else {
            match self.runtime_profile {
                RuntimeProfile::Auto => 1,
                RuntimeProfile::Balanced => 2,
                RuntimeProfile::LowPower => 3,
                RuntimeProfile::Legacy => 4,
            }
        }
    }

    fn hybrid_state_poll_interval_ticks(&self) -> u64 {
        if self.is_vault_first_tier() {
            match self.runtime_profile {
                RuntimeProfile::Auto => 75,
                RuntimeProfile::Balanced => 90,
                RuntimeProfile::LowPower => 120,
                RuntimeProfile::Legacy => 150,
            }
        } else {
            match self.runtime_profile {
                RuntimeProfile::Auto => 45,
                RuntimeProfile::Balanced => 60,
                RuntimeProfile::LowPower => 90,
                RuntimeProfile::Legacy => 120,
            }
        }
    }

    fn backend_state_poll_interval_ticks(&self) -> u64 {
        if self.is_vault_first_tier() {
            match self.runtime_profile {
                RuntimeProfile::Auto => 150,
                RuntimeProfile::Balanced => 180,
                RuntimeProfile::LowPower => 240,
                RuntimeProfile::Legacy => 300,
            }
        } else {
            match self.runtime_profile {
                RuntimeProfile::Auto => 90,
                RuntimeProfile::Balanced => 120,
                RuntimeProfile::LowPower => 180,
                RuntimeProfile::Legacy => 240,
            }
        }
    }

    fn swarm_overlap_poll_interval_ticks(&self) -> u64 {
        if self.is_vault_first_tier() {
            match self.runtime_profile {
                RuntimeProfile::Auto => 90,
                RuntimeProfile::Balanced => 120,
                RuntimeProfile::LowPower => 180,
                RuntimeProfile::Legacy => 240,
            }
        } else {
            match self.runtime_profile {
                RuntimeProfile::Auto => 60,
                RuntimeProfile::Balanced => 75,
                RuntimeProfile::LowPower => 120,
                RuntimeProfile::Legacy => 180,
            }
        }
    }

    fn telemetry_scan_interval_ticks(&self) -> u64 {
        if self.is_vault_first_tier() {
            match self.runtime_profile {
                RuntimeProfile::Auto => 450,
                RuntimeProfile::Balanced => 600,
                RuntimeProfile::LowPower => 900,
                RuntimeProfile::Legacy => 1200,
            }
        } else {
            match self.runtime_profile {
                RuntimeProfile::Auto => 300,
                RuntimeProfile::Balanced => 450,
                RuntimeProfile::LowPower => 600,
                RuntimeProfile::Legacy => 900,
            }
        }
    }

    fn symbiont_event_poll_interval_ticks(&self) -> u64 {
        if self.is_vault_first_tier() {
            match self.runtime_profile {
                RuntimeProfile::Auto => 10,
                RuntimeProfile::Balanced => 12,
                RuntimeProfile::LowPower => 18,
                RuntimeProfile::Legacy => 24,
            }
        } else {
            match self.runtime_profile {
                RuntimeProfile::Auto => 8,
                RuntimeProfile::Balanced => 10,
                RuntimeProfile::LowPower => 14,
                RuntimeProfile::Legacy => 18,
            }
        }
    }

    fn live_render_analysis_interval_ticks(&self) -> u64 {
        if self.is_vault_first_tier() {
            match self.runtime_profile {
                RuntimeProfile::Auto => 10,
                RuntimeProfile::Balanced => 12,
                RuntimeProfile::LowPower => 18,
                RuntimeProfile::Legacy => 24,
            }
        } else {
            match self.runtime_profile {
                RuntimeProfile::Auto => 8,
                RuntimeProfile::Balanced => 10,
                RuntimeProfile::LowPower => 14,
                RuntimeProfile::Legacy => 18,
            }
        }
    }

    fn live_render_os_sample_interval_ticks(&self) -> u64 {
        if self.is_vault_first_tier() {
            match self.runtime_profile {
                RuntimeProfile::Auto => 14,
                RuntimeProfile::Balanced => 18,
                RuntimeProfile::LowPower => 28,
                RuntimeProfile::Legacy => 36,
            }
        } else {
            match self.runtime_profile {
                RuntimeProfile::Auto => 10,
                RuntimeProfile::Balanced => 14,
                RuntimeProfile::LowPower => 20,
                RuntimeProfile::Legacy => 28,
            }
        }
    }

    fn dashboard_search_help(&self) -> &'static str {
        self.ui_text("Suche: Datei, Anchor, Bedrohung \u{2026}", "Search: file, anchor, threat \u{2026}")
    }

    fn dashboard_search_placeholder(&self) -> &'static str {
        self.ui_text("Suche \u{2026}", "Search \u{2026}")
    }

    fn profile_tick_interval_ms(&self) -> u64 {
        let browser_like = false;
        let analysis_visual = matches!(self.active_tab, Tab::FlowSphere | Tab::StructureMap | Tab::ADE);
        match self.runtime_profile {
            RuntimeProfile::Auto => {
                if analysis_visual {
                    120
                } else if browser_like {
                    220
                } else if self.analysis_running {
                    320
                } else {
                    900
                }
            }
            RuntimeProfile::Balanced => {
                if analysis_visual {
                    160
                } else if browser_like {
                    260
                } else {
                    650
                }
            }
            RuntimeProfile::LowPower => {
                if analysis_visual {
                    220
                } else if browser_like {
                    420
                } else {
                    1150
                }
            }
            RuntimeProfile::Legacy => {
                if analysis_visual {
                    320
                } else if browser_like {
                    650
                } else {
                    1600
                }
            }
        }
    }

    fn tick_interval_ms(&self) -> u64 {
        self.profile_tick_interval_ms()
    }

    fn handle_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::LoginUsernameChanged(value) => self.login_username = value,
            Message::LoginPasswordChanged(value) => self.login_password = value,
            Message::LoginPressed => {
                let mut login_password = self.login_password.clone();
                match self
                    .auth_store
                    .authenticate(&self.login_username, &login_password)
                {
                    Ok(user) => {
                        self.clear_runtime_keys();
                        self.derive_runtime_keys(&user, &login_password);
                        self.login_password.zeroize();
                        self.login_password.clear();
                        self.show_tutorial = self.state_store.entries_for(&user.username).is_empty();
                        self.current_user = Some(user);
                        self.active_tab = Tab::Home;
                        self.chat_context = ChatContext::Private;
                        self.selected_private_partner = None;
                        self.refresh_security_snapshot(true, "login");
                        // GENESIS NODE nur wenn genesis_node.key lokal vorhanden (backend prüft).
                        // Nicht jeder Admin ist der Genesis-Node — nur der Ersteller.
                        let role_label = if self.backend_swarm_genesis_key_ok {
                            "GENESIS NODE"
                        } else {
                            "Node"
                        };
                        self.status_line = format!(
                            "Anmeldung erfolgreich als {}! Session-Key: {}",
                            role_label,
                            self.data_key_fingerprint
                        );
                    }
                    Err(err) => self.status_line = err,
                }
                login_password.zeroize();
            }
            Message::RegisterPressed => {
                let mut login_password = self.login_password.clone();
                match self
                    .auth_store
                    .register(&self.login_username, &login_password)
                {
                    Ok(()) => match self
                        .auth_store
                        .authenticate(&self.login_username, &login_password)
                    {
                        Ok(user) => {
                            self.clear_runtime_keys();
                            self.derive_runtime_keys(&user, &login_password);
                            self.login_password.zeroize();
                            self.login_password.clear();
                            self.current_user = Some(user);
                            self.show_tutorial = true;
                            self.active_tab = Tab::Chat;
                            self.chat_context = ChatContext::Private;
                            self.selected_private_partner = None;
                            self.refresh_security_snapshot(true, "register");
                            // GENESIS NODE nur wenn genesis_node.key lokal vorhanden.
                            let role_label = if self.backend_swarm_genesis_key_ok {
                                "GENESIS NODE"
                            } else {
                                "Node"
                            };
                            self.status_line = format!(
                                "Registrierung abgeschlossen als {}! Session-Key: {}",
                                role_label,
                                self.data_key_fingerprint
                            );
                        }
                        Err(err) => self.status_line = err,
                    },
                    Err(err) => self.status_line = err,
                }
                login_password.zeroize();
            }
            Message::TabSelected(tab) => {
                // Live-Render context gate:
                // auto-enable when entering Gaming / Media; auto-disable when leaving —
                // unless the user has explicitly pressed the LiveRender button.
                let was_live_context = matches!(self.active_tab, Tab::Gaming | Tab::Media);
                let is_live_context = matches!(tab, Tab::Gaming | Tab::Media);
                if is_live_context && !self.live_render_mode {
                    self.apply_live_render_mode(true);
                    self.status_line = format!(
                        "Live-Render aktiviert für {}-Tab: Bitstream/Godel/Noether laufen live.",
                        tab.label()
                    );
                } else if was_live_context && !is_live_context
                    && self.live_render_mode
                    && !self.live_render_explicit
                {
                    self.apply_live_render_mode(false);
                    self.status_line =
                        "Live-Render pausiert — kein Gaming-/Media-Tab aktiv.".to_owned();
                }
                self.active_tab = tab;
            }
            Message::ChatContextSelected(context) => self.chat_context = context,
            Message::SecurityModeSelected(mode) => self.set_security_mode(&mode),
            Message::RuntimeProfileSelected(profile) => {
                self.runtime_profile = profile;
                match write_shell_preferences(
                    self.runtime_profile,
                    self.persistent_mode,
                    self.ui_language,
                ) {
                    Ok(()) => {
                        self.status_line = format!(
                            "Runtime-Profil gespeichert: {} | Tick {} ms",
                            self.runtime_profile_label(),
                            self.tick_interval_ms(),
                        );
                    }
                    Err(err) => {
                        self.status_line = format!(
                            "Runtime-Profil aktiv, aber nicht gespeichert: {}",
                            err
                        );
                    }
                }
            }
            Message::UiLanguageSelected(lang) => {
                self.ui_language = lang;
                let message = match self.ui_language {
                    UiLanguage::German => "Sprache auf Deutsch gesetzt.",
                    UiLanguage::English => "Interface language switched to English.",
                };
                self.status_line = match write_shell_preferences(
                    self.runtime_profile,
                    self.persistent_mode,
                    self.ui_language,
                ) {
                    Ok(()) => message.to_owned(),
                    Err(err) => format!("{} Speicherung fehlgeschlagen: {}", message, err),
                };
            }
            Message::DashboardSearchChanged(value) => self.dashboard_search = value,
            Message::DashboardInfoToggle(key) => {
                if self.dashboard_info_key.as_ref() == Some(&key) {
                    self.dashboard_info_key = None;
                } else {
                    self.dashboard_info_key = Some(key);
                    self.dashboard_info_open_tick = self.tick_counter;
                }
            }
            Message::ChatUserSearchChanged(value) => self.chat_user_search = value,
            Message::PrivatePartnerSelected(partner) => {
                self.selected_private_partner = Some(partner.clone());
                self.chat_context = ChatContext::Private;
                self.status_line = format!("Privater Thread mit {partner} geoeffnet.");
            }
            Message::PrivateMessageChanged(value) => self.private_message_draft = value,
            Message::PrivateMessageSend => self.send_private_message(),
            Message::ChatInviteUsernameChanged(value) => self.chat_invite_username = value,
            Message::ChatInviteSend => {
                let Some(current_username) = self.current_username() else {
                    self.status_line = "Privater Chat erfordert eine Anmeldung.".to_owned();
                    return Task::none();
                };
                let name = self.chat_invite_username.trim().to_owned();
                if !name.is_empty() {
                    if self.state_store.is_blocked_between(&current_username, &name) {
                        self.status_line = format!(
                            "Privater Thread mit {} ist blockiert.",
                            name
                        );
                        return Task::none();
                    }
                    self.selected_private_partner = Some(name.clone());
                    self.chat_invite_username.clear();
                    self.status_line = format!("Privater Thread mit {} geöffnet.", name);
                }
            }
            Message::ChatBlockSelectedUser => self.block_selected_partner(),
            Message::ChatUnblockSelectedUser => self.unblock_selected_partner(),
            Message::GroupRoomSelected(room_id) => self.select_group_room(room_id),
            Message::ChatGroupNameChanged(value) => self.chat_group_name = value,
            Message::ChatGroupCreate => self.create_group_room(),
            Message::GroupMemberUsernameChanged(value) => self.group_member_username = value,
            Message::GroupAddMember => self.add_member_to_active_group(),
            Message::GroupRemoveMember(member) => self.remove_member_from_active_group(member),
            Message::GroupLeaveSelected => self.leave_active_group(),
            Message::GroupMessageChanged(value) => self.group_message_draft = value,
            Message::GroupMessageSend => self.send_group_message(),
            Message::ChatBroadcastDraftChanged(value) => self.chat_broadcast_draft = value,
            Message::ChatBroadcastSend => {
                let hint = self.chat_broadcast_draft.trim().to_owned();
                if !hint.is_empty() {
                    self.status_line = "Broadcast-Anfrage wird nur lokal vorgemerkt. Eine outbound Freigabe bleibt ein getrennter, expliziter Schritt.".to_owned();
                    self.chat_broadcast_draft.clear();
                }
            }
            Message::ChatBroadcastAccept(node_id) => {
                self.chat_broadcast_requests.retain(|r| r.node_id != node_id);
                self.selected_private_partner = Some(node_id.clone());
                self.chat_context = ChatContext::Private;
                self.status_line = format!("Broadcast-Kontakt {} als privaten Thread geöffnet.", node_id);
            }
            Message::ChatBroadcastDecline(node_id) => {
                self.chat_broadcast_requests.retain(|r| r.node_id != node_id);
                self.status_line = "Broadcast-Anfrage abgelehnt.".to_owned();
            }
            Message::FileHovered(path) => {
                self.hovered_file_label = format!("Bereit fuer Drop: {}", path.display());
            }
            Message::FileHoverCleared => {
                self.hovered_file_label =
                    "Datei in das Fenster ziehen, um die Analyse zu starten.".to_owned();
            }
            Message::ShowTooltip(tooltip_text) => {
                self.status_line = tooltip_text;
            }
            Message::FileDropped(path) => {
                if self.current_username().is_none() {
                    self.status_line =
                        "Bitte zuerst lokal anmelden, bevor du Artefakte analysierst.".to_owned();
                    return Task::none();
                };
                self.queue_pending_chat_share();
                let drop_world = match self.active_tab {
                    Tab::Gaming => Some(Tab::Gaming),
                    Tab::Media => Some(Tab::Media),
                    Tab::Research => Some(Tab::Research),
                    _ => None,
                };
                // Schnell-Entropie aus den ersten 4KB (synchron, <1ms)
                self.drop_quick_entropy = quick_file_entropy(&path);
                // Annotation-Modal anzeigen statt sofort zu analysieren
                self.drop_pending_path = Some(path);
                self.drop_pending_world = drop_world;
                self.drop_annotation_input = String::new();
                self.drop_source_date_input = String::new();
                self.pending_broadcast_hint = None;
                self.pending_visual_source_date_secs = None;
                self.status_line =
                    "Artefakt erkannt \u{2014} Broadcast-Hinweis optional, Quelldatum optional nur fuer Zeitgrafiken. Analyse startet nach Bestaetigung."
                    .to_owned();
            }
            // Nutzer tippt im Annotationsfeld
            Message::DropAnnotationChanged(value) => {
                self.drop_annotation_input = value;
            }
            Message::DropSourceDateChanged(value) => {
                self.drop_source_date_input = value.chars().take(24).collect();
            }
            // Nutzer bricht Drop ab
            Message::DropAnnotationCancelled => {
                self.drop_pending_path = None;
                self.drop_pending_world = None;
                self.pending_chat_partner = None;
                self.pending_chat_group_room_id = None;
                self.drop_annotation_input = String::new();
                self.drop_source_date_input = String::new();
                self.pending_broadcast_hint = None;
                self.pending_visual_source_date_secs = None;
                self.drop_quick_entropy = 0.0;
                self.status_line = "Drop abgebrochen.".to_owned();
            }
            // Nutzer bestaetigt: Analyse starten mit optional eingegebener Beschriftung
            Message::DropAnnotationConfirmed => {
                let manual_visual_source_date = match parse_visual_source_date_input(&self.drop_source_date_input) {
                    Ok(value) => value,
                    Err(err) => {
                        self.status_line = err;
                        return Task::none();
                    }
                };
                let Some(path) = self.drop_pending_path.take() else {
                    return Task::none();
                };
                let drop_world = self.drop_pending_world.take();
                let broadcast_hint = self.drop_annotation_input.trim().to_owned();
                self.pending_broadcast_hint = if broadcast_hint.is_empty() {
                    None
                } else {
                    Some(broadcast_hint)
                };
                self.pending_visual_source_date_secs = manual_visual_source_date;
                self.drop_annotation_input.clear();
                self.drop_source_date_input.clear();
                self.drop_quick_entropy = 0.0;
                let Some(username) = self.current_username() else {
                    return Task::none();
                };
                let launch_note = if let Some(world) = drop_world {
                    if !self.live_render_mode {
                        self.apply_live_render_mode(true);
                    }
                    self.active_tab = world;
                    match launch_dropped_artifact(&path, world) {
                        Ok(note) => note,
                        Err(err) => format!("Startpfad nicht verfuegbar ({err}) - Analyse laeuft trotzdem."),
                    }
                } else {
                    self.active_tab = Tab::Data;
                    "Datei-Analyse gestartet.".to_owned()
                };
                self.pending_analysis_world = drop_world;
                self.pending_analysis_path = Some(path.clone());
                if drop_world == Some(Tab::Gaming) {
                    self.active_gaming_game_id = Some(path.to_string_lossy().to_string());
                }
                self.analysis_running = true;
                self.analysis_progress = 0.18;
                self.analysis_status = format!(
                    "Artefakt erkannt. {} {}",
                    launch_note,
                    path.display()
                );
                self.hovered_file_label = format!("Drop uebernommen: {}", path.display());
                self.status_line = self.analysis_status.clone();
                let data_key = self.data_key_fork();
                return Task::perform(
                    analyze_file_for_register(path, username, data_key),
                    Message::FileAnalysisCompleted,
                );
            }
            Message::FileAnalysisCompleted(result) => {
                self.analysis_running = false;
                let pending_world = self.pending_analysis_world.take();
                let pending_path = self.pending_analysis_path.take();
                let pending_broadcast_hint = self.pending_broadcast_hint.take();
                let pending_visual_source_date_secs = self.pending_visual_source_date_secs.take();
                if pending_world != Some(Tab::Gaming) {
                    self.active_gaming_game_id = None;
                }
                match result {
                    Ok(result) => match self.state_store.add_register_entry(result.entry.clone()) {
                        Ok(_) => {
                            if pending_world == Some(Tab::Gaming) {
                                let game_hint = pending_path
                                    .as_ref()
                                    .and_then(|path| path.to_str())
                                    .unwrap_or(result.entry.full_path.as_str());
                                self.update_gaming_progress_from_file(game_hint, &result);
                            }
                            self.last_analysis = Some(result.snapshot.clone());
                            self.last_byte_hist = result.byte_hist.clone();
                            self.last_xor_delta = result.xor_delta.clone();
                            self.apply_projection_state(
                                result.capsule_state.clone(),
                                result.structure_map_state.clone(),
                                result.structure_map_nodes.clone(),
                                result.aelab_state.clone(),
                                result.compression_state.clone(),
                                result.reconstruction_state.clone(),
                            );
                            // --- FlowSphere History-Eintrag festhalten (erster Fund = Timestamp) ---
                            {
                                let stability = result.structure_map_state.coherence_score.clamp(0.0, 1.0);
                                let mut entry = FlowSphereEntry::from_capsule(
                                    &result.capsule_state,
                                    self.cascade_metrics.as_ref(),
                                    stability,
                                );
                                if let Some(src_ts) = result.source_date_secs {
                                    if src_ts > 0 {
                                        entry.source_timestamp_secs = Some(src_ts);
                                    }
                                }
                                if let Some(manual_ts) = pending_visual_source_date_secs {
                                    if manual_ts > 0 {
                                        entry.manual_timestamp_secs = Some(manual_ts);
                                    }
                                }
                                if let Some(broadcast_hint) = pending_broadcast_hint.clone() {
                                    if !broadcast_hint.is_empty() {
                                        entry.broadcast_hint = broadcast_hint.clone();
                                        if self.flow_sphere_broadcast_name.trim().is_empty() {
                                            self.flow_sphere_broadcast_name = broadcast_hint;
                                        }
                                    }
                                }
                                let visual_ts = entry.visual_timestamp_secs(self.temporal_metadata_consent);
                                // Deduplizieren: gleicher Hash + gleicher visueller Zeitbezug nur einmal
                                let is_dup = self.flow_sphere_history.iter()
                                    .any(|e| e.source_hash == entry.source_hash
                                          && e.visual_timestamp_secs(self.temporal_metadata_consent) == visual_ts);
                                if !is_dup {
                                    self.flow_sphere_history.push(entry.clone());
                                    self.flow_sphere_session_entries.push(entry);
                                    // Maximal 200 Eintraege in History
                                    if self.flow_sphere_history.len() > 200 {
                                        self.flow_sphere_history.remove(0);
                                    }
                                }
                            }
                            let keep_chat_view = self.pending_chat_partner.is_some()
                                || self.pending_chat_group_room_id.is_some();
                            let chat_share_status = match self.publish_pending_chat_share(&result) {
                                Ok(status) => status,
                                Err(err) => Some(format!("Chat-Ablage fehlgeschlagen: {err}")),
                            };
                            self.analysis_progress = 1.0;
                            let preview_upper = result.snapshot.preview_note.to_ascii_uppercase();
                            let malware_flag = preview_upper.contains("MALWARE")
                                || preview_upper.contains("QUARANTINE")
                                || preview_upper.contains("CRITICAL")
                                || preview_upper.contains("BLOCK")
                                || preview_upper.contains("DENY");
                            let obf_flag = preview_upper.contains("OBF");
                            let danger_hint = if malware_flag || obf_flag {
                                " | Warnsignal Malware/Obfuskation erkannt"
                            } else {
                                ""
                            };
                            self.analysis_status = format!(
                                "AEF erstellt: {} | {:.1}% Gewinn{} | {}",
                                result.snapshot.file_name,
                                result.snapshot.compression_gain_percent,
                                danger_hint,
                                result.snapshot.preview_note
                            );
                            // Hinweis auf FlowSphere-Broadcast falls bereits History-Einträge vorhanden.
                            // Kein Einfluss auf Metriken — nur Orientierung für den Nutzer.
                            if self.flow_sphere_history.len() >= 2 {
                                self.status_line = format!(
                                    "{} \u{2014} FlowSphere: Muster in History vorhanden \u{b7} evtl. Zusammenh\u{e4}nge oder Broadcast-\u{dc}berschneidung pr\u{fc}fen.",
                                    self.analysis_status
                                );
                            } else {
                                self.status_line = self.analysis_status.clone();
                            }
                            if let Some(chat_note) = chat_share_status {
                                self.status_line = format!("{} \u{2014} {}", self.status_line, chat_note);
                            }
                            self.active_tab = if keep_chat_view { Tab::Chat } else { Tab::Data };
                            // Auto-AEF: Gate bestanden (lossless >= 0.95 + Anker) → direkt encodieren
                            if let Some(aelab) = &result.aelab_state {
                                if aelab.lossless >= 0.95 && aelab.has_anchor {
                                    let src = PathBuf::from(&result.entry.full_path);
                                    let data_key = self.data_key_fork();
                                    self.status_line = format!(
                                        "{} \u{2014} AEF-Encoding l\u{e4}uft \u{2026}",
                                        self.analysis_status
                                    );
                                    return Task::perform(
                                        async move {
                                            let out_dir = crate::data_path("rust_shell/aef");
                                            std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
                                            let stem = src
                                                .file_stem()
                                                .and_then(|s| s.to_str())
                                                .unwrap_or("file");
                                            let out_path = out_dir.join(format!("{stem}.aef"));
                                            let vault = VaultStore::load_default().map_err(|e| e.to_string())?;
                                            let vault = Arc::new(RwLock::new(vault));
                                            let engine = Arc::new(EnginePipeline::new());
                                            let encoder = if let Some(dk) = data_key {
                                                AefEncoder::new(Arc::clone(&vault), Arc::clone(&engine)).withdatakey(dk)
                                            } else {
                                                AefEncoder::new(Arc::clone(&vault), Arc::clone(&engine))
                                            };
                                            encoder
                                                .encode_sync(&src, &out_path)
                                                .map(|_| out_path.to_string_lossy().to_string())
                                                .map_err(|e| e.to_string())
                                        },
                                        Message::AutoAefEncodeCompleted,
                                    );
                                }
                            }
                            self.refresh_security_snapshot(true, "file_loaded");
                            // Auto-AEF: Gate bestanden (lossless >= 0.95 + Anker) → direkt encodieren
                            if let Some(aelab) = &result.aelab_state {
                                if aelab.lossless >= 0.95 && aelab.has_anchor {
                                    let src = PathBuf::from(&result.entry.full_path);
                                    let data_key = self.data_key_fork();
                                    self.status_line = format!(
                                        "{} \u{2014} AEF-Encoding l\u{e4}uft \u{2026}",
                                        self.analysis_status
                                    );
                                    return Task::perform(
                                        async move {
                                            let out_dir = crate::data_path("rust_shell/aef");
                                            std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
                                            let stem = src
                                                .file_stem()
                                                .and_then(|s| s.to_str())
                                                .unwrap_or("file");
                                            let out_path = out_dir.join(format!("{stem}.aef"));
                                            let vault = VaultStore::load_default().map_err(|e| e.to_string())?;
                                            let vault = Arc::new(RwLock::new(vault));
                                            let engine = Arc::new(EnginePipeline::new());
                                            let encoder = if let Some(dk) = data_key {
                                                AefEncoder::new(Arc::clone(&vault), Arc::clone(&engine)).withdatakey(dk)
                                            } else {
                                                AefEncoder::new(Arc::clone(&vault), Arc::clone(&engine))
                                            };
                                            encoder
                                                .encode_sync(&src, &out_path)
                                                .map(|_| out_path.to_string_lossy().to_string())
                                                .map_err(|e| e.to_string())
                                        },
                                        Message::AutoAefEncodeCompleted,
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            self.pending_chat_partner = None;
                            self.pending_chat_group_room_id = None;
                            self.analysis_progress = 0.0;
                            self.analysis_status =
                                format!("Analyse konnte nicht gespeichert werden: {err}");
                            self.status_line = self.analysis_status.clone();
                        }
                    },
                    Err(err) => {
                        self.pending_chat_partner = None;
                        self.pending_chat_group_room_id = None;
                        self.analysis_progress = 0.0;
                        self.analysis_status = format!("Analyse fehlgeschlagen: {err}");
                        self.status_line = self.analysis_status.clone();
                    }
                }
            }
            Message::LiveRenderAnalysisCompleted(result) => {
                self.live_render_analysis_running = false;
                match result {
                    Ok(result) => {
                        let live_result_for_gaming = result.clone();
                        self.apply_projection_state(
                            result.capsule_state,
                            result.structure_map_state,
                            result.structure_map_nodes,
                            result.aelab_state,
                            result.compression_state,
                            result.reconstruction_state,
                        );
                        if self.tick_counter.saturating_sub(self.gaming_progress_last_live_update_tick) >= 12 {
                            if let (Some(game_hint), Some(username)) = (
                                self.active_gaming_game_id.clone(),
                                self.current_username(),
                            ) {
                                self.update_gaming_progress_from_live(
                                    &game_hint,
                                    &username,
                                    &live_result_for_gaming,
                                );
                                self.gaming_progress_last_live_update_tick = self.tick_counter;
                            }
                        }
                    }
                    Err(err) => {
                        self.status_line = format!("Live-Render Capsule fehlgeschlagen: {err}");
                    }
                }
            }
            Message::ReconstructPressed(entry_id) => {
                let Some(_) = self.current_username() else {
                    self.status_line = "Bitte zuerst lokal anmelden.".to_owned();
                    return Task::none();
                };
                let Some(entry) = self.entries().into_iter().find(|e| e.id == entry_id) else {
                    self.rekonstruktion_selected = Some(entry_id);
                    return Task::none();
                };
                self.rekonstruktion_selected = Some(entry_id);
                self.rekonstruktion_running = true;
                self.rekonstruktion_result = None;
                self.status_line = format!("Rekonstruktion gestartet: {}", entry.file_name);
                let aef_path = PathBuf::from(&entry.full_path);
                let out_dir = crate::data_path("rust_shell/reconstructed");
                let out_path = out_dir.join(&entry.file_name);
                let file_name = entry.file_name.clone();
                let data_key = self.data_key_fork();
                return Task::perform(
                    async move {
                        let vault = VaultStore::load_default().map_err(|e| e.to_string())?;
                        let vault = Arc::new(RwLock::new(vault));
                        let decoder = if let Some(dk) = data_key {
                            AefDecoder::new(vault).withdatakey(dk)
                        } else {
                            AefDecoder::new(vault)
                        };
                        decoder
                            .decode_sync(&aef_path, &out_path)
                            .map(|r| (file_name, r))
                            .map_err(|e| e.to_string())
                    },
                    Message::ReconstructionCompleted,
                );
            }
            Message::ReconstructionCompleted(result) => {
                self.rekonstruktion_running = false;
                let status = match &result {
                    Ok((name, r)) => {
                        if r.reconstruction_complete {
                            format!("Rekonstruktion abgeschlossen: {name}")
                        } else {
                            format!("Rekonstruktion unvollstaendig: {name} ({} Vault-Refs fehlen)", r.missing_vault_refs.len())
                        }
                    }
                    Err(err) => {
                        if err.contains("Magic Bytes") || err.contains("ungültig") {
                            "Rekonstruktion fehlgeschlagen: Keine AEF-Datei gefunden. Datei zuerst neu droppen.".to_owned()
                        } else {
                            format!("Rekonstruktion fehlgeschlagen: {err}")
                        }
                    }
                };
                self.status_line = status;
                self.rekonstruktion_result = Some(result);
            }
            Message::ExportPressed(entry_id) => {
                let Some(result) = &self.rekonstruktion_result else {
                    return Task::none();
                };
                if let Ok((file_name, r)) = result {
                    if r.reconstruction_complete {
                        let src = crate::data_path("rust_shell/reconstructed")
                            .join(file_name);
                        let dst = PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default())
                            .join("Downloads")
                            .join(file_name);
                        match fs::copy(&src, &dst) {
                            Ok(_) => {
                                self.status_line =
                                    format!("Exportiert nach Downloads: {file_name}");
                            }
                            Err(err) => {
                                self.status_line = format!("Export fehlgeschlagen: {err}");
                            }
                        }
                    }
                }
                let _ = entry_id;
            }
            Message::WindowResized(width, height) => {
                self.window_width = width;
                self.window_height = height;
            }
            Message::FlowSphereSnapshotSelected(idx) => {
                self.flow_sphere_snapshot_idx = idx;
            }
            Message::FlowSphereZoomIn => {
                self.flow_sphere_zoom = (self.flow_sphere_zoom + 0.10).clamp(0.60, 2.20);
            }
            Message::FlowSphereZoomOut => {
                self.flow_sphere_zoom = (self.flow_sphere_zoom - 0.10).clamp(0.60, 2.20);
            }
            Message::FlowSphereRotateLeft => {
                self.flow_sphere_rotation_offset -= 0.25;
            }
            Message::FlowSphereRotateRight => {
                self.flow_sphere_rotation_offset += 0.25;
            }
            Message::FlowSphereResetView => {
                self.flow_sphere_zoom = 1.0;
                self.flow_sphere_rotation_offset = 0.0;
            }
            Message::FlowSphereToggleViewMode => {
                self.flow_sphere_view_mode = !self.flow_sphere_view_mode;
                self.set_flow_sphere_focus(if self.flow_sphere_view_mode {
                    "internal_core"
                } else {
                    "external_links"
                });
            }
            Message::FlowSphereToggleInternal => {
                self.flow_sphere_show_internal = !self.flow_sphere_show_internal;
                if self.flow_sphere_show_internal {
                    self.flow_sphere_view_mode = true;
                    self.set_flow_sphere_focus("internal_core");
                }
            }
            Message::FlowSphereToggleExternal => {
                self.flow_sphere_show_external = !self.flow_sphere_show_external;
                if self.flow_sphere_show_external {
                    self.flow_sphere_view_mode = false;
                    self.set_flow_sphere_focus("external_links");
                }
            }
            Message::FlowSphereDomainRename(idx, value) => {
                if let Some(name) = self.flow_sphere_domain_names.get_mut(idx) {
                    *name = value.chars().take(40).collect();
                }
            }
            Message::FlowSphereBroadcastNameChanged(value) => {
                self.flow_sphere_broadcast_name = value.chars().take(48).collect();
            }
            Message::FlowSphereBroadcastConsentToggled => {
                self.flow_sphere_broadcast_opt_in = !self.flow_sphere_broadcast_opt_in;
                if !self.flow_sphere_broadcast_opt_in {
                    self.flow_sphere_broadcast_proposal = None;
                    self.flow_sphere_broadcast_visible = None;
                    self.flow_sphere_broadcast_outbound = None;
                    self.flow_sphere_broadcast_last_sent_at = None;
                }
                self.status_line = if self.flow_sphere_broadcast_opt_in {
                    "FlowSphere: Broadcast-Pruefung aktiviert. Vorschlaege koennen jetzt angefragt werden.".to_owned()
                } else {
                    "FlowSphere: Broadcast-Pruefung deaktiviert. Vorschlag und Sichtbarkeit wurden geloescht.".to_owned()
                };
            }
            Message::FlowSphereBroadcastSuggest => {
                if !self.flow_sphere_broadcast_opt_in {
                    self.status_line = "FlowSphere: Broadcast zuerst freigeben, dann Vorschlag aus der Analyse ableiten.".to_owned();
                } else {
                    self.flow_sphere_broadcast_proposal = self.flow_sphere_broadcast_suggestion();
                    self.status_line = if self.flow_sphere_broadcast_proposal.is_some() {
                        "FlowSphere: Broadcast-Vorschlag gefunden. Zustimmung steht aus.".to_owned()
                    } else {
                        "FlowSphere: Kein belastbarer Broadcast-Vorschlag gefunden.".to_owned()
                    };
                }
            }
            Message::FlowSphereBroadcastApprove => {
                if let Some(proposal) = self.flow_sphere_broadcast_proposal.take() {
                    self.flow_sphere_broadcast_visible = Some(proposal);
                    self.flow_sphere_broadcast_outbound = None;
                    self.flow_sphere_broadcast_last_sent_at = None;
                    self.status_line = "FlowSphere: Broadcast-Vorschlag lokal freigegeben. Outbound-Senden bleibt ein separater Schritt.".to_owned();
                }
            }
            Message::FlowSphereBroadcastDispatch => {
                if let Some(visible) = self.flow_sphere_broadcast_visible.clone() {
                    if self.flow_sphere_broadcast_outbound.as_deref() == Some(visible.as_str()) {
                        self.status_line = "FlowSphere: Diese Broadcast-Anfrage ist bereits als outbound markiert.".to_owned();
                    } else {
                        self.flow_sphere_broadcast_outbound = Some(visible);
                        self.flow_sphere_broadcast_last_sent_at = Some(current_epoch_label());
                        self.status_line = "FlowSphere: Broadcast-Anfrage als outbound markiert. Kontakt bleibt weiterhin explizit bestaetigungspflichtig.".to_owned();
                    }
                }
            }
            Message::FlowSphereBroadcastReject => {
                self.flow_sphere_broadcast_proposal = None;
                self.status_line = "FlowSphere: Broadcast-Vorschlag verworfen.".to_owned();
            }
            Message::FlowSphereExplain(key) => {
                self.set_flow_sphere_focus(key);
            }
            Message::FlowSphereNodeClicked(idx) => {
                if self.flow_sphere_view_mode {
                    self.set_flow_sphere_focus(format!("attractor_{}", idx));
                } else {
                    self.set_flow_sphere_focus(format!("swarm_{}", idx));
                }
            }
            Message::FlowSphereExportPressed => {
                let snapshot = serde_json::json!({
                    "snapshot_idx": self.flow_sphere_snapshot_idx,
                    "tick": self.tick_counter,
                    "entropy": self.structure_map_compression / 100.0,
                    "anchor_count": self.structure_map_nodes.last().map_or(0, |v| v.len()),
                    "stability": if self.structure_map_locked { 1.0 } else { self.structure_map_compression / 100.0 },
                });
                let path = crate::app_root().join(format!("data/flow_sphere_snapshot_{}.json", self.tick_counter));
                if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
                    let _ = std::fs::create_dir_all(crate::app_root().join("data"));
                    let _ = std::fs::write(&path, json);
                    self.status_line = format!("FlowSphere-Snapshot exportiert: {}", path.display());
                }
            }
            Message::FlowSphereSubTabSelected(subtab) => {
                self.flow_sphere_subtab = subtab;
            }
            Message::FlowSphereCompareSelected(idx) => {
                if self.flow_sphere_compare_idx == Some(idx) {
                    self.flow_sphere_compare_idx = None; // Toggle: nochmal klicken = deselektieren
                } else {
                    self.flow_sphere_compare_idx = Some(idx);
                }
            }
            Message::OpenFullTab(tab) => {
                self.active_tab = tab;
                self.app_mode = AppMode::Full;
                return window::get_latest().then(|id_opt| {
                    if let Some(id) = id_opt {
                        Task::batch(vec![
                            window::resize(id, iced::Size::new(FULL_WINDOW_WIDTH, FULL_WINDOW_HEIGHT)),
                            window::change_level(id, window::Level::Normal),
                        ])
                    } else {
                        Task::none()
                    }
                });
            }
            Message::SymbiontEventsReceived(result) => {
                self.symbiont_events_polling = false;
                if let Ok((new_events, last_idx)) = result {
                    self.symbiont_last_event_idx = last_idx;
                    for entry in new_events {
                        self.symbiont_events.push(entry);
                    }
                    // Keep ring buffer bounded at 200 entries
                    if self.symbiont_events.len() > 200 {
                        let drain_count = self.symbiont_events.len() - 200;
                        self.symbiont_events.drain(0..drain_count);
                    }
                }
            }
            Message::SymbiontEventsClearPressed => {
                self.symbiont_events.clear();
                self.symbiont_last_event_idx = 0;
            }
            Message::SymbiontInputChanged(s) => {
                self.symbiont_input = s;
            }
            Message::SymbiontRunPressed => {
                if self.symbiont_busy || self.symbiont_input.trim().is_empty() {
                    return Task::none();
                }
                self.symbiont_busy = true;
                self.symbiont_result = "Warte auf Antwort...".to_owned();
                let host = self.symbiont_host.clone();
                let port = self.symbiont_port;
                let method = self.symbiont_input.trim().to_owned();
                return Task::perform(
                    async move {
                        let result = symbiont_rpc::request_json(
                            &host,
                            port,
                            &method,
                            serde_json::json!({}),
                        )?;
                        Ok(serde_json::to_string_pretty(&result)
                            .unwrap_or_else(|_| result.to_string()))
                    },
                    Message::SymbiontResultReceived,
                );
            }
            Message::SymbiontResultReceived(result) => {
                self.symbiont_busy = false;
                self.symbiont_result = match result {
                    Ok(s)  => s,
                    Err(e) => format!("Fehler: {e}"),
                };
            }
            Message::HybridBridgeStartPressed => {
                match self.hybrid_bridge.start() {
                    Ok(()) => {
                        self.hybrid_bridge_error.clear();
                        self.status_line = "Hybrid-Bridge gestartet.".to_owned();
                    }
                    Err(err) => {
                        self.hybrid_bridge_error = err.clone();
                        self.status_line = format!("Hybrid-Bridge Start fehlgeschlagen: {err}");
                    }
                }
                self.poll_hybrid_state();
            }
            Message::HybridBridgeStopPressed => {
                match self.hybrid_bridge.stop() {
                    Ok(()) => {
                        self.status_line = "Hybrid-Bridge gestoppt.".to_owned();
                    }
                    Err(err) => {
                        self.hybrid_bridge_error = err.clone();
                        self.status_line = format!("Hybrid-Bridge Stop fehlgeschlagen: {err}");
                    }
                }
                self.poll_hybrid_state();
            }
            Message::HybridBridgeRestartPressed => {
                match self.hybrid_bridge.restart() {
                    Ok(()) => {
                        self.hybrid_bridge_error.clear();
                        self.status_line = "Hybrid-Bridge neu gestartet.".to_owned();
                    }
                    Err(err) => {
                        self.hybrid_bridge_error = err.clone();
                        self.status_line = format!("Hybrid-Bridge Restart fehlgeschlagen: {err}");
                    }
                }
                self.poll_hybrid_state();
            }
            Message::HybridSymbiontEnabled(enabled) => {
                match set_symbiont_enabled(enabled) {
                    Ok(()) => {
                        self.hybrid_symbiont_enabled = enabled;
                        self.status_line = if enabled {
                            "Symbiont-Link im Hybrid-Setup aktiviert.".to_owned()
                        } else {
                            "Symbiont-Link im Hybrid-Setup deaktiviert.".to_owned()
                        };
                        let _ = self.hybrid_bridge.restart();
                    }
                    Err(err) => {
                        self.hybrid_bridge_error = err.clone();
                        self.status_line = format!("Symbiont-Setting konnte nicht gespeichert werden: {err}");
                    }
                }
                self.poll_hybrid_state();
            }
            Message::HybridSymbiontEndpointPreset(host, port) => {
                match set_symbiont_endpoint(host.clone(), port) {
                    Ok(()) => {
                        self.symbiont_host = host;
                        self.symbiont_port = port;
                        self.status_line = format!(
                            "Symbiont-Endpoint auf {}:{} gesetzt.",
                            self.symbiont_host, self.symbiont_port
                        );
                        let _ = self.hybrid_bridge.restart();
                    }
                    Err(err) => {
                        self.hybrid_bridge_error = err.clone();
                        self.status_line = format!("Symbiont-Endpoint konnte nicht gespeichert werden: {err}");
                    }
                }
                self.poll_hybrid_state();
            }
            Message::ToggleMode => {
                if self.current_user.is_none() {
                    return Task::none();
                }
                self.app_mode = match self.app_mode {
                    AppMode::Overlay => AppMode::Full,
                    AppMode::Full => AppMode::Overlay,
                };
                let (new_w, new_h) = match self.app_mode {
                    AppMode::Full => (FULL_WINDOW_WIDTH, FULL_WINDOW_HEIGHT),
                    AppMode::Overlay => (OVERLAY_WINDOW_WIDTH, OVERLAY_WINDOW_HEIGHT),
                };
                let new_level = match self.app_mode {
                    AppMode::Full => window::Level::Normal,
                    AppMode::Overlay => window::Level::AlwaysOnTop,
                };// GÖDELSTOP: Wenn die innere Probe N× konvergiert ist, Analyse pausieren.
                    // Verhindert dass das System endlos seine eigene stabile Ausgabe analysiert.
                    // Reset erfolgt automatisch sobald sich das Signal wieder ändert (delta > 1%).
                    let godel_stop_active = self.live_render_godel_stop_skip >= 5
                        && self.live_render_invariant_streak >= 3;
                    if !self.live_render_analysis_running
                        && self.tick_counter % self.live_render_analysis_interval_ticks() == 0
                        && !self.live_render_last_frame.is_empty()
                        && !godel_stop_active
                        Task::batch(vec![
                            window::resize(id, iced::Size::new(new_w, new_h)),
                            window::change_level(id, new_level),
                        ])
                    } else {
                        Task::none()
                    }
                });
            }
            Message::LiveRenderToggle => {
                let enable = !self.live_render_mode;
                // Track whether this is an explicit user action (button press).
                // Explicit mode keeps live render active regardless of active tab.
                self.live_render_explicit = enable;
                self.apply_live_render_mode(enable);
                self.status_line = if enable {
                    "Live-Render-Modus aktiviert: Bitstream/XOR/Godel/Anchor laufen live.".to_owned()
                } else {
                    "Live-Render-Modus deaktiviert: passiver Modus aktiv.".to_owned()
                };
            }
            Message::Tick => {
                let mut queued_tasks: Vec<Task<Message>> = Vec::new();
                self.tick_counter = self.tick_counter.wrapping_add(1);
                if self.tick_counter % self.launcher_poll_interval_ticks() == 0 {
                    self.launcher_state.poll_processes();
                }
                if self.live_render_mode {
                    let previous_live_signal = self.live_render_last_frame.clone();
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.capture_live_render_frame();
                    })) {
                        Ok(()) => {}
                        Err(payload) => {
                            let panic_message = Self::panic_payload_to_string(payload.as_ref());
                            self.apply_live_render_mode(false);
                            self.status_line = format!(
                                "Live-Render wurde nach einem Laufzeitfehler deaktiviert: {panic_message}"
                            );
                            let _ = fs::create_dir_all("logs");
                            if let Ok(mut file) = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("logs/live_render_errors.log")
                            {
                                let _ = writeln!(
                                    file,
                                    "tick={} panic={}",
                                    self.tick_counter,
                                    panic_message
                                );
                            }
                        }
                    }
                    // GÖDELSTOP: Wenn die innere Probe N× konvergiert ist, Analyse pausieren.
                    // Verhindert dass das System endlos seine eigene stabile Ausgabe analysiert.
                    // Reset erfolgt automatisch sobald sich das Signal wieder ändert (delta > 1%).
                    let godel_stop_active = self.live_render_godel_stop_skip >= 5
                        && self.live_render_invariant_streak >= 3;
                    if !self.live_render_analysis_running
                        && self.tick_counter % self.live_render_analysis_interval_ticks() == 0
                        && !self.live_render_last_frame.is_empty()
                        && !godel_stop_active
                    {
                        self.live_render_analysis_running = true;
                        queued_tasks.push(Task::perform(
                            analyze_live_signal_for_shell(
                                self.live_render_last_frame.clone(),
                                previous_live_signal,
                                self.tick_counter,
                            ),
                            Message::LiveRenderAnalysisCompleted,
                        ));
                    }
                }
                if self.tick_counter % self.hybrid_state_poll_interval_ticks() == 0 {
                    self.poll_hybrid_state();
                }
                if self.tick_counter % self.backend_state_poll_interval_ticks() == 0 {
                    self.poll_backend_state();
                }
                // Poll swarm overlap contact requests (offset by half-interval to spread load).
                if self.tick_counter % self.swarm_overlap_poll_interval_ticks()
                    == self.swarm_overlap_poll_interval_ticks() / 2
                {
                    self.poll_swarm_overlap_events();
                }
                // Scan telemetry processes (offset 17 to spread load).
                if self.tick_counter % self.telemetry_scan_interval_ticks() == 17 {
                    let shield = self.telemetry_shield_enabled;
                    queued_tasks.push(Task::perform(
                        scan_telemetry_activity(shield),
                        Message::TelemetryScanResult,
                    ));
                }
                // Poll Symbiont live events while the server is running
                if self.tick_counter % self.symbiont_event_poll_interval_ticks() == 3
                    && self.hybrid_symbiont_running
                    && !self.symbiont_events_polling
                {
                    self.symbiont_events_polling = true;
                    let host = self.symbiont_host.clone();
                    let port = self.symbiont_port;
                    let since = self.symbiont_last_event_idx;
                    queued_tasks.push(Task::perform(
                        async move {
                            let result = symbiont_rpc::request_json(
                                &host,
                                port,
                                "aether/events",
                                serde_json::json!({ "since_idx": since, "limit": 30 }),
                            )?;
                            let last_idx = result
                                .get("last_idx")
                                .and_then(|v: &serde_json::Value| v.as_u64())
                                .unwrap_or(since);
                            let entries: Vec<String> = result
                                .get("events")
                                .and_then(|v: &serde_json::Value| v.as_array())
                                .map(|arr: &Vec<serde_json::Value>| {
                                    arr.iter()
                                        .filter_map(|e: &serde_json::Value| {
                                            let idx = e.get("idx")?.as_u64()?;
                                            let ts = e.get("ts")?.as_f64()?;
                                            let kind = e.get("kind")?.as_str()?;
                                            let detail = e
                                                .get("detail")
                                                .and_then(|v: &serde_json::Value| v.as_str())
                                                .unwrap_or("");
                                            Some(format!(
                                                "[{idx}] {ts:.3}  {kind}  {detail}"
                                            ))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            Ok((entries, last_idx))
                        },
                        Message::SymbiontEventsReceived,
                    ));
                }
                let analysis_visual_tab =
                    matches!(self.active_tab, Tab::FlowSphere | Tab::StructureMap | Tab::ADE);
                if analysis_visual_tab && !self.live_render_mode && self.capsule_state.is_none() {
                    if self.structure_map_nodes.iter().all(|ring| ring.is_empty())
                        || self.tick_counter % 2 == 0
                    {
                        self.step_structure_map();
                    }
                }
                if self.active_tab == Tab::StructureMap || self.active_tab == Tab::ADE || self.active_tab == Tab::FlowSphere {
                    return if queued_tasks.is_empty() {
                        Task::none()
                    } else {
                        Task::batch(queued_tasks)
                    };
                }
                return if queued_tasks.is_empty() {
                    Task::none()
                } else {
                    Task::batch(queued_tasks)
                };
            }
            Message::SecurityRecheck => {
                self.refresh_security_snapshot(true, "manual_recheck");
                self.status_line = "Security-Recheck abgeschlossen.".to_owned();
            }
            Message::TelemetryShieldToggle(enabled) => {
                self.telemetry_shield_enabled = enabled;
                apply_telemetry_firewall(enabled);
                self.status_line = if enabled {
                    self.ui_text(
                        "Telemetrie-Firewall aktiviert. Erkennung l\u{e4}uft im Hintergrund.",
                        "Telemetry firewall enabled. Detection running in background.",
                    ).to_owned()
                } else {
                    self.ui_text(
                        "Telemetrie-Shield deaktiviert.",
                        "Telemetry shield disabled.",
                    ).to_owned()
                };
                return Task::perform(
                    scan_telemetry_activity(enabled),
                    Message::TelemetryScanResult,
                );
            }
            Message::TemporalMetadataConsentToggle(enabled) => {
                self.temporal_metadata_consent = enabled;
                // In settings.json persistieren
                let p = std::path::Path::new("data/settings.json");
                if let Ok(raw) = std::fs::read_to_string(p) {
                    if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&raw) {
                        val["temporal_metadata_consent"] = serde_json::Value::Bool(enabled);
                        let _ = std::fs::write(p, serde_json::to_string_pretty(&val)
                            .unwrap_or_default());
                    }
                }
                self.status_line = if enabled {
                    self.ui_text(
                        "Metadaten-Datum aktiv: Header-/Erstellungsdaten treiben die Zeitachsen, manuelle Daten bleiben Fallback.",
                        "Metadata dates active: header/creation dates drive timelines, manual dates remain fallback.",
                    ).to_owned()
                } else {
                    self.ui_text(
                        "Metadaten-Datum deaktiviert. Manuelle Quelldaten bleiben aktiv, sonst gilt der Analysezeitpunkt.",
                        "Metadata dates disabled. Manual source dates stay active, otherwise analysis time is used.",
                    ).to_owned()
                };
            }
            Message::TelemetryScanResult(alerts) => {
                if !alerts.is_empty() {
                    let new_alerts: Vec<TelemetryAlert> = alerts
                        .into_iter()
                        .filter(|a| !self.telemetry_alerts.iter().any(|e| e.process == a.process && e.remote == a.remote))
                        .collect();
                    self.telemetry_alerts.extend(new_alerts);
                    if self.telemetry_alerts.len() > 30 {
                        self.telemetry_alerts.drain(0..self.telemetry_alerts.len() - 30);
                    }
                }
            }
            // ── Permanent-Modus / Overlay-Close-Guard ─────────────────────────────
            Message::PersistentModeToggle(val) => {
                self.persistent_mode = val;
                let base_message = if val {
                    self.ui_text(
                        "Schliessen nur ueber Einstellungen aktiv: X minimiert zur Leiste.",
                        "Close only via settings enabled: X collapses to bar.",
                    )
                } else {
                    self.ui_text(
                        "Schliessen nur ueber Einstellungen deaktiviert: X beendet das Programm.",
                        "Close only via settings disabled: X closes the program.",
                    )
                };
                self.status_line = match write_shell_preferences(
                    self.runtime_profile,
                    self.persistent_mode,
                    self.ui_language,
                ) {
                    Ok(()) => base_message.to_owned(),
                    Err(err) => format!("{} Speicherung fehlgeschlagen: {}", base_message, err),
                };
            }
            Message::ForceQuit => {
                return window::get_latest().then(|id_opt| {
                    if let Some(id) = id_opt {
                        window::close(id)
                    } else {
                        Task::none()
                    }
                });
            }
            Message::CloseWindowRequested(win_id) => {
                if self.persistent_mode {
                    // Collapse to always-on-top overlay bar instead of quitting.
                    self.app_mode = AppMode::Overlay;
                    self.status_line = self.ui_text(
                        "Läuft im Hintergrund. Escape oder Klick → Vollansicht.",
                        "Running in background. Escape or click → full view.",
                    ).to_owned();
                    return Task::batch(vec![
                        window::resize(win_id, iced::Size::new(OVERLAY_WINDOW_WIDTH, OVERLAY_WINDOW_HEIGHT)),
                        window::change_level(win_id, window::Level::AlwaysOnTop),
                    ]);
                } else {
                    return window::close(win_id);
                }
            }
            Message::TutorialDismissed => {
                self.show_tutorial = false;
                self.status_line = "Tutorial ausgeblendet.".to_owned();
            }
            // ── Launcher Dashboard Messages ────────────────────────────────────────
            Message::LauncherModeSelected(mode) => {
                self.launcher_state.mode = mode;
                self.launcher_state.log(format!("[LAUNCHER] Mode switched to: {:?}", mode));
                self.status_line = format!("Launcher Mode: {}", mode.label());
            }
            Message::LauncherServiceStartPressed(service_id) => {
                match self.launcher_state.start_service(&service_id) {
                    Ok(()) => {
                        self.status_line = format!("Service {} started", service_id);
                    }
                    Err(err) => {
                        self.launcher_state.log(format!("[ERROR] Failed to start {}: {}", service_id, err));
                        self.status_line = format!("Error: {}", err);
                    }
                }
            }
            Message::LauncherServiceStopPressed(service_id) => {
                match self.launcher_state.stop_service(&service_id) {
                    Ok(()) => {
                        self.status_line = format!("Service {} stopped", service_id);
                    }
                    Err(err) => {
                        self.launcher_state.log(format!("[ERROR] Failed to stop {}: {}", service_id, err));
                        self.status_line = format!("Error: {}", err);
                    }
                }
            }
            Message::LauncherBuildTaskPressed(task_id) => {
                match self.launcher_state.mark_build_task_running(&task_id) {
                    Ok(task_name) => {
                        self.status_line = format!("Build task {} started", task_name);
                        if let Some(task) = self.launcher_state.build_task(&task_id) {
                            return Task::perform(
                                async move { crate::launcher_dashboard::run_build_task(task) },
                                move |result| Message::LauncherBuildTaskCompleted(task_id.clone(), result),
                            );
                        }
                        self.launcher_state.fail_build_task(&task_id, "task disappeared after scheduling");
                        self.status_line = format!("Error: task {} unavailable", task_id);
                    }
                    Err(err) => {
                        self.launcher_state.log(format!("[ERROR] Failed to execute {}: {}", task_id, err));
                        self.status_line = format!("Error: {}", err);
                    }
                }
            }
            Message::LauncherBuildTaskCompleted(task_id, result) => {
                match result {
                    Ok(build_result) => {
                        let exit_code = build_result.exit_code;
                        let task_name = build_result.task_name.clone();
                        self.launcher_state.finish_build_task(&build_result);
                        if exit_code == 0 {
                            self.status_line = format!("Build task {} completed", task_name);
                        } else {
                            self.status_line = format!("Build task {} failed with exit {}", task_name, exit_code);
                        }
                    }
                    Err(err) => {
                        self.launcher_state.fail_build_task(&task_id, &err);
                        self.status_line = format!("Error: {}", err);
                    }
                }
            }
            Message::LauncherLogsClearPressed => {
                self.launcher_state.unified_log.clear();
                self.launcher_state.log("Logs cleared".to_string());
                self.status_line = "Launcher logs cleared".to_owned();
            }
            Message::SwarmConsentToggled(enabled) => {
                match write_swarm_consent(enabled) {
                    Ok(()) => {
                        self.swarm_consented = enabled;
                        self.status_line = if enabled {
                            "Swarm-Teilnahme aktiviert. Nur strukturelle Fingerabdrücke werden geteilt.".to_owned()
                        } else {
                            "Swarm-Teilnahme deaktiviert.".to_owned()
                        };
                    }
                    Err(err) => {
                        self.status_line = format!("Swarm-Consent konnte nicht gespeichert werden: {err}");
                    }
                }
            }
            Message::SwarmOverlapAccepted(key) => {
                if let Some(req) = self
                    .swarm_overlap_requests
                    .iter()
                    .find(|r| r.anchor_hash_a == key)
                    .cloned()
                {
                    self.swarm_overlap_requests.retain(|r| r.anchor_hash_a != key);
                    // Open a private chat thread with the remote node's public key as partner ID.
                    self.selected_private_partner = Some(req.remote_node_pubkey.clone());
                    self.chat_context = ChatContext::Private;
                    self.active_tab = Tab::Chat;
                    self.status_line = format!(
                        "Domänen-Anfrage angenommen · Privater Thread mit {} geöffnet.",
                        &req.remote_node_pubkey.chars().take(16).collect::<String>()
                    );
                }
            }
            Message::SwarmOverlapDeclined(key) => {
                self.swarm_overlap_requests.retain(|r| r.anchor_hash_a != key);
                self.status_line = "Domänen-Anfrage abgelehnt.".to_owned();
            }
            // ─────────────────────────────────────────────────────────────────────
            Message::AnchorGroupSelected(index) => self.selected_anchor_group = index,
            Message::AutoAefEncodeCompleted(result) => match result {
                Ok(path) => {
                    self.status_line = format!(
                        "AEF gespeichert: {path} \u{2014} Rekonstruktion jetzt verf\u{fc}gbar."
                    );
                }
                Err(err) => {
                    self.status_line = format!("AEF-Encoding fehlgeschlagen: {err}");
                }
            },
        }
        Task::none()
    }

    fn view_overlay(&self) -> Element<'_, Message> {
        let entropy_str = if self.backend_state_loaded {
            format!("E {:.2}", self.backend_entropy_mean)
        } else {
            "E --".to_owned()
        };
        let vault_str = if self.backend_state_loaded {
            format!("V {}", self.backend_vault_main)
        } else {
            "V --".to_owned()
        };
        let cpu_str = if self.backend_state_loaded {
            format!("CPU {:.0}%", self.backend_cpu_pct)
        } else {
            "CPU --".to_owned()
        };

        let quick_button = |label: String, tab: Tab| {
            button(text(label).size(11).color(c(TEXT_H())))
                .on_press(Message::OpenFullTab(tab))
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(c(BG_CARD2()))),
                    border: Border {
                        color: c(BORDER()),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    text_color: c(TEXT_M()),
                    ..Default::default()
                })
                .padding([3, 8])
        };

        let bar = row![
            text("⬡ AETHER").size(13).color(c(ACCENT())),
            text(entropy_str).size(12).color(c(TEXT_M())),
            text(vault_str).size(12).color(c(TEXT_M())),
            text(cpu_str).size(12).color(c(TEXT_M())),
            quick_button(self.ui_text("Kontrolle", "Control").to_owned(), Tab::Control),
            quick_button(self.ui_text("Swarm Ops", "Swarm Ops").to_owned(), Tab::SwarmOps),
            quick_button(self.ui_text("Threat", "Threat").to_owned(), Tab::ADE),
            quick_button(self.ui_text("FlowSphere", "FlowSphere").to_owned(), Tab::FlowSphere),
            quick_button(self.ui_text("Delta", "Delta").to_owned(), Tab::StructureMap),
            quick_button(self.ui_text("Privatsphaere", "Privacy").to_owned(), Tab::Privacy),
            quick_button(self.ui_text("Dateien", "Files").to_owned(), Tab::Data),
            quick_button(self.ui_text("Verlauf", "Logs").to_owned(), Tab::Logs),
            quick_button(self.ui_text("Chat", "Chat").to_owned(), Tab::Chat),
            button(text(if self.live_render_mode { "Live: ON" } else { "Live: OFF" }).size(11).color(c(TEXT_H())))
                .on_press(Message::LiveRenderToggle)
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(c(BG_CARD2()))),
                    border: Border {
                        color: c(BORDER_ACT()),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    text_color: c(TEXT_M()),
                    ..Default::default()
                })
                .padding([3, 8]),
            button(text(self.ui_text("▲ Vollansicht", "▲ Open Full View")).size(12).color(c(TEXT_H())))
                .on_press(Message::OpenFullTab(self.active_tab))
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(c(BG_CARD2()))),
                    border: Border { color: c(BORDER_ACT()), width: 1.0, radius: 4.0.into() },
                    text_color: c(ACCENT()),
                    ..Default::default()
                })
                .padding([4, 10]),
        ]
        .spacing(16)
        .align_y(iced::Alignment::Center)
        .padding([0, 16]);

        // XOR / Bytestream Compare strip (36px below the main bar)
        let bytestream_strip = canvas::Canvas::new(BytestreamBarScene {
            hist: self.last_byte_hist.clone(),
            delta: self.last_xor_delta.clone(),
            has_data: !self.last_byte_hist.is_empty(),
        })
        .width(Length::Fill)
        .height(Length::Fixed(36.0));

        let overlay_col = column![
            container(bar)
                .width(Length::Fill)
                .height(Length::Fixed(36.0))
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(c(BG_BASE()))),
                    border: Border { color: c(BORDER()), width: 1.0, radius: 0.0.into() },
                    ..Default::default()
                }),
            bytestream_strip,
        ];

        container(overlay_col)
            .width(Length::Fill)
            .height(Length::Fixed(72.0))
            .style(|_: &Theme| container::Style {
                background: Some(Background::Color(c(BG_BASE()))),
                border: Border { color: c(BORDER()), width: 1.0, radius: 0.0.into() },
                ..Default::default()
            })
            .into()
    }

    /// Drop-Annotation-Modal: erscheint wenn eine Datei fallen gelassen wurde,
    /// bevor die Analyse startet. Zeigt Strukturvorschau + optionales Freitext-Feld.
    /// Semantik bleibt beim Nutzer — nur Struktur geht in die Berechnung.
    fn view_drop_annotation(&self) -> Element<'_, Message> {
        let path = match &self.drop_pending_path {
            Some(p) => p,
            None => return column![].into(),
        };
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unbekannte Datei");
        let file_size_label = std::fs::metadata(path)
            .map(|m| {
                let bytes = m.len();
                if bytes < 1024 {
                    format!("{} B", bytes)
                } else if bytes < 1_048_576 {
                    format!("{:.1} KB", bytes as f32 / 1024.0)
                } else {
                    format!("{:.1} MB", bytes as f32 / 1_048_576.0)
                }
            })
            .unwrap_or_else(|_| "? B".to_owned());

        let entropy = self.drop_quick_entropy;
        let entropy_label = if entropy < 2.0 {
            "sehr niedrig \u{2014} stark strukturiert"
        } else if entropy < 4.0 {
            "niedrig \u{2014} regelm\u{00e4}\u{00df}ig strukturiert"
        } else if entropy < 6.0 {
            "mittel \u{2014} gemischte Entropie"
        } else if entropy < 7.2 {
            "hoch \u{2014} dicht oder komprimiert"
        } else {
            "maximal \u{2014} zufllig oder verschl\u{00fc}sselt"
        };
        let entropy_fraction = (entropy / 8.0).clamp(0.0, 1.0);

        let accent = Color::from_rgb8(0x74, 0x8B, 0xFF);
        let dim = Color::from_rgba(0.55, 0.60, 0.75, 0.85);
        let green = Color::from_rgb8(0x64, 0xFF, 0xB8);

        let card = container(
            column![
                text("\u{25c6} Artefakt erkannt").size(14).color(accent),
                iced::widget::Space::new(Length::Shrink, Length::Fixed(10.0)),
                text(format!("  {}", file_name))
                    .size(16)
                    .color(Color::WHITE),
                text(format!("  {}", file_size_label))
                    .size(11)
                    .color(dim),
                iced::widget::Space::new(Length::Shrink, Length::Fixed(14.0)),
                text("  Strukturvorschau (erste 4 KB):").size(11).color(dim),
                progress_bar(0.0..=1.0, entropy_fraction)
                    .height(8)
                    .style(move |_: &Theme| progress_bar::Style {
                        background: Background::Color(
                            Color::from_rgba(0.12, 0.16, 0.28, 0.8),
                        ),
                        bar: Background::Color(green),
                        border: Border::default(),
                    }),
                text(format!(
                    "  {:.2} bit/byte \u{2014} {}",
                    entropy, entropy_label
                ))
                .size(10)
                .color(dim),
                iced::widget::Space::new(Length::Shrink, Length::Fixed(14.0)),
                text("  Was ist das f\u{00fc}r dich? (optional \u{2014} bleibt dein Wissen)")
                    .size(11)
                    .color(dim),
                text_input(
                    "Broadcast-Hinweis, keine Kategorie \u{2022} beeinflusst keine Cluster oder Dynamiken",
                    &self.drop_annotation_input,
                )
                .on_input(Message::DropAnnotationChanged)
                .on_submit(Message::DropAnnotationConfirmed)
                .padding([8, 10])
                .size(13),
                iced::widget::Space::new(Length::Shrink, Length::Fixed(14.0)),
                text("  Quelldatum oder Bezugsdatum (optional \u{2014} nur fuer Zeitachsen, nie fuer die Analyse)")
                    .size(11)
                    .color(dim),
                text_input(
                    "YYYY-MM-DD oder DD.MM.YYYY",
                    &self.drop_source_date_input,
                )
                .on_input(Message::DropSourceDateChanged)
                .on_submit(Message::DropAnnotationConfirmed)
                .padding([8, 10])
                .size(13),
                iced::widget::Space::new(Length::Shrink, Length::Fixed(12.0)),
                text("  Das Label dient nur der Broadcast-Abwaegung. Das Datum speist nur Grafik, Dynamiken und Overlaps.")
                    .size(10)
                    .color(dim),
                iced::widget::Space::new(Length::Shrink, Length::Fixed(12.0)),
                row![
                    button(text("Analysieren").size(13))
                        .on_press(Message::DropAnnotationConfirmed)
                        .padding([10, 24])
                        .style(move |_: &Theme, _| button::Style {
                            background: Some(Background::Color(Color::from_rgba(
                                0.45, 0.27, 0.92, 0.85,
                            ))),
                            border: Border {
                                color: accent,
                                width: 1.2,
                                radius: 6.0.into(),
                            },
                            text_color: Color::WHITE,
                            ..Default::default()
                        }),
                    iced::widget::Space::new(Length::Fixed(12.0), Length::Shrink),
                    button(text("Abbrechen").size(12).color(dim))
                        .on_press(Message::DropAnnotationCancelled)
                        .padding([10, 18])
                        .style(move |_: &Theme, _| button::Style {
                            background: Some(Background::Color(Color::from_rgba(
                                0.08, 0.12, 0.22, 0.85,
                            ))),
                            border: Border {
                                color: Color::from_rgba(0.25, 0.28, 0.45, 0.6),
                                width: 1.0,
                                radius: 6.0.into(),
                            },
                            text_color: dim,
                            ..Default::default()
                        }),
                ]
                .align_y(Alignment::Center),
            ]
            .padding([24, 28])
            .width(Length::Shrink),
        )
        .max_width(540)
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.06, 0.11, 0.22, 0.97))),
            border: Border {
                color: accent,
                width: 1.2,
                radius: 12.0.into(),
            },
            ..Default::default()
        });

        // Zentriert auf dunklem Hintergrund (ersetzt die normale Ansicht w\u{00e4}hrend des Popups)
        container(card)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .align_y(iced::alignment::Vertical::Center)
            .style(|_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgba(
                    0.01, 0.03, 0.10, 0.93,
                ))),
                ..Default::default()
            })
            .into()
    }

    fn view_symbiont(&self) -> Element<'_, Message> {
        let bridge_state = if self.hybrid_bridge_running { "online" } else { "offline" };
        let sym_state = if self.hybrid_symbiont_running { "online" } else { "offline" };
        let vscode_state = if self.vscode_symbiont_active { "online" } else { "offline" };
        let status = if self.backend_state_loaded {
            format!(
                "Backend aktiv | Entropy {:.2} | Vault {}",
                self.backend_entropy_mean,
                self.backend_vault_main,
            )
        } else {
            "Backend noch nicht geladen. Overlay laeuft trotzdem weiter.".to_owned()
        };

        let events_column = if self.symbiont_events.is_empty() {
            column![
                text(if self.hybrid_symbiont_running {
                    "Warte auf Symbiont-Ereignisse ..."
                } else {
                    "Symbiont offline - Bridge starten, um Events zu empfangen."
                })
                .size(11)
                .color(c(TEXT_D()))
            ]
            .spacing(2)
        } else {
            self.symbiont_events
                .iter()
                .rev()
                .take(24)
                .fold(Column::new().spacing(8), |col, event| {
                    col.push(
                        container(
                            column![
                                text(event).size(11).color(c(TEXT_M())),
                            ]
                            .spacing(2),
                        )
                        .padding([8, 10])
                        .style(|_: &Theme| container::Style {
                            background: Some(Background::Color(Color::from_rgba(0.08, 0.13, 0.18, 0.92))),
                            border: Border {
                                color: Color::from_rgba(0.24, 0.54, 0.58, 0.90),
                                width: 1.0,
                                radius: 8.0.into(),
                            },
                            ..Default::default()
                        })
                    )
                })
        };

        let sym_inner = container(
            column![
                text("Symbiont Control").size(28).color(c(TEXT_H())),
                text("Zentrale Stelle fuer Signal- und Strukturanalyse. Symbiont-Module leben teils im Backend, hier bekommst du klare Einstiegspunkte.")
                    .size(13)
                    .color(c(TEXT_M())),
                container(
                    column![
                        text("Hybrid Bridge: Python-Bruecke zwischen Rust-Core und Python-Modulen. Start/Stop/Restart startet den Prozess modules/hybrid_bridge.py.").size(11).color(c(TEXT_D())),
                        text("Symbiont: Das Python-Backend (aether-symbiont/server/symbiont_server.py) stellt Vault-Daten und Analyse-Ergebnisse ueber IPC bereit.").size(11).color(c(TEXT_D())),
                        text("WebSocket: Echtzeit-Kanal zwischen Symbiont-Backend und Rust-Shell. Aktiv wenn Hybrid Bridge online ist.").size(11).color(c(TEXT_D())),
                        text("SymbiontLink: Verbindungsstatus zum VS-Code-Plugin (aether-symbiont Extension). Zeigt ob IDE-Integration aktiv ist.").size(11).color(c(TEXT_D())),
                        text("Runtime Hybrid / Runtime Web: Betriebsmodi des Backends. Hybrid = Python+Rust gemischt, Web = Browser-Bridge aktiv.").size(11).color(c(TEXT_D())),
                        text("Kybernetik II: Das System beobachtet sich selbst. Je mehr Muster im Vault, desto effizienter werden neue Analysen \u{2014} alte Hardware wird wertvoller.").size(11).color(c(TEXT_D())),
                    ]
                    .spacing(6)
                )
                .padding(12)
                .style(panel_frame_style),
                container(text(status).size(12).color(c(TEXT_D())))
                    .padding(10)
                    .style(panel_frame_style),
                row![
                    cyber_kpi_card(
                        "Entropy Mean",
                        format!("{:.2}", self.backend_entropy_mean),
                        "aus IPC Bridge",
                        Color::from_rgb8(0x3F, 0xBA, 0xC2),
                        "sym_entropy"
                    ),
                    cyber_kpi_card(
                        "Anchor Count",
                        format!("{}", self.backend_anchor_count),
                        "stream health",
                        Color::from_rgb8(0x5A, 0xAE, 0x84),
                        "sym_anchor"
                    ),
                    cyber_kpi_card(
                        "Local Users",
                        format!("{}", self.auth_store.user_count()),
                        "symbiont scope",
                        Color::from_rgb8(0xC7, 0xA0, 0x4A),
                        "sym_users"
                    ),
                ]
                .spacing(10),
                row![
                    button(text("Open Data Analysis").size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::Data))
                        .padding([8, 12])
                        .style(primary_button_style),
                    button(text("Open Threat Analysis").size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::ADE))
                        .padding([8, 12])
                        .style(primary_button_style),
                    button(text("Open Chat").size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::Chat))
                        .padding([8, 12])
                        .style(primary_button_style),
                ]
                .spacing(10),
                container(
                    column![
                        row![
                            text("Hybrid Bridge:").size(12).color(c(TEXT_D())),
                            button(text(format!(" {} (?)", bridge_state)).size(12).color(c(TEXT_H())))
                                .on_press(Message::ShowTooltip("Hybrid Bridge: Python-Bruecke zwischen Rust-Core und Python-Modulen.".to_owned()))
                                .style(secondary_button_style)
                                .padding([2, 6]),
                            text("| Symbiont:").size(12).color(c(TEXT_D())),
                            button(text(format!(" {} (?)", sym_state)).size(12).color(c(TEXT_H())))
                                .on_press(Message::ShowTooltip("Symbiont: Python-Backend fuer Vault- und Analyse-Daten ueber IPC.".to_owned()))
                                .style(secondary_button_style)
                                .padding([2, 6]),
                        ]
                        .spacing(4)
                        .align_y(Alignment::Center),
                        row![
                            text("VS Code Symbiont:").size(12).color(c(TEXT_D())),
                            button(text(format!(" {} (?)", vscode_state)).size(12).color(c(TEXT_H())))
                                .on_press(Message::ShowTooltip("SymbiontLink: Status der VS-Code-Integration.".to_owned()))
                                .style(secondary_button_style)
                                .padding([2, 6]),
                            button(text(format!(" {} ", if self.vscode_symbiont_mode.trim().is_empty() { "no mode" } else { &self.vscode_symbiont_mode })).size(12).color(c(TEXT_M())))
                                .on_press(Message::ShowTooltip(format!("VS Code Symbiont Mode: {}", if self.vscode_symbiont_mode.trim().is_empty() { "none" } else { &self.vscode_symbiont_mode })))
                                .style(secondary_button_style)
                                .padding([2, 4]),
                        ]
                        .spacing(2)
                        .align_y(Alignment::Center),
                        row![
                            text("Yggdrasil P2P:").size(12).color(c(TEXT_D())),
                            {
                                let ygg_state = if self.hybrid_yggdrasil_running { "online" } else { "offline" };
                                let ygg_color = if self.hybrid_yggdrasil_running {
                                    Color::from_rgb8(0x3A, 0xC2, 0x72)
                                } else {
                                    Color::from_rgb8(0xC2, 0x4A, 0x3A)
                                };
                                button(text(format!(" {} (?)", ygg_state)).size(12).color(ygg_color))
                                    .on_press(Message::ShowTooltip(
                                        "Yggdrasil: IPv6-Overlay-Mesh fuer P2P-Konnektivitaet zwischen Knoten. Adresse beginnt mit 200::/7.".to_owned()
                                    ))
                                    .style(secondary_button_style)
                                    .padding([2, 6])
                            },
                            {
                                let addr_display = if self.hybrid_yggdrasil_addr.is_empty() {
                                    "keine Adresse".to_owned()
                                } else {
                                    format!("[{}]", &self.hybrid_yggdrasil_addr)
                                };
                                button(text(addr_display).size(11).color(c(TEXT_D())))
                                    .on_press(Message::ShowTooltip(format!(
                                        "Eigene Yggdrasil-Adresse: {}",
                                        if self.hybrid_yggdrasil_addr.is_empty() { "noch nicht aktiv" } else { &self.hybrid_yggdrasil_addr }
                                    )))
                                    .style(secondary_button_style)
                                    .padding([2, 6])
                            },
                        ]
                        .spacing(4)
                        .align_y(Alignment::Center),
                        row![
                            button(text("Bridge Start").size(12).color(c(TEXT_H())))
                                .on_press(Message::HybridBridgeStartPressed)
                                .padding([8, 12])
                                .style(primary_button_style),
                            button(text("Bridge Restart").size(12).color(c(TEXT_H())))
                                .on_press(Message::HybridBridgeRestartPressed)
                                .padding([8, 12])
                                .style(primary_button_style),
                            button(text("Bridge Stop").size(12).color(c(TEXT_H())))
                                .on_press(Message::HybridBridgeStopPressed)
                                .padding([8, 12])
                                .style(secondary_button_style),
                        ]
                        .spacing(10),
                    ]
                    .spacing(8)
                )
                .padding(10)
                .style(panel_frame_style),
                // ─── Kybernetik II — Selbstoptimierung ───────────────────────────────
                {
                    let teal_co  = Color::from_rgb8(0x3F, 0xBA, 0xC2);
                    let green_ok = Color::from_rgb8(0x4C, 0xD9, 0x6E);
                    let amber_co = Color::from_rgb8(0xD4, 0xA0, 0x42);
                    let gain = self.last_analysis.as_ref()
                        .map(|s| s.compression_gain_percent)
                        .unwrap_or(0.0);
                    let vault_conv = (self.backend_anchor_count as f32
                        / (self.backend_anchor_count as f32 + 100.0)).clamp(0.0, 1.0);
                    let delta_conv_pct = self.cascade_metrics.as_ref()
                        .map(|m| m.delta_convergence as f32 * 100.0)
                        .unwrap_or(0.0);
                    let noether_pct = self.cascade_metrics.as_ref()
                        .map(|m| m.noether_consistency as f32 * 100.0)
                        .unwrap_or(0.0);
                    let trust_pct = self.cascade_metrics.as_ref()
                        .map(|m| m.trust_score as f32 * 100.0)
                        .unwrap_or(0.0);
                    let opt_rows: Vec<Element<'_, Message>> = vec![
                        row![
                            text("Vault-Konvergenz").size(11).color(c(TEXT_D())).width(Length::Fixed(160.0)),
                            progress_bar(0.0..=1.0, vault_conv).height(6).width(Length::Fixed(110.0)),
                            text(format!("{} Anker \u{2014} weniger Compute je mehr Wissen",
                                self.backend_anchor_count)).size(10).color(teal_co),
                        ].spacing(8).align_y(Alignment::Center).into(),
                        row![
                            text("Lossless \u{0394}").size(11).color(c(TEXT_D())).width(Length::Fixed(160.0)),
                            progress_bar(0.0..=100.0, gain).height(6).width(Length::Fixed(110.0)),
                            text(format!("{:.1}% Verdichtung letzter Fund", gain)).size(10).color(
                                if gain > 30.0 { green_ok } else if gain > 10.0 { amber_co } else { c(TEXT_M()) }
                            ),
                        ].spacing(8).align_y(Alignment::Center).into(),
                        row![
                            text("Delta-Konvergenz").size(11).color(c(TEXT_D())).width(Length::Fixed(160.0)),
                            progress_bar(0.0..=100.0, delta_conv_pct).height(6).width(Length::Fixed(110.0)),
                            text(format!("{:.1}% Redundanz-Abbau", delta_conv_pct)).size(10).color(c(TEXT_M())),
                        ].spacing(8).align_y(Alignment::Center).into(),
                        row![
                            text("Noether-Invarianz").size(11).color(c(TEXT_D())).width(Length::Fixed(160.0)),
                            progress_bar(0.0..=100.0, noether_pct).height(6).width(Length::Fixed(110.0)),
                            text(format!("{:.1}% strukturelle Stabilitaet", noether_pct)).size(10).color(c(TEXT_M())),
                        ].spacing(8).align_y(Alignment::Center).into(),
                        row![
                            text("Algo-Trust").size(11).color(c(TEXT_D())).width(Length::Fixed(160.0)),
                            progress_bar(0.0..=100.0, trust_pct).height(6).width(Length::Fixed(110.0)),
                            text(format!("{:.1}% Metrik-Koh\u{00e4}renz", trust_pct)).size(10).color(
                                if trust_pct > 65.0 { green_ok }
                                else if trust_pct > 40.0 { amber_co }
                                else { c(WARN()) }
                            ),
                        ].spacing(8).align_y(Alignment::Center).into(),
                        row![
                            text("Prozess-Overhead").size(11).color(c(TEXT_D())).width(Length::Fixed(160.0)),
                            text(format!(
                                "CPU {:.0}%  \u{00b7}  Tick {} ms  \u{00b7}  Muster kumuliert: {}",
                                self.backend_cpu_pct,
                                self.tick_interval_ms(),
                                self.flow_sphere_history.len(),
                            )).size(10).color(c(TEXT_M())),
                        ].spacing(8).align_y(Alignment::Center).into(),
                        {
                            // Bits-per-Joule row with mini sparkline
                            let bpj = self.live_render_bits_per_joule;
                            let bpj_label = if bpj >= 1_000_000.0 {
                                format!("{:.1} Mb/J", bpj / 1_000_000.0)
                            } else if bpj >= 1_000.0 {
                                format!("{:.0} kb/J", bpj / 1_000.0)
                            } else if bpj > 0.0 {
                                format!("{:.0} b/J", bpj)
                            } else {
                                "\u{2014} b/J".to_owned()
                            };
                            let bpj_color = if bpj >= 1_000_000.0 { green_ok }
                                else if bpj >= 10_000.0 { teal_co }
                                else if bpj > 0.0 { amber_co }
                                else { c(TEXT_D()) };
                            // sparkline: last 20 samples mapped to block chars
                            let history = &self.live_render_bpj_history;
                            let spark: String = if history.is_empty() {
                                "\u{2581}\u{2581}\u{2581}\u{2581}\u{2581}\u{2581}\u{2581}\u{2581}".to_owned()
                            } else {
                                let max = history.iter().cloned().fold(0.0_f32, f32::max).max(1.0);
                                let bars = ['\u{2581}','\u{2582}','\u{2583}','\u{2584}','\u{2585}','\u{2586}','\u{2587}','\u{2588}'];
                                history.iter().rev().take(20).rev()
                                    .map(|v| bars[((v / max) * 7.0).clamp(0.0, 7.0) as usize])
                                    .collect()
                            };
                            row![
                                text("Bits pro Joule").size(11).color(c(TEXT_D())).width(Length::Fixed(160.0)),
                                text(spark).size(10).color(teal_co).width(Length::Fixed(110.0)),
                                text(bpj_label).size(10).color(bpj_color),
                            ].spacing(8).align_y(Alignment::Center).into()
                        },
                    ];
                    container(
                        column![
                            text("\u{29bf} Kybernetik II \u{2014} Selbstoptimierung")
                                .size(13).color(teal_co),
                            text("Das System verdichtet Wissen passiv. Je mehr Muster bekannt, desto weniger Rechenaufwand f\u{00fc}r neue Analysen.")
                                .size(11).color(c(TEXT_D())),
                            column(opt_rows).spacing(6),
                        ]
                        .spacing(8)
                    )
                    .padding(12)
                    .style(panel_frame_style)
                },
                // ─── Schnell-Abfrage ─────────────────────────────────────────────────
                container(
                    column![
                        text("\u{25ba} Schnell-Abfrage").size(13).color(c(TEXT_H())),
                        text("Symbiont-Methode eingeben (z.B. aether/status) und Senden dr\u{00fc}cken.")
                            .size(11)
                            .color(c(TEXT_D())),
                        row![
                            iced::widget::text_input("aether/status", &self.symbiont_input)
                                .on_input(Message::SymbiontInputChanged)
                                .on_submit(Message::SymbiontRunPressed)
                                .padding([6, 10])
                                .size(12)
                                .width(Length::Fill),
                            button(
                                text(if self.symbiont_busy { "\u{21bb}" } else { "Senden" })
                                    .size(12)
                                    .color(c(TEXT_H()))
                            )
                            .on_press(Message::SymbiontRunPressed)
                            .padding([6, 12])
                            .style(if self.symbiont_busy { secondary_button_style } else { primary_button_style }),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                        container(
                            text(&self.symbiont_result)
                                .size(11)
                                .color(if self.symbiont_result.starts_with("Fehler") {
                                    Color::from_rgb8(0xD9, 0x50, 0x50)
                                } else {
                                    c(TEXT_M())
                                })
                        )
                        .padding([8, 10])
                        .style(panel_frame_style)
                        .width(Length::Fill),
                    ]
                    .spacing(8)
                )
                .padding(10)
                .style(panel_frame_style),
                container(
                    column![
                        row![
                            text(format!("● Live Events{}", if self.symbiont_events_polling { " ↻" } else { "" }))
                                .size(13)
                                .color(if self.hybrid_symbiont_running { Color::from_rgb8(0x4C, 0xD9, 0x6E) } else { c(TEXT_D()) }),
                            text(format!("({} Eintraege)", self.symbiont_events.len()))
                                .size(11)
                                .color(c(TEXT_D())),
                            iced::widget::Space::new(Length::Fill, Length::Shrink),
                            button(text("Leeren").size(11).color(c(TEXT_M())))
                                .on_press(Message::SymbiontEventsClearPressed)
                                .padding([4, 10])
                                .style(secondary_button_style),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                        container(scrollable(events_column).height(Length::Fixed(200.0)))
                            .padding(8)
                            .style(panel_frame_style),
                    ]
                    .spacing(6)
                )
                .padding(10)
                .style(panel_frame_style),
                info_card(
                    "Hinweis",
                    "aether-symbiont (VSCode) und symbiont_core.py sind separate Ebenen. Dieser Tab zeigt Bridge-Status, P2P-Verbindung und Selbstoptimierungs-Kennzahlen.",
                ),
            ]
            .spacing(12)
        )
        .padding(12)
        .width(Length::Fill);

        scrollable(sym_inner)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }

    fn view_swarm_ops(&self) -> Element<'_, Message> {
        let accent   = Color::from_rgb8(0x3F, 0xBA, 0xC2);
        let green    = Color::from_rgb8(0x5A, 0xAE, 0x84);
        let gold     = Color::from_rgb8(0xC7, 0xA0, 0x4A);
        let mid      = c(TEXT_M());
        let dim      = c(TEXT_D());
        let panel_s  = Color::from_rgba(0.08, 0.12, 0.16, 0.90);
        let border_c = c(BORDER());

        let node_status = if self.swarm_startup.node_initialized {
            format!(
                "Node bereit \u{b7} nodes={} \u{b7} packs={}",
                self.swarm_startup.node_count,
                self.swarm_startup.new_pack_count
            )
        } else {
            "Node noch nicht initialisiert".to_owned()
        };

        let locally_analyzed = self.flow_sphere_history.len();
        let overlap_pending  = self.swarm_overlap_requests.len();
        let anchor_count     = self.backend_anchor_count;

        let mut content = column![].spacing(14);

        // ── Header ───────────────────────────────────────────────────────────
        content = content.push(
            column![
                text("\u{25c6} SWARM OPS \u{b7} INVARIANTENBASIERTE KNOTENKOORDINATION").size(15).color(accent),
                text(node_status).size(11).color(dim),
            ].spacing(4)
        );

        // ── Was ist Swarm Ops? ───────────────────────────────────────────────
        content = content.push(
            container(
                column![
                    text("Was ist Swarm Ops und wozu dient er?").size(13).color(accent),
                    text("Swarm Ops ist die Schaltzentrale f\u{fc}r das Netz der Aether-Knoten. Hier siehst du welche Knoten aktiv sind und welche strukturellen Dom\u{e4}nen sie abdecken \u{2014} ohne dass Rohdaten jemals den Knoten verlassen.").size(12).color(mid),
                    text("Priorit\u{e4}t \u{2014} lokal zuerst: Jeder Knoten erreicht mit der Zeit das Maximum das offline m\u{f6}glich ist. Der Vault w\u{e4}chst, der lernende Beobachter entfernt Overhead und Bloat, die Invarianten werden sch\u{e4}rfer. Jede neue Analyse macht den Knoten effizienter. Das passiert lokal, immer, auch komplett ohne Netz.").size(11).color(dim),
                    text("Das absolute Maximum ist nur im Netz erreichbar: Offline ist die Obergrenze das was ein einzelner Knoten mit seinen eigenen Daten und seiner eigenen Hardware leisten kann. Mit dem Schwarm im R\u{fc}cken verschiebt sich diese Grenze nach oben \u{2014} weil strukturell komplement\u{e4}re Knotenprofile L\u{fc}cken schlie\u{df}en die ein einzelner Knoten nie f\u{fc}llen k\u{f6}nnte. Aber das ist ein Bonus, kein Fundament.").size(11).color(dim),
                    text("Swarm ist optionaler R\u{fc}ckenwind: Wenn im Hintergrund strukturell passende Kapazit\u{e4}t verf\u{fc}gbar ist passiert etwas \u{2014} wenn nicht, l\u{e4}uft alles trotzdem auf dem lokalen Maximum weiter. Kein Unterschied, keine Abh\u{e4}ngigkeit.").size(11).color(dim),
                ].spacing(6),
            )
            .padding([12, 14])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(panel_s)),
                border: Border { color: accent, width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
        );

        // ── Emergente Netzwerk-Freischaltung ─────────────────────────────────
        {
            let tier_label = if self.hw_network_tier.is_empty() {
                "ermittelt…".to_owned()
            } else {
                self.hw_network_tier.clone()
            };
            let os_label = if self.hw_os_platform.is_empty() {
                "unbekannt".to_owned()
            } else {
                self.hw_os_platform.clone()
            };
            let [lb, lp, ygg, dht] = self.hw_p2p_unlocked;
            let feat_color = |on: bool| if on { green } else { dim };
            let feat_char = |on: bool| if on { "\u{2713}" } else { "\u{2014}" };
            content = content.push(
                container(
                    column![
                        text("Emergente Netzwerk-Freischaltung").size(13).color(gold),
                        text(format!(
                            "Plattform: {}  \u{b7}  Tier: {}",
                            os_label, tier_label
                        )).size(11).color(dim),
                        text("Welche P2P-Features diese Hardware unterstützt (automatisch ermittelt):").size(11).color(mid),
                        row![
                            container(column![
                                text(format!("{} LAN-Beacon", feat_char(lb))).size(12).color(feat_color(lb)),
                                text("Passiver Knoten\nsichtbar im LAN").size(10).color(dim),
                            ].spacing(2)).padding([6, 10]),
                            container(column![
                                text(format!("{} LAN-P2P", feat_char(lp))).size(12).color(feat_color(lp)),
                                text("Gossip + Leader-\nElection lokal").size(10).color(dim),
                            ].spacing(2)).padding([6, 10]),
                            container(column![
                                text(format!("{} Yggdrasil", feat_char(ygg))).size(12).color(feat_color(ygg)),
                                text("IPv6-Overlay-Mesh\ninternetf\u{e4}hig").size(10).color(dim),
                            ].spacing(2)).padding([6, 10]),
                            container(column![
                                text(format!("{} DHT", feat_char(dht))).size(12).color(feat_color(dht)),
                                text("Kademlia-Relay\n+ Peer-Tabelle").size(10).color(dim),
                            ].spacing(2)).padding([6, 10]),
                        ].spacing(4),
                        text(if !lb {
                            "\u{26a0} LocalOnly: Dieses Ger\u{e4}t ist zu schwach f\u{fc}r Netzwerkbetrieb \u{2014} nur lokale Analyse."
                        } else if !lp {
                            "\u{25cf} LAN-Beacon: Ank\u{fc}ndigung im LAN aktiv. Voller Gossip erfordert mehr RAM/Kerne."
                        } else if !ygg {
                            "\u{25cf} LAN-P2P bereit. Yggdrasil erfordert moderneres OS oder mehr RAM."
                        } else if !dht {
                            "\u{25cf} Yggdrasil-P2P bereit. DHT-Relay erfordert \u{2265}4 GB RAM + 4 Kerne."
                        } else {
                            "\u{25c6} Voller DHT aktiv \u{2014} dieser Knoten kann als Relay teilnehmen."
                        }).size(11).color(if !lb { c(WARN()) } else { accent }),
                    ].spacing(6),
                )
                .padding([12, 14])
                .style(move |_: &Theme| container::Style {
                    background: Some(Background::Color(panel_s)),
                    border: Border { color: gold, width: 1.0, radius: 8.0.into() },
                    ..Default::default()
                })
            );
        }

        // ── KPIs ─────────────────────────────────────────────────────────────
        content = content.push(
            row![
                cyber_kpi_card(
                    "Swarm Nodes",
                    format!("{}", self.swarm_startup.node_count),
                    "bootstrap",
                    accent,
                    "swarm_nodes"
                ),
                cyber_kpi_card(
                    "Lokale Analysen",
                    format!("{}", locally_analyzed),
                    "observer-history",
                    green,
                    "swarm_local"
                ),
                cyber_kpi_card(
                    "Offene Anfragen",
                    format!("{}", overlap_pending),
                    "overlap-requests",
                    gold,
                    "swarm_overlap"
                ),
                cyber_kpi_card(
                    "Anchors gesamt",
                    format!("{}", anchor_count),
                    "invariant-store",
                    accent,
                    "swarm_anchors"
                ),
            ].spacing(10)
        );

        // ── Invariantenbasierte Aufgabenverteilung ───────────────────────────
        content = content.push(
            container(
                column![
                    text("Swarm-Beteiligung \u{2014} emergent, optional, im Hintergrund").size(13).color(accent),
                    text("Kein Knoten wird zum Worker ernannt. Wenn im Hintergrund strukturell kompatible Kapazit\u{e4}t verf\u{fc}gbar ist passiert etwas \u{2014} wenn nicht, passiert nichts. Kein Unterschied f\u{fc}r den eigenen Knoten. Rechenkapazit\u{e4}t, Latenz und Last entscheiden im Moment und das \u{e4}ndert sich st\u{e4}ndig.").size(11).color(dim),
                    row![
                        column![
                            text("Emergent, nicht geplant").size(11).color(green),
                            text("Rollen entstehen situativ aus dem aktuellen Zustand des Netzes \u{2014} nicht aus einer vordefinierten Hierarchie. Ein Knoten der gerade Kapazit\u{e4}t hat beteiligt sich, ein Knoten der ausgelastet ist h\u{e4}lt sich zur\u{fc}ck. Das ergibt sich von selbst.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                        column![
                            text("Mehrere Knoten, gleiche Aufgabe").size(11).color(green),
                            text("Die selbe Berechnung kann von mehreren Knoten gleichzeitig \u{fc}bernommen werden. Das ist kein Fehler sondern ein Feature: Redundanz verst\u{e4}rkt das Ergebnis, gleicht Ausf\u{e4}lle aus und macht das Netz robuster ohne dass jemand etwas konfigurieren muss.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                        column![
                            text("Kein Datentransfer, nur Fingerabdr\u{fc}cke").size(11).color(green),
                            text("Ausgetauscht werden ausschlie\u{df}lich mathematische Invarianten \u{2014} strukturelle Fingerabdr\u{fc}cke ohne Inhalt. Wer etwas beitragen kann signalisiert das \u{fc}ber den Anchor-Hash. Kein Vertrauen als Person n\u{f6}tig: die Struktur spricht f\u{fc}r sich.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                    ].spacing(10),
                ].spacing(7),
            )
            .padding([12, 14])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(panel_s)),
                border: Border { color: green, width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
        );

        // ── Lernender Beobachter als Koordinationsmotor ──────────────────────
        content = content.push(
            container(
                column![
                    text("Lernender Beobachter \u{2014} der Knoten wird mit der Zeit besser").size(13).color(accent),
                    text("Der Beobachter lernt still was dieser Knoten schon gut kann und wo noch Overhead steckt. Mit jeder Analyse werden Invarianten sch\u{e4}rfer, Bloat wird erkannt und entfernt, der Vault komprimiert sein Wissen. Der Knoten wird effizienter \u{2014} automatisch, im Hintergrund, ohne Konfiguration. Das ist die Kerngarantie unabh\u{e4}ngig davon ob Swarm-Verbindungen bestehen oder nicht.").size(11).color(dim),
                    row![
                        column![
                            text("Stetig wachsende lokale Effizienz").size(11).color(gold),
                            text("Noether-K, Delta-Konvergenz und Fourier-Periodizit\u{e4}t bauen intern ein immer sch\u{e4}rferes Bild auf. Je mehr der Knoten analysiert hat desto weniger Rechenaufwand braucht er f\u{fc}r bekannte Muster \u{2014} der Overhead sinkt mit der Zeit.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                        column![
                            text("Vault entfernt Bloat automatisch").size(11).color(gold),
                            text("Redundante Pfade, veraltete Invarianten und ineffiziente Repr\u{e4}sentationen werden durch den lernenden Beobachter laufend bereinigt. Der Vault wird nicht gro\u{df}er sondern sch\u{e4}rfer. Auch alte oder schwache Hardware profitiert davon direkt.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                        column![
                            text("Swarm als optionaler Multiplikator").size(11).color(gold),
                            text("Wenn im Hintergrund andere Knoten mit passenden Invarianten verf\u{fc}gbar sind k\u{f6}nnen sie erweiternd mitmachen \u{2014} redundant, ohne Koordination, ohne feste Rollen. Kein Knoten muss einem anderen vertrauen: die Struktur ist die Signatur.").size(10).color(dim),
                        ].spacing(3).width(Length::FillPortion(1)),
                    ].spacing(10),
                    text("Vault-Individualit\u{e4}t \u{2014} nat\u{fc}rliche Komplementarit\u{e4}t:").size(12).color(gold),
                    text("Jeder Vault ist einzigartig weil er aus unterschiedlichen Analysen gewachsen ist. Wenn Knoten zusammenwirken erg\u{e4}nzen sie sich von Natur aus \u{2014} ohne Rollenvergabe. Das ergibt sich aus dem was jeder gesehen hat.").size(10).color(dim),
                    text("Globaler Vault (FlowSphere) \u{2014} kollektiver Bonus:").size(11).color(gold),
                    text("Der globale Vault geh\u{f6}rt allen teilnehmenden Knoten gleichzeitig. Jeder tr\u{e4}gt sein Profil bei und profitiert vom aggregierten Bild \u{2014} ein Muster-Ged\u{e4}chtnis das kein einzelner Knoten je erreichen k\u{f6}nnte. Wenn es passiert ist es ein Gewinn. Wenn nicht l\u{e4}uft der eigene Knoten trotzdem auf Maximum.").size(10).color(dim),
                    text("Kurzum: Jeder Nutzer hat mit der Zeit einen immer effizienteren Knoten \u{2014} egal ob allein oder im Netz. Der Schwarm ist nur das was obendrauf kommt.").size(11).color(mid),
                ].spacing(7),
            )
            .padding([12, 14])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(panel_s)),
                border: Border { color: gold, width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
        );

        // ── Consent + Status ─────────────────────────────────────────────────
        content = content.push(
            container(
                column![
                    text("Swarm-Teilnahme").size(12).color(accent),
                    row![
                        button(text(if self.swarm_consented { "Swarm-Teilnahme [aktiv]" } else { "Swarm aktivieren" }).size(12).color(c(TEXT_H())))
                            .on_press(Message::SwarmConsentToggled(true))
                            .padding([8, 12])
                            .style(if self.swarm_consented { primary_button_style } else { secondary_button_style }),
                        button(text(if !self.swarm_consented { "Swarm-Teilnahme [aus]" } else { "Swarm deaktivieren" }).size(12).color(c(TEXT_H())))
                            .on_press(Message::SwarmConsentToggled(false))
                            .padding([8, 12])
                            .style(if !self.swarm_consented { primary_button_style } else { secondary_button_style }),
                    ].spacing(10),
                    text(if self.swarm_consented {
                        "Aktiv \u{2014} ausschlie\u{df}lich SHA-256-Fingerabdr\u{fc}cke und aggregierte Strukturmetriken werden geteilt. Keine Rohdaten, keine Inhalte, keine Identit\u{e4}ten."
                    } else {
                        "Deaktiviert \u{2014} dieser Knoten sendet nichts an den Schwarm. Alle Analysen laufen rein lokal."
                    }).size(11).color(dim),
                ].spacing(8),
            )
            .padding([12, 14])
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(panel_s)),
                border: Border { color: border_c, width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
        );

        // ── Schnellzugriff ────────────────────────────────────────────────────
        content = content.push(
            row![
                button(text("Anchors").size(12).color(c(TEXT_H())))
                    .on_press(Message::TabSelected(Tab::Anchors))
                    .padding([8, 12])
                    .style(primary_button_style),
                button(text("FlowSphere").size(12).color(c(TEXT_H())))
                    .on_press(Message::TabSelected(Tab::FlowSphere))
                    .padding([8, 12])
                    .style(primary_button_style),
                button(text("Chat").size(12).color(c(TEXT_H())))
                    .on_press(Message::TabSelected(Tab::Chat))
                    .padding([8, 12])
                    .style(primary_button_style),
                button(text("Logs").size(12).color(c(TEXT_H())))
                    .on_press(Message::TabSelected(Tab::Logs))
                    .padding([8, 12])
                    .style(primary_button_style),
            ].spacing(10)
        );

        container(scrollable(content.padding([0, 4])))
            .padding(12)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_privacy_ops(&self) -> Element<'_, Message> {
        container(
            column![
                text("Privacy & Process Monitor").size(28).color(c(TEXT_H())),
                text("Privacy Observer, Process Engine und Sicherheitschecks fuer den Alltag einfach bedienbar.")
                    .size(13)
                    .color(c(TEXT_M())),
                row![
                    cyber_kpi_card(
                        "CPU",
                        if self.backend_state_loaded {
                            format!("{:.0}%", self.backend_cpu_pct)
                        } else {
                            "--".to_owned()
                        },
                        "live",
                        Color::from_rgb8(0x3F, 0xBA, 0xC2),
                        "privacy_cpu"
                    ),
                    cyber_kpi_card(
                        "Memory",
                        if self.backend_state_loaded {
                            format!("{:.2} GB", self.backend_mem_used_gb)
                        } else {
                            "--".to_owned()
                        },
                        "live",
                        Color::from_rgb8(0x5A, 0xAE, 0x84),
                        "privacy_mem"
                    ),
                    cyber_kpi_card(
                        "Trust",
                        self.security_snapshot.trust_state.clone(),
                        "security monitor",
                        Color::from_rgb8(0xC7, 0xA0, 0x4A),
                        "privacy_trust"
                    ),
                ]
                .spacing(10),
                row![
                    button(text("Security Recheck").size(12).color(c(TEXT_H())))
                        .on_press(Message::SecurityRecheck)
                        .padding([8, 12])
                        .style(primary_button_style),
                    button(text("Open Logs").size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::Logs))
                        .padding([8, 12])
                        .style(primary_button_style),
                ]
                .spacing(10),
                info_card(
                    "Hinweis",
                    "Die tieferen Privacy-Backends (WindowsPrivacyObserver/ProcessEngine) laufen in Python. Dieser Tab bietet die wichtigsten UI-Einstiege ohne Dateichaos.",
                ),
            ]
            .spacing(12),
        )
        .padding(12)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn view_control_center(&self) -> Element<'_, Message> {
            let module_card = |
                title: &'static str,
                desc: &'static str,
                status: String,
                route_label: &'static str,
                route_tab: Tab,
            | {
                container(
                    column![
                        row![
                            text(title).size(18).color(c(TEXT_H())),
                            iced::widget::Space::new(Length::Fill, Length::Shrink),
                            container(text(status).size(11).color(c(ACCENT())))
                                .padding([4, 8])
                                .style(|_: &Theme| container::Style {
                                    background: Some(Background::Color(Color::from_rgba(0.12, 0.24, 0.28, 0.85))),
                                    border: Border { color: c(BORDER()), width: 1.0, radius: 8.0.into() },
                                    ..Default::default()
                                }),
                        ]
                        .align_y(Alignment::Center),
                        text(desc).size(13).color(c(TEXT_M())),
                        button(text(route_label).size(12).color(c(TEXT_H())))
                            .on_press(Message::TabSelected(route_tab))
                            .padding([8, 12])
                            .style(primary_button_style),
                    ]
                    .spacing(10),
                )
                .padding(14)
                .style(standard_card_style)
                .width(Length::Fill)
            };

            let backend_status = if self.backend_state_loaded {
                format!(
                    "Vault {} | Entropy {:.2} | CPU {:.0}%",
                    self.backend_vault_main,
                    self.backend_entropy_mean,
                    self.backend_cpu_pct
                )
            } else {
                self.ui_text("Backend-State noch nicht geladen", "Backend state not loaded yet").to_owned()
            };

            let trust_lower = self.security_snapshot.trust_state.to_ascii_lowercase();
            let backend_color = if self.backend_state_loaded {
                Color::from_rgb8(0x3A, 0xA6, 0x64)
            } else {
                Color::from_rgb8(0xC7, 0xA0, 0x4A)
            };
            let backend_label = if self.backend_state_loaded {
                self.ui_text("Gruen", "Green")
            } else {
                self.ui_text("Gelb", "Yellow")
            };
            let swarm_color = if self.swarm_startup.node_initialized {
                Color::from_rgb8(0x3A, 0xA6, 0x64)
            } else {
                Color::from_rgb8(0xC0, 0x58, 0x58)
            };
            let swarm_label = if self.swarm_startup.node_initialized {
                self.ui_text("Gruen", "Green")
            } else {
                self.ui_text("Rot", "Red")
            };
            let (trust_color, trust_label) = if trust_lower.contains("critical")
                || trust_lower.contains("danger")
                || trust_lower.contains("blocked")
            {
                (Color::from_rgb8(0xC0, 0x58, 0x58), self.ui_text("Rot", "Red"))
            } else if trust_lower.contains("warn")
                || trust_lower.contains("monitor")
                || trust_lower.contains("limited")
            {
                (Color::from_rgb8(0xC7, 0xA0, 0x4A), self.ui_text("Gelb", "Yellow"))
            } else {
                (Color::from_rgb8(0x3A, 0xA6, 0x64), self.ui_text("Gruen", "Green"))
            };

            let status_chip = |title: &str, value: &str, color: Color| {
                container(
                    Row::new()
                        .push(text("●").size(14).color(color))
                        .push(text(format!("{}: {}", title, value)).size(12).color(c(TEXT_M())) )
                        .spacing(8)
                        .align_y(Alignment::Center),
                )
                .padding([6, 10])
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(c(BG_CARD2()))),
                    border: Border { color: c(BORDER()), width: 1.0, radius: 8.0.into() },
                    ..Default::default()
                })
            };

            let traffic_row = Row::new()
                .push(status_chip(self.ui_text("Backend", "Backend"), backend_label, backend_color))
                .push(status_chip(self.ui_text("Startnode", "Start node"), swarm_label, swarm_color))
                .push(status_chip(self.ui_text("Trust", "Trust"), trust_label, trust_color))
                .spacing(10);

            let top_summary = Row::new()
                .push(cyber_kpi_card(
                    "Backend Vault",
                    format!("{}", self.backend_vault_main),
                    "IPC file bridge",
                    Color::from_rgb8(0x3F, 0xBA, 0xC2),
                    "backend_vault"
                ))
                .push(cyber_kpi_card(
                    "Swarm Nodes",
                    format!("{}", self.swarm_startup.node_count),
                    "Bootstrap discovery",
                    Color::from_rgb8(0x5A, 0xAE, 0x84),
                    "swarm_nodes"
                ))
                .push(cyber_kpi_card(
                    "Users / Symbiont",
                    format!("{}", self.auth_store.user_count()),
                    "Rust shell knows local user scope",
                    Color::from_rgb8(0xC7, 0xA0, 0x4A),
                    "symbiont_scope"
                ))
                .spacing(10);

            let core_row = Row::new()
                .push(module_card(
                    "Core Workspace",
                    "Overview, Chat, Browser, Files, Reconstruction und Runtime sind die Hauptfunktionen fuer den Alltag.",
                    "aktiv".to_owned(),
                    "Open Files",
                    Tab::Data,
                ))
                .push(module_card(
                    "Threat & Analysis",
                    "Threat Graph, ADE, Logs und Anchors decken die Hauptanalyse im Rust-Frontend bereits ab.",
                    "aktiv".to_owned(),
                    "Open Threat Analysis",
                    Tab::ADE,
                ))
                .spacing(10);

            let advanced_row = Row::new()
                .push(module_card(
                    "Symbiont",
                    "Symbiont-Core und aether-symbiont sind hier als eigener Bedienbereich gebuendelt und verlinken direkt zu Analysepfaden.",
                    "aktiv".to_owned(),
                    "Open Symbiont",
                    Tab::Symbiont,
                ))
                .push(module_card(
                    "Privacy & Process Monitor",
                    "Privacy Observer, Process Engine und Sicherheitschecks sind als eigener Tab verfuegbar und direkt bedienbar.",
                    "aktiv".to_owned(),
                    "Open Privacy",
                    Tab::Privacy,
                ))
                .spacing(10);

            let infra_row = Row::new()
                .push(module_card(
                    "Swarm / P2P / Anchors",
                    "Swarm-Sync, P2P-Anchor-Pool und Public-TTD-Transport sind im Bereich Swarm Ops zusammengefuehrt.",
                    format!(
                        "{} node(s) | startnode {}",
                        self.swarm_startup.node_count,
                        if self.swarm_startup.node_initialized { "ja" } else { "nein" }
                    ),
                    "Open Swarm Ops",
                    Tab::SwarmOps,
                ))
                .push(module_card(
                    "Policies / Vault / Trust",
                    "Rule Engine, Vault Chain und Governance existieren, aber nicht als eigener Bedienbereich. Relevante Kontrolle liegt derzeit in Runtime und Files.",
                    "teilweise exponiert".to_owned(),
                    "Open Runtime",
                    Tab::Settings,
                ))
                .spacing(10);

            let quick_start_row = Row::new()
                .push(
                    button(text(self.ui_text("1) Uebersicht", "1) Overview")).size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::Home))
                        .padding([8, 12])
                        .style(primary_button_style)
                )
                .push(
                    button(text(self.ui_text("2) Security-Pruefung", "2) Security Recheck")).size(12).color(c(TEXT_H())))
                        .on_press(Message::SecurityRecheck)
                        .padding([8, 12])
                        .style(primary_button_style)
                )
                .push(
                    button(text(self.ui_text("3) Kontrollzentrum", "3) Control Center")).size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::Control))
                        .padding([8, 12])
                        .style(primary_button_style)
                )
                .push(
                    button(text("4) Swarm Ops").size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::SwarmOps))
                        .padding([8, 12])
                        .style(primary_button_style)
                )
                .push(
                    button(text("5) Runtime").size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::Settings))
                        .padding([8, 12])
                        .style(primary_button_style)
                )
                .spacing(10);

            container(
                scrollable(
                    column![
                        text(self.ui_text("Kontrollzentrum", "Control Center")).size(28).color(c(TEXT_H())),
                        text(self.ui_text(
                            "Zentraler Einstieg fuer alle sinnvollen Bedienflaechen und fuer fortgeschrittene Subsysteme, die bisher nur verteilt in Modulen existieren.",
                            "Central entry point for practical controls and advanced subsystems that were previously spread across modules.",
                        ))
                            .size(13)
                            .color(c(TEXT_M())),
                        traffic_row,
                        info_card(
                            self.ui_text("Erste Schritte", "First steps"),
                            self.ui_text(
                                "Folge den 5 Buttons von links nach rechts fuer einen sicheren Standard-Start ohne Modulwissen.",
                                "Follow the 5 buttons from left to right for a safe default startup without module knowledge.",
                            ),
                        ),
                        quick_start_row,
                        container(text(backend_status).size(12).color(c(TEXT_D())))
                            .padding(10)
                            .style(panel_frame_style),
                        top_summary,
                        core_row,
                        advanced_row,
                        infra_row,
                    ]
                    .spacing(12)
                    .padding([4, 4]),
                )
            )
            .padding(12)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_launcher(&self) -> Element<'_, Message> {
        let header = row![
            text("Unified Launcher Dashboard").size(24).color(c(TEXT_H())),
            text(" | Manage all services & build tasks").size(14).color(c(TEXT_M())),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        // Mode selector
        let mode_buttons = row![
            self.mode_button(LauncherMode::Services, "🔧 Services"),
            self.mode_button(LauncherMode::BuildTasks, "🔨 Build"),
            self.mode_button(LauncherMode::Logs, "📝 Logs"),
            self.mode_button(LauncherMode::Configuration, "⚙️ Config"),
        ]
        .spacing(8)
        .padding([8, 0]);

        // Content based on selected mode
        let content: Element<'_, Message> = match self.launcher_state.mode {
            LauncherMode::Services => self.view_launcher_services(),
            LauncherMode::BuildTasks => self.view_launcher_build_tasks(),
            LauncherMode::Logs => self.view_launcher_logs(),
            LauncherMode::Configuration => self.view_launcher_configuration(),
        };

        container(
            column![
                header,
                mode_buttons,
                container(iced::widget::Space::new(Length::Fill, Length::Fixed(1.0)))
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(c(BORDER()))),
                        ..Default::default()
                    })
                    .width(Length::Fill)
                    .height(Length::Fixed(1.0)),
                container(content)
                    .width(Length::Fill)
                    .height(Length::Fill),
            ]
            .spacing(12)
            .padding(16)
            .width(Length::Fill)
            .height(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn mode_button<'a>(&self, mode: LauncherMode, label: &'a str) -> Element<'a, Message> {
        let is_active = self.launcher_state.mode == mode;
        button(text(label).size(13).color(if is_active { c(ACCENT()) } else { c(TEXT_M()) }))
            .on_press(Message::LauncherModeSelected(mode))
            .padding([8, 16])
            .style(move |_: &Theme, _| button::Style {
                background: Some(Background::Color(if is_active {
                    Color::from_rgba(0.55, 0.25, 0.95, 0.4)
                } else {
                    Color::TRANSPARENT
                })),
                border: Border {
                    color: if is_active { c(ACCENT()) } else { c(BORDER()) },
                    width: 1.0,
                    radius: 6.0.into(),
                },
                text_color: if is_active { c(ACCENT()) } else { c(TEXT_M()) },
                ..Default::default()
            })
            .into()
    }

    fn view_launcher_services(&self) -> Element<'_, Message> {
        let services: Vec<_> = self.launcher_state.all_services().iter().map(|s| *s).collect();
        
        let service_cards: Vec<_> = services
            .iter()
            .map(|service| {
                let status_color = service.status.color_rgb();
                let status_label = service.status.label();
                let status_badge = text(format!("● {}", status_label))
                    .size(12)
                    .color(Color::from_rgb(status_color.0, status_color.1, status_color.2));
                let (start_btn, stop_btn): (Option<Element<'_, Message>>, Option<Element<'_, Message>>) = match service.status {
                    ServiceStatus::Running => (
                        None,
                        Some(
                            button(text("Stop").size(12).color(c(TEXT_H())))
                                .on_press(Message::LauncherServiceStopPressed(service.id.clone()))
                                .padding([6, 12])
                                .style(secondary_button_style)
                                .into()
                        ),
                    ),
                    ServiceStatus::Idle => (
                        Some(
                            button(text("Start").size(12).color(c(TEXT_H())))
                                .on_press(Message::LauncherServiceStartPressed(service.id.clone()))
                                .padding([6, 12])
                                .style(primary_button_style)
                                .into()
                        ),
                        None,
                    ),
                    _ => (None, None),
                };

                let mut button_row = row![];
                if let Some(btn) = start_btn {
                    button_row = button_row.push(btn);
                }
                if let Some(btn) = stop_btn {
                    button_row = button_row.push(btn);
                }
                button_row = button_row.spacing(8);

                container(
                    column![
                        row![
                            text(service.name.clone()).size(14).color(c(TEXT_H())),
                            status_badge
                        ]
                        .width(Length::Fill)
                        .spacing(8)
                        .align_y(Alignment::Center)
                        .width(Length::Fill),
                        text(service.description.clone()).size(11).color(c(TEXT_M())),
                        text(format!(
                            "PID: {} | Uptime: {}s{}",
                            service
                                .process_id
                                .map(|pid| pid.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                            service.uptime_secs,
                            if service.log_fresh { " | new log lines" } else { "" }
                        ))
                        .size(10)
                        .color(if service.log_fresh { Color::from_rgb8(0x6C, 0xD4, 0x8F) } else { c(TEXT_D()) }),
                        if let Some(port) = service.port {
                            text(format!("Port: {}", port)).size(10).color(c(TEXT_D()))
                        } else {
                            text("").size(10)
                        },
                        button_row.width(Length::Fill),
                    ]
                    .spacing(6)
                    .width(Length::Fill),
                )
                .padding(12)
                .style(panel_frame_style)
                .width(Length::Fill)
                .into()
            })
            .collect();

        scrollable(column(service_cards).spacing(8))
            .height(Length::Fill)
            .into()
    }

    fn view_launcher_build_tasks(&self) -> Element<'_, Message> {
        let tasks = self.launcher_state.build_tasks.clone();
        
        let task_cards: Vec<_> = tasks
            .iter()
            .map(|task| {
                let status_text = if task.running {
                    "● Running...".to_owned()
                } else if let Some(code) = task.last_exit_code {
                    format!("● Exit: {}", code)
                } else {
                    "● Ready".to_owned()
                };
                let status_color = if task.running {
                    Color::from_rgb8(0xF0, 0xA0, 0x00)
                } else if task.last_exit_code == Some(0) {
                    Color::from_rgb8(0x00, 0xD0, 0x00)
                } else if task.last_exit_code.is_none() {
                    c(TEXT_D())
                } else {
                    Color::from_rgb8(0xD0, 0x00, 0x00)
                };

                container(
                    column![
                        row![
                            text(task.name.clone()).size(14).color(c(TEXT_H())),
                            text(status_text).size(12).color(status_color)
                        ]
                        .width(Length::Fill)
                        .spacing(8),
                        text(task.description.clone()).size(11).color(c(TEXT_M())),
                        row![
                            button(text(if task.running { "Running..." } else { "Execute" }).size(12).color(c(TEXT_H())))
                                .on_press_maybe((!task.running).then_some(Message::LauncherBuildTaskPressed(task.id.clone())))
                                .padding([6, 12])
                                .style(primary_button_style)
                        ]
                        .width(Length::Fill)
                    ]
                    .spacing(6)
                    .width(Length::Fill),
                )
                .padding(12)
                .style(panel_frame_style)
                .width(Length::Fill)
                .into()
            })
            .collect();

        scrollable(column(task_cards).spacing(8))
            .height(Length::Fill)
            .into()
    }

    fn view_launcher_logs(&self) -> Element<'_, Message> {
        let logs = self.launcher_state.recent_logs(50);

        let log_lines: Vec<_> = logs
            .iter()
            .rev()
            .map(|(_, line)| {
                text(line.clone())
                    .size(11)
                    .color(c(TEXT_M()))
                    .into()
            })
            .collect();

        let service_sections: Vec<Element<'_, Message>> = self
            .launcher_state
            .all_services()
            .into_iter()
            .map(|service| {
                let lines: Vec<Element<'_, Message>> = if service.log_lines.is_empty() {
                    vec![text("No service output yet.").size(11).color(c(TEXT_D())).into()]
                } else {
                    service
                        .log_lines
                        .iter()
                        .map(|line| text(line.clone()).size(10).color(c(TEXT_M())).into())
                        .collect()
                };

                container(
                    column![
                        text(format!("{} Log Tail", service.name)).size(13).color(c(TEXT_H())),
                        container(scrollable(column(lines).spacing(2)).height(Length::Fixed(110.0)))
                            .padding(8)
                            .style(panel_frame_style),
                    ]
                    .spacing(6)
                    .width(Length::Fill),
                )
                .style(panel_frame_style)
                .padding(10)
                .width(Length::Fill)
                .into()
            })
            .collect();

        container(
            column![
                row![
                    text("Recent Logs").size(14).color(c(TEXT_H())),
                    iced::widget::Space::new(Length::Fill, Length::Shrink),
                    button(text("Clear").size(12).color(c(TEXT_H())))
                        .on_press(Message::LauncherLogsClearPressed)
                        .padding([4, 12])
                        .style(secondary_button_style),
                ]
                .align_y(Alignment::Center)
                .width(Length::Fill),
                container(scrollable(column(log_lines).spacing(2)).height(Length::Fixed(220.0)))
                    .padding(8)
                    .style(panel_frame_style),
                scrollable(column(service_sections).spacing(8))
                    .height(Length::Fill),
            ]
            .spacing(8)
            .width(Length::Fill)
            .height(Length::Fill),
        )
        .padding(12)
        .style(panel_frame_style)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn view_launcher_configuration(&self) -> Element<'_, Message> {
        container(
            column![
                text("Launcher Configuration").size(16).color(c(TEXT_H())),
                text("Platform Information").size(13).color(c(TEXT_M())),
                text(self.launcher_state.platform_info.clone()).size(11).color(c(TEXT_D())),
                container(iced::widget::Space::new(Length::Fixed(1.0), Length::Fixed(12.0))),
                text("Service Endpoints").size(13).color(c(TEXT_M())),
                text("Symbiont Server: 127.0.0.1:38571").size(11).color(c(TEXT_D())),
                text("Iced Shell: Currently Running").size(11).color(c(TEXT_D())),
                container(iced::widget::Space::new(Length::Fixed(1.0), Length::Fixed(12.0))),
                text("Aethernet & Swarm").size(13).color(c(TEXT_M())),
                text(format!(
                    "Aethernet: {} | Receiver Port: {}",
                    if self.hybrid_aethernet_running { "online" } else { "offline" },
                    self.hybrid_aethernet_receiver_port,
                ))
                .size(11)
                .color(c(TEXT_D())),
                text(format!(
                    "Nodes: {} (reachable: {}) | Packs: {} | Consensus: {} | Candidates: {}",
                    self.backend_swarm_node_count,
                    self.backend_swarm_reachable_node_count,
                    self.backend_swarm_pack_count,
                    self.backend_swarm_consensus_count,
                    self.backend_swarm_candidate_count,
                ))
                .size(11)
                .color(c(TEXT_D())),
                text(format!(
                    "Genesis Key: {} | Quorum: {} | Saving: {:.2}%",
                    if self.backend_swarm_genesis_key_ok { "ok" } else { "missing" },
                    if self.backend_swarm_quorum_reachable { "reachable" } else { "not reachable" },
                    self.backend_swarm_estimated_saving_percent,
                ))
                .size(11)
                .color(c(TEXT_D())),
                text(if self.backend_swarm_summary.is_empty() {
                    "Summary: unavailable".to_owned()
                } else {
                    format!("Summary: {}", self.backend_swarm_summary)
                })
                .size(11)
                .color(c(TEXT_D())),
            ]
            .spacing(8)
            .width(Length::Fill),
        )
        .padding(16)
        .style(panel_frame_style)
        .width(Length::Fill)
        .into()
    }

    fn root_view(&self) -> Element<'_, Message> {
        if self.current_user.is_none() {
            return self.view_auth();
        }

        // Drop-Annotation-Modal hat Priorität vor der normalen Ansicht
        if self.drop_pending_path.is_some() {
            return self.view_drop_annotation();
        }

        match self.app_mode {
            AppMode::Overlay => self.view_overlay(),
            AppMode::Full => {
                let shell = self.view_shell();
                let global_bar = self.view_global_control_bar();
                let minimize_bar = container(
                    row![
                        text("Kompaktleiste am unteren Rand | Esc blendet um").size(11).color(c(TEXT_M())),
                        iced::widget::Space::new(Length::Fill, Length::Shrink),
                        button(text("▼ Zur Kompaktleiste (Esc)").size(11).color(c(TEXT_H())))
                            .on_press(Message::ToggleMode)
                            .style(|_: &Theme, _| button::Style {
                                background: Some(Background::Color(c(BG_CARD()))),
                                border: Border { color: c(BORDER()), width: 1.0, radius: 4.0.into() },
                                text_color: c(TEXT_M()),
                                ..Default::default()
                            })
                            .padding([3, 10]),
                    ]
                    .padding([4, 12])
                )
                .width(Length::Fill)
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(c(BG_BASE()))),
                    border: Border { color: c(BORDER()), width: 1.0, radius: 0.0.into() },
                    ..Default::default()
                });

                column![shell, global_bar, minimize_bar].into()
            }
        }
    }
}

fn app_title(_state: &AetherIcedShell) -> String {
    "Aether".to_owned()
}

fn app_theme(state: &AetherIcedShell) -> Theme {
    state.theme_definition()
}

fn app_update(state: &mut AetherIcedShell, message: Message) -> Task<Message> {
    state.handle_message(message)
}

fn app_view(state: &AetherIcedShell) -> Element<'_, Message> {
    state.root_view()
}

fn app_event(event: iced::Event, status: event::Status, _window: window::Id) -> Option<Message> {
    if status == event::Status::Captured {
        return None;
    }
    match event {
        iced::Event::Keyboard(keyboard::Event::KeyPressed { key, .. }) => {
            if key == keyboard::Key::Named(keyboard::key::Named::Escape) {
                return Some(Message::ToggleMode);
            }
            None
        }
        iced::Event::Window(window::Event::CloseRequested) => {
            Some(Message::CloseWindowRequested(_window))
        }
        iced::Event::Window(window::Event::Resized(size)) => {
            Some(Message::WindowResized(size.width, size.height))
        }
        iced::Event::Window(window::Event::FileHovered(path)) => Some(Message::FileHovered(path)),
        iced::Event::Window(window::Event::FilesHoveredLeft) => Some(Message::FileHoverCleared),
        iced::Event::Window(window::Event::FileDropped(path)) => Some(Message::FileDropped(path)),
        _ => None,
    }
}

fn app_subscription(state: &AetherIcedShell) -> Subscription<Message> {
    Subscription::batch(vec![
        event::listen_with(app_event),
        time::every(Duration::from_millis(state.tick_interval_ms())).map(|_| Message::Tick),
    ])
}

/// Führt `start.py` synchron aus wenn `data/keys/node_private.key` fehlt (Erststart).
/// Blockiert bis start.py beendet ist — kein GUI-Start davor.
fn run_bootstrap_if_needed() {
    let root = crate::app_root();
    let key_path = root.join("data").join("keys").join("node_private.key");
    if key_path.exists() {
        return;
    }
    let start_py = root.join("start.py");
    if !start_py.exists() {
        eprintln!("[aether] start.py nicht gefunden unter {}. Bootstrap uebersprungen.", start_py.display());
        return;
    }
    // Python-Executable suchen: python → python3 → py (Windows Launcher)
    let candidates = ["python", "python3", "py"];
    let python_exe = candidates.iter().find(|&&candidate| {
        std::process::Command::new(candidate)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }).copied();
    let Some(python) = python_exe else {
        eprintln!("[aether] Kein Python-Interpreter gefunden. Bootstrap manuell ausfuehren: python start.py");
        return;
    };
    eprintln!("[aether] Erststart erkannt — fuehre start.py aus ({python})...");
    match std::process::Command::new(python)
        .arg(start_py.as_os_str())
        .current_dir(&root)
        .status()
    {
        Ok(status) if status.success() => {
            eprintln!("[aether] Bootstrap abgeschlossen.");
        }
        Ok(status) => {
            eprintln!("[aether] start.py beendet mit Status: {status}. Starte trotzdem weiter.");
        }
        Err(err) => {
            eprintln!("[aether] start.py konnte nicht gestartet werden: {err}");
        }
    }
}

pub fn run() -> iced::Result {
    run_bootstrap_if_needed();
    iced::application(app_title, app_update, app_view)
        .theme(app_theme)
        .subscription(app_subscription)
        .settings(Settings {
            antialiasing: true,
            ..Settings::default()
        })
        .window(window::Settings {
            size: iced::Size::new(FULL_WINDOW_WIDTH, FULL_WINDOW_HEIGHT),
            min_size: Some(iced::Size::new(960.0, 640.0)),
            position: window::Position::Specific(Point::new(36.0, 28.0)),
            decorations: true,
            ..window::Settings::default()
        })
        .run_with(|| {
            let startup_resize = window::get_latest().then(|id_opt| {
                if let Some(id) = id_opt {
                    window::resize(id, iced::Size::new(FULL_WINDOW_WIDTH, FULL_WINDOW_HEIGHT))
                } else {
                    Task::none()
                }
            });
            (AetherIcedShell::bootstrap(), startup_resize)
        })
}

fn make_sparkline(fill: f32) -> String {
    let total = 20usize;
    let filled = (fill.clamp(0.0, 1.0) * total as f32) as usize;
    let empty = total - filled;
    format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
}

// ---------------------------------------------------------------------------
// Aether.FlowSphere – deterministic 3D sphere projection (iced Canvas)
// Replaces the old 10-ring StructureMap as the modern structural visualizer.
// All animation parameters are derived from tick + entropy, no random values.
// ---------------------------------------------------------------------------

struct FlowSphereScene {
    tick: u64,
    entropy: f32,
    stability: f32,
    delta_phases: [f32; 5],   // 5 delta arc event phases
    attractor_lons: [f32; 6], // 6 attractor longitude positions
    info_growth: f32,
    zoom: f32,
    manual_rotation_offset: f32,
    view_mode: bool, // true=Local (Attraktoren), false=Global (Swarm nodes)
    swarm_nodes: Vec<(String, f32, f32, f32)>, // (name, lat, lon, coherence_score)
    anomaly_level: f32,
    external_link_strength: f32,
    noether_consistency: f32,
    active_focus_key: String,
    // Unabhaengige Layer-Schalter
    show_internal: bool,        // Interne Verbindungen (Attractor-Graph + Kanten)
    show_external: bool,        // Externe Verbindungen (Swarm-Orbit + Bruecken)
    domain_names: Vec<String>,  // Benutzerdefinierte Domaennamen fuer Attraktoren
    broadcast_visible: Option<String>,
}

impl FlowSphereScene {
    fn scene_geometry(&self, bounds: Rectangle) -> (Point, f32, f32) {
        (
            Point::new(bounds.width * 0.5, bounds.height * 0.53),
            bounds.width.min(bounds.height) * 0.28 * self.zoom.clamp(0.7, 1.7),
            self.manual_rotation_offset + self.tick as f32 * 0.0075,
        )
    }

    fn project(&self, bounds: Rectangle, lat: f32, lon: f32) -> (Point, f32) {
        let (center, sphere_radius, rotation) = self.scene_geometry(bounds);
        let lon = lon + rotation;
        let x = lat.cos() * lon.cos();
        let y = lat.sin();
        let z = lat.cos() * lon.sin();
        let depth = ((z + 1.0) * 0.5).clamp(0.0, 1.0);
        let scale = 0.72 + depth * 0.28;
        (
            Point::new(center.x + x * sphere_radius * scale, center.y + y * sphere_radius),
            depth,
        )
    }

    fn attractor_point(&self, bounds: Rectangle, idx: usize) -> (Point, f32) {
        let lon = self.attractor_lons.get(idx).copied().unwrap_or(0.0);
        let lat = ((idx as f32 * 0.63) + self.info_growth * 0.05).sin() * 0.58 * (0.35 + self.stability * 0.55);
        self.project(bounds, lat, lon)
    }

    fn swarm_point(&self, bounds: Rectangle, idx: usize) -> Option<Point> {
        let (_, orbit_radius, rotation) = self.scene_geometry(bounds);
        let orbit_radius = orbit_radius * (1.42 + self.external_link_strength * 0.14);
        self.swarm_nodes.get(idx).map(|(_, _, lon, _)| {
            let (center, _, _) = self.scene_geometry(bounds);
            let angle = *lon + rotation * 0.35;
            Point::new(
                center.x + angle.cos() * orbit_radius,
                center.y + angle.sin() * orbit_radius * 0.58,
            )
        })
    }

    fn hit_index(&self, bounds: Rectangle, cursor: Point) -> Option<usize> {
        if self.view_mode {
            (0..self.attractor_lons.len()).find(|idx| {
                let (point, _) = self.attractor_point(bounds, *idx);
                let dx = cursor.x - point.x;
                let dy = cursor.y - point.y;
                (dx * dx + dy * dy).sqrt() <= 18.0
            })
        } else {
            (0..self.swarm_nodes.len()).find(|idx| {
                self.swarm_point(bounds, *idx)
                    .map(|point| {
                        let dx = cursor.x - point.x;
                        let dy = cursor.y - point.y;
                        (dx * dx + dy * dy).sqrt() <= 18.0
                    })
                    .unwrap_or(false)
            })
        }
    }
}

impl canvas::Program<Message> for FlowSphereScene {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        use std::f32::consts::{FRAC_PI_2, PI, TAU};

        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let width = bounds.width;
        let height = bounds.height;
        let center = Point::new(width * 0.5, height * 0.53);
        let sphere_radius = width.min(height) * 0.28 * self.zoom.clamp(0.7, 1.7);
        let rotation = self.manual_rotation_offset + self.tick as f32 * 0.0075;

        let background_top = Color::from_rgb8(0x03, 0x09, 0x12);
        let background_bottom = Color::from_rgb8(0x09, 0x15, 0x22);
        let local_shell = Color::from_rgba(0.45, 0.25, 0.86, if self.show_internal { 0.22 } else { 0.06 });
        let global_shell = Color::from_rgba(0.16, 0.74, 0.76, if self.show_external { 0.22 } else { 0.06 });
        let shell_opacity = if self.show_internal && self.show_external { 0.14 } else { 0.20 };
        let _ = shell_opacity; // used below
        let grid_color = Color::from_rgba(0.45, 0.67, 0.82, 0.18);
        let internal_color = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let external_color = Color::from_rgb8(0x7F, 0xD9, 0xFF);
        let stable_color = Color::from_rgb8(0x4C, 0xD9, 0x6E);
        let anomaly_color = Color::from_rgb8(0xD9, 0x50, 0x50);
        let pulse_color = Color::from_rgb8(0xFF, 0xD7, 0x00);
        let focus_is_internal = self.active_focus_key == "internal_core";
        let focus_is_overlay = self.active_focus_key == "overlay";
        let focus_is_anomaly = self.active_focus_key == "anomaly";
        let focus_is_external = self.active_focus_key == "external_links";

        frame.fill_rectangle(Point::ORIGIN, bounds.size(), background_top);
        frame.fill(
            &canvas::Path::rectangle(Point::new(0.0, height * 0.58), Size::new(width, height * 0.42)),
            background_bottom,
        );

        let project = |lat: f32, lon: f32| -> (Point, f32) {
            let lon = lon + rotation;
            let x = lat.cos() * lon.cos();
            let y = lat.sin();
            let z = lat.cos() * lon.sin();
            let depth = ((z + 1.0) * 0.5).clamp(0.0, 1.0);
            let scale = 0.72 + depth * 0.28;
            (
                Point::new(
                    center.x + x * sphere_radius * scale,
                    center.y + y * sphere_radius,
                ),
                depth,
            )
        };

        // Shell-Farbe: beide Layer koennen gleichzeitig aktiv sein
        let shell_color = match (self.show_internal, self.show_external) {
            (true, true)   => Color::from_rgba(0.30, 0.48, 0.74, 0.18), // Blau-Mix
            (true, false)  => local_shell,
            (false, true)  => global_shell,
            (false, false) => Color::from_rgba(0.22, 0.28, 0.36, 0.10),
        };
        frame.fill(&canvas::Path::circle(center, sphere_radius * 1.03), shell_color);
        frame.stroke(
            &canvas::Path::circle(center, sphere_radius),
            canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.65, 0.82, 0.95, 0.30)),
                width: 1.2,
                ..canvas::Stroke::default()
            },
        );

        for lat_idx in -2..=2 {
            let lat = lat_idx as f32 * FRAC_PI_2 / 3.4;
            let path = canvas::Path::new(|builder| {
                for step in 0..=48 {
                    let lon = -PI + TAU * step as f32 / 48.0;
                    let (point, _) = project(lat, lon);
                    if step == 0 {
                        builder.move_to(point);
                    } else {
                        builder.line_to(point);
                    }
                }
            });
            frame.stroke(
                &path,
                canvas::Stroke {
                    style: canvas::Style::Solid(grid_color),
                    width: 1.0,
                    ..canvas::Stroke::default()
                },
            );
        }

        for lon_idx in 0..8 {
            let lon = lon_idx as f32 * TAU / 8.0;
            let path = canvas::Path::new(|builder| {
                for step in 0..=36 {
                    let lat = -FRAC_PI_2 * 0.94 + PI * 0.94 * step as f32 / 36.0;
                    let (point, _) = project(lat, lon);
                    if step == 0 {
                        builder.move_to(point);
                    } else {
                        builder.line_to(point);
                    }
                }
            });
            frame.stroke(
                &path,
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(0.40, 0.58, 0.72, 0.12)),
                    width: 0.9,
                    ..canvas::Stroke::default()
                },
            );
        }

        // === INTERNAL LAYER: Kern, Wellen, Verteilungsfelder =========
        if self.show_internal {
        for band_idx in 0..3 {
            let lat = (band_idx as f32 - 1.0) * 0.28 + (self.info_growth * 0.15);
            let spread = (0.14 + self.entropy * 0.18 + band_idx as f32 * 0.03).clamp(0.10, 0.34);
            let path = canvas::Path::new(|builder| {
                for step in 0..=72 {
                    let lon = -PI + TAU * step as f32 / 72.0;
                    let wobble = (lon * (1.2 + band_idx as f32 * 0.35) + rotation * 0.85).sin() * spread;
                    let (point, _) = project((lat + wobble).clamp(-1.1, 1.1), lon);
                    if step == 0 {
                        builder.move_to(point);
                    } else {
                        builder.line_to(point);
                    }
                }
            });
            frame.stroke(
                &path,
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(internal_color.r, internal_color.g, internal_color.b, 0.12 + band_idx as f32 * 0.05)),
                    width: 5.0 + band_idx as f32 * 2.0,
                    ..canvas::Stroke::default()
                },
            );
        }
        let core_radius = sphere_radius * (0.18 + self.stability * 0.10);
        frame.fill(
            &canvas::Path::circle(center, core_radius),
            Color::from_rgba(stable_color.r, stable_color.g, stable_color.b, 0.22 + self.stability * 0.16 + if focus_is_internal { 0.12 } else { 0.0 }),
        );
        frame.stroke(
            &canvas::Path::circle(center, core_radius * 1.35),
            canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(internal_color.r, internal_color.g, internal_color.b, if focus_is_internal { 0.58 } else { 0.28 })),
                width: if focus_is_internal { 2.4 } else { 1.0 },
                ..canvas::Stroke::default()
            },
        );

        for wave_idx in 0..3 {
            let path = canvas::Path::new(|builder| {
                for step in 0..=64 {
                    let lon = -PI + TAU * step as f32 / 64.0;
                    let lat = ((lon * (wave_idx as f32 + 1.35) + rotation * 1.2).sin() * 0.12)
                        + (wave_idx as f32 - 1.0) * 0.18 * self.entropy;
                    let (point, _) = project(lat.clamp(-1.1, 1.1), lon);
                    if step == 0 {
                        builder.move_to(point);
                    } else {
                        builder.line_to(point);
                    }
                }
            });
            frame.stroke(
                &path,
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(internal_color.r, internal_color.g, internal_color.b, 0.22 + wave_idx as f32 * 0.05 + if focus_is_overlay { 0.12 } else { 0.0 })),
                    width: if focus_is_overlay { 2.0 } else { 1.3 },
                    ..canvas::Stroke::default()
                },
            );
        }

        // Interne Domaen-Kanten: verbinde benachbarte Attraktoren
        let attractor_pts: Vec<(Point, f32)> = self.attractor_lons.iter().enumerate().map(|(idx, lon)| {
            let lat = ((idx as f32 * 0.63) + self.info_growth * 0.05).sin() * 0.58 * (0.35 + self.stability * 0.55);
            project(lat, *lon)
        }).collect();
        for i in 0..attractor_pts.len() {
            let j = (i + 1) % attractor_pts.len();
            let (pi, _di) = attractor_pts[i];
            let (pj, _dj) = attractor_pts[j];
            let edge = canvas::Path::new(|builder| {
                builder.move_to(pi);
                builder.line_to(pj);
            });
            // Adjazente Kanten: solid, komplex = entferntere mit gestrichelt
            if j == i + 1 {
                frame.stroke(&edge, canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(internal_color.r, internal_color.g, internal_color.b,
                        0.28 + self.noether_consistency * 0.18 + if focus_is_internal { 0.14 } else { 0.0 })),
                    width: if focus_is_internal { 1.6 } else { 1.0 },
                    ..canvas::Stroke::default()
                });
            }
        }
        // Diagonale Kanten (domäneninterne Langstrecken-Kopplungen)
        for i in 0..attractor_pts.len() {
            let j = (i + 2) % attractor_pts.len();
            let (pi, _) = attractor_pts[i];
            let (pj, _) = attractor_pts[j];
            let coupling = ((self.noether_consistency - 0.35) * 1.8).clamp(0.0, 1.0);
            if coupling > 0.2 {
                let edge = canvas::Path::new(|builder| { builder.move_to(pi); builder.line_to(pj); });
                frame.stroke(&edge, canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(internal_color.r * 0.7, internal_color.g * 0.7, 1.0,
                        coupling * 0.18)),
                    width: 0.8,
                    line_dash: canvas::LineDash { segments: &[5.0, 6.0], offset: 0 },
                    ..canvas::Stroke::default()
                });
            }
        }

        for (idx, lon) in self.attractor_lons.iter().enumerate() {
            let lat = ((idx as f32 * 0.63) + self.info_growth * 0.05).sin() * 0.58 * (0.35 + self.stability * 0.55);
            let (point, depth) = project(lat, *lon);
            let radius = 5.5 + depth * 4.0;
            let is_selected = self.active_focus_key == format!("attractor_{}", idx);
            let color = Color::from_rgba(stable_color.r, stable_color.g, stable_color.b, 0.45 + depth * 0.35);
            frame.fill(
                &canvas::Path::circle(point, radius + 10.0 + self.entropy * 8.0),
                Color::from_rgba(stable_color.r, stable_color.g, stable_color.b, 0.05 + depth * 0.08),
            );
            frame.fill(&canvas::Path::circle(point, radius), color);
            frame.stroke(
                &canvas::Path::circle(point, radius + 4.0 + self.entropy * 4.0),
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(external_color.r, external_color.g, external_color.b, 0.16 + depth * 0.15 + if is_selected { 0.28 } else { 0.0 })),
                    width: if is_selected { 2.4 } else { 1.0 },
                    ..canvas::Stroke::default()
                },
            );
            if is_selected {
                if let Some(label) = self.domain_names.get(idx).map(|s| s.trim()).filter(|label| !label.is_empty()) {
                frame.fill_text(canvas::Text {
                    content: label.to_owned(),
                    position: Point::new(point.x + radius + 6.0, point.y - 3.0),
                    color: Color::from_rgba(stable_color.r, stable_color.g, stable_color.b, 0.72 + if is_selected { 0.20 } else { 0.0 }),
                    size: iced::Pixels(if is_selected { 11.0 } else { 9.5 }),
                    horizontal_alignment: iced::alignment::Horizontal::Left,
                    vertical_alignment: iced::alignment::Vertical::Center,
                    ..canvas::Text::default()
                });
                }
            }
        }
        } // end show_internal

        for (idx, phase) in self.delta_phases.iter().enumerate() {
            let lon = rotation * 0.6 + idx as f32 * TAU / self.delta_phases.len() as f32;
            let lat = (phase * 0.18).sin() * 0.72;
            let (point, depth) = project(lat, lon);
            let pulse_radius = 3.5 + (phase.sin().abs() * 4.0) + depth * 2.0;
            frame.fill(
                &canvas::Path::circle(point, pulse_radius),
                Color::from_rgba(pulse_color.r, pulse_color.g, pulse_color.b, 0.32 + depth * 0.26 + if focus_is_overlay { 0.18 } else { 0.0 }),
            );
            frame.stroke(
                &canvas::Path::circle(point, pulse_radius + 4.0),
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(pulse_color.r, pulse_color.g, pulse_color.b, 0.18 + if focus_is_overlay { 0.24 } else { 0.0 })),
                    width: if focus_is_overlay { 2.0 } else { 1.0 },
                    ..canvas::Stroke::default()
                },
            );
        }

        let anomaly_count = if self.anomaly_level > 0.15 {
            1 + (self.anomaly_level * 3.0).floor() as usize
        } else {
            0
        };
        for idx in 0..anomaly_count {
            let lon = rotation + idx as f32 * TAU / (anomaly_count.max(1) as f32) + 0.45;
            let lat = ((idx as f32 * 1.4) + self.entropy * PI).sin() * 0.62;
            let (point, depth) = project(lat, lon);
            let spike = Point::new(point.x + 18.0 + depth * 12.0, point.y - 12.0);
            let marker = canvas::Path::new(|builder| {
                builder.move_to(Point::new(point.x - 6.0, point.y));
                builder.line_to(Point::new(point.x + 6.0, point.y));
                builder.move_to(Point::new(point.x, point.y - 6.0));
                builder.line_to(Point::new(point.x, point.y + 6.0));
                builder.move_to(point);
                builder.line_to(spike);
            });
            frame.stroke(
                &marker,
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(anomaly_color.r, anomaly_color.g, anomaly_color.b, 0.65 + if focus_is_anomaly { 0.18 } else { 0.0 })),
                    width: if focus_is_anomaly { 2.2 } else { 1.4 },
                    ..canvas::Stroke::default()
                },
            );
            frame.stroke(
                &canvas::Path::circle(point, 9.0 + depth * 4.0),
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(anomaly_color.r, anomaly_color.g, anomaly_color.b, 0.42 + if focus_is_anomaly { 0.16 } else { 0.0 })),
                    width: if focus_is_anomaly { 2.0 } else { 1.2 },
                    ..canvas::Stroke::default()
                },
            );
        }

        // === EXTERNAL LAYER: Orbit, Swarm-Knoten, Broadcast-Label ===
        if self.show_external {
            let orbit_radius = sphere_radius * (1.42 + self.external_link_strength * 0.14);
            frame.stroke(
                &canvas::Path::circle(center, orbit_radius),
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(external_color.r, external_color.g, external_color.b, 0.18 + if focus_is_external { 0.18 } else { 0.0 })),
                    width: if focus_is_external { 1.8 } else { 1.0 },
                    line_dash: canvas::LineDash { segments: &[7.0, 5.0], offset: 0 },
                    ..canvas::Stroke::default()
                },
            );
            let orbit_points: Vec<(Point, f32)> = self.swarm_nodes.iter().map(|(_, _lat, lon, coherence)| {
                let angle = *lon + rotation * 0.35;
                (
                    Point::new(
                        center.x + angle.cos() * orbit_radius,
                        center.y + angle.sin() * orbit_radius * 0.58,
                    ),
                    *coherence,
                )
            }).collect();
            for idx in 0..orbit_points.len() {
                let next = (idx + 1) % orbit_points.len().max(1);
                if let Some((point_a, coh_a)) = orbit_points.get(idx).copied() {
                    if let Some((point_b, coh_b)) = orbit_points.get(next).copied() {
                        let density_arc = canvas::Path::new(|builder| {
                            builder.move_to(point_a);
                            builder.line_to(point_b);
                        });
                        let density = ((coh_a + coh_b) * 0.5).clamp(0.0, 1.0);
                        frame.stroke(
                            &density_arc,
                            canvas::Stroke {
                                style: canvas::Style::Solid(Color::from_rgba(external_color.r, external_color.g, external_color.b, 0.08 + density * 0.18)),
                                width: 1.2 + density * 2.2,
                                ..canvas::Stroke::default()
                            },
                        );
                    }
                }
            }
            for (idx, (name, lat, lon, coherence)) in self.swarm_nodes.iter().enumerate() {
                let (anchor, _) = project(*lat * 0.55, *lon);
                let angle = *lon + rotation * 0.35;
                let node_point = Point::new(
                    center.x + angle.cos() * orbit_radius,
                    center.y + angle.sin() * orbit_radius * 0.58,
                );
                let node_color = if *coherence > 0.72 { stable_color } else if *coherence > 0.45 { pulse_color } else { anomaly_color };
                let is_selected = self.active_focus_key == format!("swarm_{}", idx);
                let bridge = canvas::Path::new(|builder| { builder.move_to(anchor); builder.line_to(node_point); });
                frame.stroke(&bridge, canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(node_color.r, node_color.g, node_color.b, 0.20 + self.external_link_strength * 0.22 + if is_selected || focus_is_external { 0.16 } else { 0.0 })),
                    width: if is_selected { 2.4 } else if focus_is_external { 1.6 } else { 1.1 },
                    ..canvas::Stroke::default()
                });
                frame.fill(&canvas::Path::circle(node_point, 5.0 + *coherence * 4.0), node_color);
                frame.stroke(&canvas::Path::circle(node_point, 9.0 + (1.0 - *coherence) * 4.0), canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(node_color.r, node_color.g, node_color.b, 0.18 + if is_selected { 0.22 } else { 0.0 })),
                    width: if is_selected { 2.2 } else { 1.0 },
                    ..canvas::Stroke::default()
                });
                if is_selected {
                    frame.fill_text(canvas::Text {
                        content: name.clone(),
                        position: Point::new(node_point.x + 10.0, node_point.y - 4.0),
                        color: Color::from_rgba(0.76, 0.88, 0.96, 0.82),
                        size: iced::Pixels(10.0),
                        horizontal_alignment: iced::alignment::Horizontal::Left,
                        vertical_alignment: iced::alignment::Vertical::Center,
                        ..canvas::Text::default()
                    });
                }
            }
            if let Some(visible) = &self.broadcast_visible {
                frame.fill_text(canvas::Text {
                    content: format!("\u{25CE} Broadcast: {}", visible),
                    position: Point::new(center.x, center.y + orbit_radius + 14.0),
                    color: Color::from_rgba(external_color.r, external_color.g, external_color.b, 0.88),
                    size: iced::Pixels(11.0),
                    horizontal_alignment: iced::alignment::Horizontal::Center,
                    vertical_alignment: iced::alignment::Vertical::Top,
                    ..canvas::Text::default()
                });
            }
        } // end show_external

        frame.fill_text(canvas::Text {
            content: match (self.show_internal, self.show_external) {
                (true, true)   => "Intern + Extern: Verteilungsfelder und Netzbezug".to_owned(),
                (true, false)  => "Interne Verteilungen: Kern, Dichtefelder, Kopplungsgraph".to_owned(),
                (false, true)  => "Externe Verteilungen: Orbitdichte, Peers, Drift".to_owned(),
                (false, false) => "Alle Layer ausgeblendet - Schalter aktivieren".to_owned(),
            },
            position: Point::new(18.0, 22.0),
            color: Color::from_rgb8(0xD8, 0xE6, 0xF2),
            size: iced::Pixels(13.0),
            horizontal_alignment: iced::alignment::Horizontal::Left,
            vertical_alignment: iced::alignment::Vertical::Center,
            ..canvas::Text::default()
        });
        frame.fill_text(canvas::Text {
            content: format!(
                "Shannon {:.2} bit | Noether {:.0}% | externe Kopplung {:.0}% | Anomalie {:.0}%",
                self.entropy * 7.83,
                self.noether_consistency * 100.0,
                self.external_link_strength * 100.0,
                self.anomaly_level * 100.0
            ),
            position: Point::new(18.0, 40.0),
            color: Color::from_rgb8(0x7B, 0x97, 0xAA),
            size: iced::Pixels(10.0),
            horizontal_alignment: iced::alignment::Horizontal::Left,
            vertical_alignment: iced::alignment::Vertical::Center,
            ..canvas::Text::default()
        });
        frame.fill_text(canvas::Text {
            content: if self.show_internal && self.show_external {
                "Beide Layer: Musterdichte innen, Peer-Verteilung aussen. Namen bleiben Nebensache.".to_owned()
            } else if self.show_internal {
                "Lokalmodus zeigt Verteilungsfelder und Kernpunkte. Nutzerhinweise erscheinen nur im Fokus.".to_owned()
            } else if self.show_external {
                "Globalmodus zeigt Peer-Verteilung und Kopplung. Broadcast wird erst nach Anfrage und Zustimmung sichtbar.".to_owned()
            } else {
                "Schalter 'Intern' oder 'Extern' aktivieren, um Ebenen einzublenden.".to_owned()
            },
            position: Point::new(18.0, 56.0),
            color: Color::from_rgb8(0x90, 0xA8, 0xB8),
            size: iced::Pixels(10.0),
            horizontal_alignment: iced::alignment::Horizontal::Left,
            vertical_alignment: iced::alignment::Vertical::Center,
            ..canvas::Text::default()
        });

        vec![frame.into_geometry()]
    }

    fn update(
        &self,
        _state: &mut Self::State,
        event: canvas::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> (event::Status, Option<Message>) {
        match event {
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                if let Some(position) = cursor.position_in(bounds) {
                    if let Some(idx) = self.hit_index(bounds, position) {
                        return (event::Status::Captured, Some(Message::FlowSphereNodeClicked(idx)));
                    }
                }
                (event::Status::Ignored, None)
            }
            _ => (event::Status::Ignored, None),
        }
    }

    fn mouse_interaction(
        &self,
        _state: &Self::State,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        if let Some(position) = cursor.position_in(bounds) {
            if self.hit_index(bounds, position).is_some() {
                return mouse::Interaction::Pointer;
            }
        }
        mouse::Interaction::default()
    }
}

// ---------------------------------------------------------------------------
// Aether.MetricRadar – hexagonales Radar-Chart fuer FlowSphere-Seitenleiste
// Zeigt 6 Kernmetriken (Trust, Stabilitaet, Noether, Delta, Benford, Bayes)
// auf einem halbtransparenten 6-Achsen-Spinner mit Puls-Animation.
// ---------------------------------------------------------------------------
struct MetricRadarScene {
    /// Signal A: normierte Rohwerte [0,1], 12 Achsen, feste deterministisch auditierbare Reihenfolge:
    /// 0 Shannon | 1 PermEnt | 2 KatzFD | 3 Zipf | 4 Benford | 5 Fourier |
    /// 6 Noether | 7 H-Lambda | 8 Symmetrie | 9 SCE | 10 DeltaKonv | 11 Bayes
    /// Normierungsregeln (invertierbar): Shannon/8.0, KatzFD/2.0, Zipf/3.0, Fourier=ln1p(x)/3.912
    /// Alle anderen Werte kommen direkt [0,1] aus der Pipeline.
    values_a: [f32; 12],
    /// Signal B (optionaler Vergleich) – exakt dieselbe Normierung
    values_b: Option<[f32; 12]>,
    /// Achsen-Indizes mit strukturellem Widerspruch (A>0.65 & B<0.35 oder umgekehrt)
    contradiction_axes: Vec<usize>,
    tick: u64,
    /// Label fuer Signal A
    label_a: String,
    /// Label fuer Signal B
    label_b: String,
}

impl canvas::Program<Message> for MetricRadarScene {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        use std::f32::consts::PI;

        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let cx = bounds.width * 0.5;
        let cy = bounds.height * 0.52;
        let max_r = bounds.width.min(bounds.height) * 0.34;
        let n = 12usize;

        // Achsen-Labels (fix, deterministisch) + individuelle Farben
        let labels = [
            "Shannon", "PermEnt", "KatzFD", "Zipf\u{03b1}",
            "Benford", "Fourier", "Noether", "H-\u{03bb}",
            "Symm", "SCE", "\u{0394}Konv", "Bayes",
        ];
        let axis_colors = [
            Color::from_rgb8(0xAF, 0x86, 0xFF), // Shannon
            Color::from_rgb8(0x88, 0x60, 0xFF), // PermEnt
            Color::from_rgb8(0xFF, 0xB0, 0x50), // KatzFD
            Color::from_rgb8(0x7F, 0xD9, 0xFF), // Zipf
            Color::from_rgb8(0xC0, 0x8D, 0xFF), // Benford
            Color::from_rgb8(0xFF, 0xD7, 0x00), // Fourier
            Color::from_rgb8(0x4C, 0xD9, 0x6E), // Noether
            Color::from_rgb8(0xFF, 0x70, 0x50), // H-λ
            Color::from_rgb8(0x50, 0xD0, 0xFF), // Symmetrie
            Color::from_rgb8(0xD9, 0xA0, 0x50), // SCE
            Color::from_rgb8(0x80, 0xFF, 0xB0), // ΔKonv
            Color::from_rgb8(0xFF, 0x90, 0xC0), // Bayes
        ];
        let contradiction_color = Color::from_rgb8(0xFF, 0x30, 0x30);

        frame.fill_rectangle(Point::ORIGIN, bounds.size(), Color::from_rgb8(0x03, 0x09, 0x12));

        let axis_pt = |i: usize, r: f32| -> Point {
            let angle = -PI / 2.0 + i as f32 * 2.0 * PI / n as f32;
            Point::new(cx + angle.cos() * r, cy + angle.sin() * r)
        };

        // Skalierungsringe 25/50/75/100%
        for ring in 1..=4usize {
            let r = max_r * ring as f32 / 4.0;
            let ring_path = canvas::Path::new(|builder| {
                for i in 0..n {
                    let p = axis_pt(i, r);
                    if i == 0 { builder.move_to(p); } else { builder.line_to(p); }
                }
                builder.close();
            });
            frame.stroke(&ring_path, canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.50, 0.65, 0.82,
                    if ring == 4 { 0.28 } else { 0.10 })),
                width: if ring == 4 { 1.1 } else { 0.6 },
                ..canvas::Stroke::default()
            });
            // Prozentwert at 100%-Ring
            if ring == 4 {
                frame.fill_text(canvas::Text {
                    content: "100".to_owned(),
                    position: Point::new(cx + 3.0, cy - max_r - 2.0),
                    color: Color::from_rgba(0.50, 0.65, 0.82, 0.45),
                    size: iced::Pixels(7.5),
                    horizontal_alignment: iced::alignment::Horizontal::Left,
                    vertical_alignment: iced::alignment::Vertical::Bottom,
                    ..canvas::Text::default()
                });
            }
        }

        // Achslinien — Widerspruchs-Achsen rot markieren
        for i in 0..n {
            let tip = axis_pt(i, max_r);
            let is_contradiction = self.contradiction_axes.contains(&i);
            let axis_line = canvas::Path::new(|builder| {
                builder.move_to(Point::new(cx, cy));
                builder.line_to(tip);
            });
            frame.stroke(&axis_line, canvas::Stroke {
                style: canvas::Style::Solid(if is_contradiction {
                    Color::from_rgba(contradiction_color.r, contradiction_color.g, contradiction_color.b, 0.60)
                } else {
                    Color::from_rgba(0.40, 0.55, 0.70, 0.22)
                }),
                width: if is_contradiction { 1.6 } else { 0.7 },
                ..canvas::Stroke::default()
            });
        }

        // Signal B (Vergleich) – zuerst zeichnen damit A drueber liegt
        if let Some(vals_b) = &self.values_b {
            let path_b = canvas::Path::new(|builder| {
                for i in 0..n {
                    let p = axis_pt(i, max_r * vals_b[i].clamp(0.0, 1.0));
                    if i == 0 { builder.move_to(p); } else { builder.line_to(p); }
                }
                builder.close();
            });
            frame.fill(&path_b, Color::from_rgba(1.0, 0.55, 0.20, 0.12));
            frame.stroke(&path_b, canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(1.0, 0.65, 0.20, 0.70)),
                width: 1.4,
                line_dash: canvas::LineDash { segments: &[6.0, 4.0], offset: 0 },
                ..canvas::Stroke::default()
            });
            // Punkte B
            for i in 0..n {
                let p = axis_pt(i, max_r * vals_b[i].clamp(0.0, 1.0));
                frame.fill(&canvas::Path::circle(p, 2.8),
                    Color::from_rgba(1.0, 0.65, 0.20, 0.85));
            }
        }

        // Signal A (aktuell) – Haupt-Polygon
        let path_a = canvas::Path::new(|builder| {
            for i in 0..n {
                let p = axis_pt(i, max_r * self.values_a[i].clamp(0.0, 1.0));
                if i == 0 { builder.move_to(p); } else { builder.line_to(p); }
            }
            builder.close();
        });
        frame.fill(&path_a, Color::from_rgba(0.30, 0.65, 1.00, 0.16));
        frame.stroke(&path_a, canvas::Stroke {
            style: canvas::Style::Solid(Color::from_rgba(0.55, 0.82, 1.00, 0.80)),
            width: 1.7,
            ..canvas::Stroke::default()
        });

        // Punkte A (Achsenfarbe)
        for i in 0..n {
            let p = axis_pt(i, max_r * self.values_a[i].clamp(0.0, 1.0));
            let is_contra = self.contradiction_axes.contains(&i);
            let color = if is_contra { contradiction_color } else { axis_colors[i] };
            frame.fill(&canvas::Path::circle(p, if is_contra { 5.0 } else { 3.5 }), color);
            // Wert als Prozent direkt am Punkt (nur wenn Platz)
            let pct = format!("{:.0}", self.values_a[i] * 100.0);
            frame.fill_text(canvas::Text {
                content: pct,
                position: Point::new(p.x, p.y - 7.0),
                color: Color::from_rgba(color.r, color.g, color.b, 0.75),
                size: iced::Pixels(7.5),
                horizontal_alignment: iced::alignment::Horizontal::Center,
                vertical_alignment: iced::alignment::Vertical::Bottom,
                ..canvas::Text::default()
            });
        }

        // Widerspruchs-Pfeile: Differenzlinie zwischen A und B an Widerspruchs-Achsen
        if let Some(vals_b) = &self.values_b {
            for &i in &self.contradiction_axes {
                let pa = axis_pt(i, max_r * self.values_a[i].clamp(0.0, 1.0));
                let pb = axis_pt(i, max_r * vals_b[i].clamp(0.0, 1.0));
                let diff_line = canvas::Path::new(|builder| {
                    builder.move_to(pa);
                    builder.line_to(pb);
                });
                frame.stroke(&diff_line, canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(1.0, 0.20, 0.20, 0.80)),
                    width: 2.0,
                    ..canvas::Stroke::default()
                });
            }
        }

        // Puls-Ring (deterministischer Tick, kein Zufall)
        let pulse_phase = (self.tick as f32 * 0.04).sin() * 0.5 + 0.5;
        frame.stroke(
            &canvas::Path::circle(Point::new(cx, cy), max_r * (0.92 + pulse_phase * 0.08)),
            canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.35, 0.65, 1.0, 0.04 + pulse_phase * 0.04)),
                width: 0.7,
                ..canvas::Stroke::default()
            },
        );

        // Labels aussen
        for i in 0..n {
            let p = axis_pt(i, max_r * 1.24);
            let is_contra = self.contradiction_axes.contains(&i);
            frame.fill_text(canvas::Text {
                content: labels[i].to_owned(),
                position: p,
                color: if is_contra {
                    Color::from_rgba(1.0, 0.40, 0.40, 1.0)
                } else {
                    Color::from_rgba(axis_colors[i].r, axis_colors[i].g, axis_colors[i].b, 0.85)
                },
                size: iced::Pixels(9.0),
                horizontal_alignment: iced::alignment::Horizontal::Center,
                vertical_alignment: iced::alignment::Vertical::Center,
                ..canvas::Text::default()
            });
        }

        // Legende unten
        let legend_y = bounds.height - 14.0;
        frame.fill_text(canvas::Text {
            content: format!("\u{25cf} {}", self.label_a),
            position: Point::new(8.0, legend_y),
            color: Color::from_rgba(0.55, 0.82, 1.00, 0.85),
            size: iced::Pixels(9.5),
            horizontal_alignment: iced::alignment::Horizontal::Left,
            vertical_alignment: iced::alignment::Vertical::Center,
            ..canvas::Text::default()
        });
        if self.values_b.is_some() {
            frame.fill_text(canvas::Text {
                content: format!("\u{25cc} {}", self.label_b),
                position: Point::new(8.0, legend_y - 13.0),
                color: Color::from_rgba(1.0, 0.65, 0.20, 0.85),
                size: iced::Pixels(9.5),
                horizontal_alignment: iced::alignment::Horizontal::Left,
                vertical_alignment: iced::alignment::Vertical::Center,
                ..canvas::Text::default()
            });
            if !self.contradiction_axes.is_empty() {
                let contra_names: Vec<&str> = self.contradiction_axes.iter()
                    .map(|&i| labels[i])
                    .collect();
                frame.fill_text(canvas::Text {
                    content: format!("\u{26a0} Widerspruch: {}", contra_names.join(", ")),
                    position: Point::new(bounds.width * 0.5, legend_y),
                    color: contradiction_color,
                    size: iced::Pixels(9.0),
                    horizontal_alignment: iced::alignment::Horizontal::Center,
                    vertical_alignment: iced::alignment::Vertical::Center,
                    ..canvas::Text::default()
                });
            }
        }

        vec![frame.into_geometry()]
    }
}

// ── DotScene (status indicator dot) ─────────────────────────────────────────

// ── XOR Bytestream Compare Strip (Leistenmodus) ──────────────────────────
struct BytestreamBarScene {
    hist: Vec<f32>,    // 64-bucket original byte frequency
    delta: Vec<f32>,   // 64-bucket |orig−aef| XOR divergence
    has_data: bool,
}

impl canvas::Program<Message> for BytestreamBarScene {
    type State = ();
    fn draw(
        &self,
        _s: &(),
        renderer: &iced::Renderer,
        _t: &Theme,
        bounds: Rectangle,
        _c: mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        // Background
        frame.fill_rectangle(
            Point::new(0.0, 0.0),
            bounds.size(),
            Color::from_rgb8(0x08, 0x0C, 0x14),
        );
        if !self.has_data || self.hist.is_empty() {
            // Placeholder message when no file has been analyzed yet
            let label = canvas::Text {
                content: "  XOR / Bytestream-Vergleich · Datei droppen zum Starten".to_owned(),
                position: Point::new(8.0, bounds.height * 0.35),
                color: Color::from_rgba(0.35, 0.65, 0.70, 0.60),
                size: iced::Pixels(10.5),
                ..canvas::Text::default()
            };
            frame.fill_text(label);
            return vec![frame.into_geometry()];
        }
        let n = self.hist.len() as f32;
        let cell_w = (bounds.width / n).max(1.0);
        let h = bounds.height;
        let max_orig = self.hist.iter().cloned().fold(0.0f32, f32::max).max(0.0001);
        let max_delta = self.delta.iter().cloned().fold(0.0f32, f32::max).max(0.0001);
        for (i, (&orig, &diff)) in self.hist.iter().zip(self.delta.iter()).enumerate() {
            let x = i as f32 * cell_w;
            // Cyan bar = original byte frequency
            let norm_orig = orig / max_orig;
            let bar_h = (norm_orig * h).clamp(1.0, h);
            let alpha_orig = 0.15 + 0.75 * norm_orig;
            frame.fill_rectangle(
                Point::new(x, h - bar_h),
                Size::new((cell_w - 0.8).max(0.5), bar_h),
                Color::from_rgba(0.10, 0.82, 0.78, alpha_orig),
            );
            // Orange/red overlay = XOR divergence (how much the AEF delta differs)
            if diff > 0.002 {
                let norm_d = (diff / max_delta).min(1.0);
                let d_h = (norm_d * h * 0.8).clamp(1.0, h);
                let alpha_d = 0.25 + 0.65 * norm_d;
                frame.fill_rectangle(
                    Point::new(x, h - d_h),
                    Size::new((cell_w - 0.8).max(0.5), d_h),
                    Color::from_rgba(1.0, 0.50, 0.08, alpha_d),
                );
            }
        }
        // Top label
        let label = canvas::Text {
            content: "  Byte-Hist ■ | XOR-Delta ■".to_owned(),
            position: Point::new(4.0, 1.0),
            color: Color::from_rgba(0.55, 0.75, 0.75, 0.75),
            size: iced::Pixels(9.0),
            ..canvas::Text::default()
        };
        frame.fill_text(label);
        vec![frame.into_geometry()]
    }
}

struct DonutScene {
    values: [f32; 4],
    colors: [Color; 4],
    pulse: f32,
}

impl canvas::Program<Message> for DonutScene {
    type State = ();
    fn draw(&self, _s: &(), renderer: &iced::Renderer, _t: &Theme, bounds: Rectangle, _c: mouse::Cursor) -> Vec<canvas::Geometry<iced::Renderer>> {
        use std::f32::consts::TAU;
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let cxy = Point::new(bounds.width * 0.5, bounds.height * 0.5);
        let r = bounds.width.min(bounds.height) * 0.34;
        let mut cursor = -TAU * 0.25;
        for i in 0..4 {
            let seg = self.values[i].max(0.0);
            if seg <= 0.0001 {
                continue;
            }
            let next = cursor + seg * TAU;
            let arc = canvas::Path::new(|b| {
                b.arc(canvas::path::Arc {
                    center: cxy,
                    radius: r,
                    start_angle: iced::Radians(cursor),
                    end_angle: iced::Radians(next),
                });
            });
            frame.stroke(&arc, canvas::Stroke {
                style: canvas::Style::Solid(self.colors[i]),
                width: 16.0 * self.pulse,
                ..canvas::Stroke::default()
            });
            cursor = next;
        }
        vec![frame.into_geometry()]
    }
}

// ── Helper functions for new dashboard ───────────────────────────────────────

fn info_icon_button(key: &str) -> Element<'static, Message> {
    button(text("i").size(11).color(c(TEXT_H())))
        .on_press(Message::DashboardInfoToggle(key.to_owned()))
        .padding([2, 8])
        .style(|_: &Theme, _| button::Style {
            background: Some(Background::Color(Color::from_rgba(0.10, 0.16, 0.20, 0.96))),
            border: Border { color: c(BORDER()), width: 1.0, radius: 9.0.into() },
            ..Default::default()
        })
        .into()
}

fn cyber_kpi_card(label: &str, value: String, sub: &str, accent: Color, info_key: &str) -> Element<'static, Message> {
    container(
        Column::new()
            .push(
                Row::new()
                    .push(text("\u{25cf}").size(12).color(accent))
                    .push(text(label.to_owned()).size(11).color(c(TEXT_M())))
                    .push(iced::widget::Space::new(Length::Fill, Length::Shrink))
                    .push(info_icon_button(info_key))
                    .align_y(Alignment::Center)
            )
            .push(text(value).size(30).color(c(TEXT_H())))
            .push(text(sub.to_owned()).size(11).color(c(TEXT_D())))
            .spacing(6)
    )
    .style(accent_card_style)
    .padding(12)
    .width(Length::Fill)
    .into()
}

fn dashboard_info_text(key: &str) -> &'static str {
    match key {
        "noether_score" => "Noether Score misst die zeitliche Kohärenz der Strukturanker. Hoeher bedeutet stabilere Invarianz ueber die Pipeline.",
        "risk_score" => "Risk Score ist ein deterministischer Aggregatwert (0..1000) aus Trust-State, Event-Dichte und Dateirisiko-Verteilung.",
        "image_risk" => "Image File Risk misst strukturale Auffaelligkeit in Bildartefakten (Entropie-Gradient, Frequenzbruch, Musterdrift).",
        "video_risk" => "Video File Risk erfasst periodische und fraktale Anomalien in sequenziellen Datenstroemen.",
        "total_threats" => "Total Threats zeigt die aktuelle Anzahl detektierter Aether-Events im aktiven Zeitfenster.",
        "threat_summary" => "Threat Summary visualisiert die deterministische Verlaufskurve ueber den Aether Event Stream.",
        "virus_pie" => "Threats By Virus zeigt die proportionale Verteilung ueber Klassen im aktuellen Event-Fenster.",
        "threat_details" => "Threat Details listet die verifizierten Events mit Device-ID, Signaturklasse, Pfad und Dateityp.",
        "device_list" => "Threat by device zeigt die per-Node Last und den relativen Risikoanteil jeder Instanz.",
        "pane_graph" => "Pane-Graph ersetzt den Seitenbaum: alle Panels sind Knoten im Aether-Graph mit Live-Bindings und festen Transitionen.",
        "performance" => "Performance steuert den deterministischen Laufzeitmodus: AUTO, BALANCED, LOW-POWER oder LEGACY fuer planbare Lastprofile.",
        _ => "Aether erklaert jeden Wert deterministisch: gleicher Input erzeugt dieselbe Metrik und dieselbe Darstellung.",
    }
}

fn view_score_panel(scores: Vec<(String, f32)>) -> Element<'static, Message> {
    let mut col = Column::new().spacing(4);
    for (label, value) in scores {
        col = col.push(
            Row::new()
                .push(text(label).size(11).width(Length::FillPortion(3)))
                .push(text(format!("{:.2}", value)).size(11).width(Length::FillPortion(2)))
                .spacing(8),
        );
    }
    col.into()
}

fn ade_subpanel<'a>(title: &'a str, body: Element<'a, Message>, panel_bg: Color) -> Element<'a, Message> {
    container(
        Column::new()
            .push(text(title.to_owned()).size(12).color(c(ACCENT())))
            .push(body)
            .spacing(8)
            .padding(14),
    )
    .style(move |_: &Theme| container::Style {
        background: Some(Background::Color(panel_bg)),
        border: Border { color: c(BORDER()), width: 1.0, radius: 8.0.into() },
        ..Default::default()
    })
    .width(Length::Fill)
    .into()
}

fn standard_card_style(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(c(BG_CARD()))),      
        border: Border {
            color: c(BORDER()),
            width: 1.0,
            radius: 16.0.into(),
        },
        ..Default::default()
    }
}

fn accent_card_style(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(c(BG_CARD2()))),
        border: Border {
            color: c(BORDER()),
            width: 1.0,
            radius: 16.0.into(),
        },
        ..Default::default()
    }
}

fn selected_item_style(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(0.18, 0.27, 0.31, 0.92))),
        border: Border {
            color: c(BORDER()),
            width: 1.0,
            radius: 12.0.into(),
        },
        ..Default::default()
    }
}

fn primary_button_style(_: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(Background::Color(c(ACCENT()))),
        text_color: Color::from_rgb8(0x0B, 0x12, 0x18),
        border: Border {
            color: c(ACCENT()),
            width: 1.0,
            radius: 12.0.into(),
        },
        ..Default::default()
    }
}

fn secondary_button_style(_: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(Background::Color(c(BG_CARD()))),
        text_color: c(TEXT_H()),
        border: Border {
            color: c(BORDER()),
            width: 1.0,
            radius: 12.0.into(),
        },
        ..Default::default()
    }
}

fn panel_frame_style(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(c(BG_CARD()))),
        border: Border {
            color: c(BORDER()),
            width: 1.0,
            radius: 16.0.into(),
        },
        ..Default::default()
    }
}

fn info_badge(tooltip_text: &'static str) -> Element<'static, Message> {
    let _ = tooltip_text; // stored for future tooltip implementation
    container(
        text("\u{2139}").size(9).color(Color::from_rgb8(0x4E, 0x4A, 0x76))
    )
    .style(|_: &Theme| container::Style {
        background: Some(Background::Color(Color::from_rgb8(0x16, 0x15, 0x24))),
        border: Border { color: Color::from_rgb8(0x22, 0x20, 0x36), width: 1.0, radius: 8.0.into() },
        ..Default::default()
    })
    .padding([1, 5])
    .into()
}

fn metric_help_text(metric: &str) -> &'static str {
    match metric {
        "ENTROPY" => get_score_tooltip("SHANNON"),
        "H_LAMBDA" => get_score_tooltip("H_LAMBDA"),
        "SYMMETRY" => get_score_tooltip("SYMMETRY"),
        "PERIODICITY" => get_score_tooltip("PERIODICITY"),
        "SCE" => get_score_tooltip("SCE"),
        "BAYES" => get_score_tooltip("BAYES"),
        "TRUST" => get_score_tooltip("TRUST"),
        "ZIPF" => "Zipf zeigt, ob Haeufigkeiten einem natuerlichen Rangmuster folgen. Hilfreich, um Sprache, Ereignisverteilungen und organische Wiederholungen von kuenstlichen Mustern zu trennen.",
        "BENFORD" => "Benford prueft, ob fuehrende Ziffern natuerlich verteilt sind. Auffaellige Abweichungen koennen auf kuenstliche Erzeugung, Manipulation oder unnatuerliche Auswahl hindeuten.",
        "KATZ" => "Katz FD beschreibt, wie verschlungen oder verzweigt ein Verlauf ist. Hoehere Werte bedeuten meist mehr Richtungswechsel und komplexere Pfade im Signal.",
        "NOETHER" => "Noether Consistency zeigt, wie stark Grundmuster ueber Veraenderungen hinweg erhalten bleiben. Hohe Werte sprechen fuer stabile Erhaltungsstrukturen statt Bruechen.",
        "DELTA" => "Delta Ratio misst, wie stark sich das aktuelle Signal gegen den letzten Zustand veraendert hat. Niedrigeres Delta heisst mehr Kontinuitaet, hoeheres Delta mehr Drift oder Bruch.",
        "COHERENCE" => "Coherence fasst zusammen, wie gut die innere Struktur zusammenhaelt. Sie steigt, wenn Muster, Knoten und Wiederholungen sauber zueinander passen.",
        "COMPRESSION" => "Kompression zeigt den verlustfreien Verdichtungsgewinn gegen das Original. Sichtbarer Gewinn bedeutet, dass Wiederholung oder Struktur vorhanden ist, die effizient beschrieben werden kann.",
        _ => "Keine Erklaerung hinterlegt.",
    }
}

fn metric_help_chip(label: &'static str, metric: &'static str, accent: Color) -> Element<'static, Message> {
    button(text(label).size(11).color(Color::from_rgb8(0xE4, 0xEE, 0xF2)))
        .on_press(Message::ShowTooltip(metric_help_text(metric).to_owned()))
        .padding([6, 10])
        .style(move |_: &Theme, _| button::Style {
            background: Some(Background::Color(Color::from_rgba(accent.r * 0.18, accent.g * 0.18, accent.b * 0.18, 0.95))),
            border: Border { color: accent, width: 1.0, radius: 9.0.into() },
            text_color: Color::from_rgb8(0xE4, 0xEE, 0xF2),
            ..Default::default()
        })
        .into()
}

fn info_card<'a>(title: &str, body: &str) -> Element<'a, Message> {
    container(
        Column::new()
            .push(text(title.to_owned()).size(16))
            .push(text(body.to_owned()).size(14))
            .spacing(6)
            .width(Length::Fill),
    )
    .style(standard_card_style)
    .padding(16)
    .width(Length::Fill)
    .into()
}

fn analysis_card<'a>(
    progress: f32,
    status: &str,
    hint: &str,
    detail: &str,
) -> Element<'a, Message> {
    container(
        Column::new()
            .push(text("▶ ANALYSEFLUSS").size(16))
            .push(progress_bar(0.0..=1.0, progress.clamp(0.0, 1.0)))
            .push(text(make_sparkline(progress)).size(13))
            .push(text(status.to_owned()).size(15))
            .push(text(hint.to_owned()).size(13))
            .push(text(detail.to_owned()).size(13))
            .spacing(8)
            .width(Length::Fill),
    )
    .style(|_theme: &Theme| container::Style {
        background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
        border: Border {
            color: Color::from_rgb8(0x70, 0x40, 0xCC),
            width: 1.5,
            radius: 8.0.into(),
        },
        ..Default::default()
    })
    .padding(18)
    .width(Length::Fill)
    .into()
}

fn world_metric_card<'a>(title: &str, value: f32, detail: &str, accent: Color) -> Element<'a, Message> {
    container(
        Column::new()
            .push(
                Row::new()
                    .push(text(title.to_owned()).size(14).color(c(TEXT_H())))
                    .push(iced::widget::Space::new(Length::Fill, Length::Shrink))
                    .push(text(format!("{:.0}%", value.clamp(0.0, 1.0) * 100.0)).size(18).color(accent))
            )
            .push(progress_bar(0.0..=1.0, value.clamp(0.0, 1.0)))
            .push(text(detail.to_owned()).size(11).color(c(TEXT_M())))
            .spacing(8)
            .width(Length::Fill),
    )
    .style(panel_frame_style)
    .padding(14)
    .width(Length::Fill)
    .into()
}

fn gaming_progress_table<'a>(rows: &[GamingProgressRow]) -> Element<'a, Message> {
    let mut list = Column::new()
        .spacing(8)
        .push(text("Gaming Progress Ledger").size(16).color(c(TEXT_H())))
        .push(
            text("Wie bei den anderen Invarianten gilt auch hier: Push/Freigabe erst ab Quorum (mindestens 3 verschiedene Spieler pro Titel).")
                .size(12)
                .color(c(TEXT_M())),
        );

    let header = Row::new()
        .spacing(10)
        .push(text("Game").size(11).color(c(TEXT_D())).width(Length::FillPortion(3)))
        .push(text("Found").size(11).color(c(TEXT_D())).width(Length::FillPortion(1)))
        .push(text("Improve").size(11).color(c(TEXT_D())).width(Length::FillPortion(1)))
        .push(text("Players").size(11).color(c(TEXT_D())).width(Length::FillPortion(1)))
        .push(text("Quorum").size(11).color(c(TEXT_D())).width(Length::FillPortion(1)));
    list = list.push(container(header).padding([4, 6]).style(panel_frame_style));

    if rows.is_empty() {
        list = list.push(info_card(
            "Noch keine Spiele erfasst",
            "Droppe einen Spielpfad im Gaming-Tab, damit Fortschritt, Spielerzahl und Quorum-Status aufgebaut werden.",
        ));
    } else {
        for row_data in rows.iter().take(10) {
            let quorum_label = if row_data.quorum_ready {
                format!("bereit ({})", row_data.players.len())
            } else {
                format!("{}/3", row_data.players.len())
            };
            let insight = if row_data.quorum_ready {
                row_data.last_shared_insight.clone()
            } else {
                format!(
                    "Quorum-Gate aktiv: Shared Insights werden bei mindestens 3 Spielern freigeschaltet (aktuell {}).",
                    row_data.players.len()
                )
            };
            let row_line = Row::new()
                .spacing(10)
                .push(text(row_data.game_label.clone()).size(12).color(c(TEXT_H())).width(Length::FillPortion(3)))
                .push(text(format!("{:.1}%", row_data.found_percent)).size(12).color(c(TEXT_M())).width(Length::FillPortion(1)))
                .push(text(format!("{:.1}%", row_data.improved_percent)).size(12).color(c(TEXT_M())).width(Length::FillPortion(1)))
                .push(text(format!("{}", row_data.players.len())).size(12).color(c(TEXT_M())).width(Length::FillPortion(1)))
                .push(text(quorum_label).size(12).color(c(TEXT_M())).width(Length::FillPortion(1)));

            list = list.push(
                container(
                    Column::new()
                        .spacing(4)
                        .push(row_line)
                        .push(text(insight).size(11).color(c(TEXT_D())))
                        .push(text(format!("Sessions {} | Update {}", row_data.session_count, row_data.last_updated)).size(10).color(c(TEXT_D()))),
                )
                .padding(10)
                .style(panel_frame_style),
            );
        }
    }

    container(list).padding(12).style(panel_frame_style).into()
}

fn launch_dropped_artifact(path: &Path, world: Tab) -> Result<String, String> {
    let path_str = path
        .to_str()
        .ok_or_else(|| "Pfad ist nicht UTF-8-kompatibel".to_owned())?;

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", path_str])
            .spawn()
            .map_err(|err| format!("Windows-Start fehlgeschlagen: {err}"))?;
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path_str)
            .spawn()
            .map_err(|err| format!("open fehlgeschlagen: {err}"))?;
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(path_str)
            .spawn()
            .map_err(|err| format!("xdg-open fehlgeschlagen: {err}"))?;
    }

    Ok(match world {
        Tab::Gaming => "Spielpfad gestartet; Rendering- und Strukturbeobachtung laufen parallel.".to_owned(),
        Tab::Media => "Medienpfad gestartet; Rendering-, Struktur- und Kompressionsbeobachtung laufen parallel.".to_owned(),
        _ => "Artefakt gestartet.".to_owned(),
    })
}

fn register_card(entry: RegisterEntry) -> Element<'static, Message> {
    let gain_fill = entry.compression_gain_percent / 100.0;
    let preview_upper = entry.preview_note.to_ascii_uppercase();
    let suspicious = preview_upper.contains("EICAR")
        || preview_upper.contains("OBF")
        || preview_upper.contains("MALWARE")
        || preview_upper.contains("BLOCK")
        || preview_upper.contains("DENY")
        || preview_upper.contains("QUARANTINE")
        || preview_upper.contains("CRITICAL");
    container(
        Column::new()
            .push(text(format!("▤ {} | {}", entry.id, entry.file_name)).size(16))
            .push(text(format!(
                "{} | {} B orig | {} B delta | {:.2}% Gain",
                entry.source_kind,
                entry.original_size,
                entry.delta_size,
                entry.compression_gain_percent
            ))
            .size(13))
            .push(text(make_sparkline(gain_fill)).size(12))
            .push(text(entry.anchor_summary.clone()).size(13))
            .push(text(entry.preview_note.clone())
                .size(13)
                .color(if suspicious {
                    Color::from_rgb8(0xFF, 0xAE, 0x42)
                } else {
                    c(TEXT_M())
                }))
            .push(text(entry.plain_note.clone())
                .size(14)
                .color(if suspicious {
                    Color::from_rgb8(0xFF, 0xD0, 0x80)
                } else {
                    Color::from_rgb8(0xC8, 0xE6, 0xC9)
                }))
            .spacing(5),
    )
    .style(move |_: &Theme| {
        if suspicious {
            container::Style {
                background: Some(Background::Color(Color::from_rgba(0.42, 0.18, 0.02, 0.36))),
                border: Border {
                    color: Color::from_rgb8(0xFF, 0xAE, 0x42),
                    width: 1.4,
                    radius: 10.0.into(),
                },
                ..Default::default()
            }
        } else {
            selected_item_style(&Theme::Dark)
        }
    })
    .padding(14)
    .width(Length::Fill)
    .into()
}

fn fallback_capsule_state(
    source_label: &str,
    source_type: &str,
    domain_hint: &str,
    size_bytes: u64,
    entropy: f32,
    symmetry: f32,
    drift: f32,
    anomaly_flags: Vec<String>,
) -> CapsuleViewState {
    CapsuleViewState {
        source_label: source_label.to_owned(),
        source_type: source_type.to_owned(),
        trigger: "fallback".to_owned(),
        domain_hint: domain_hint.to_owned(),
        source_hash: String::new(),
        source_scope: "explicit_file_drop".to_owned(),
        privacy_class: "explicit_user_signal".to_owned(),
        artifact_class: "private_signal".to_owned(),
        segment_count: 1,
        segment_manifest_hash: String::new(),
        size_bytes,
        entropy,
        h_lambda: (entropy * drift * (1.0 - symmetry + 0.1)).clamp(0.0, 8.0),
        symmetry,
        periodicity: 0.0,
        zipf_alpha: 0.0,
        benford_score: 0.0,
        katz_dimension: 1.0,
        perm_entropy: 0.0,
        sce_score: symmetry.clamp(0.0, 1.0),
        bayes_confidence: symmetry.clamp(0.0, 1.0),
        trust_score: (0.65 * symmetry + 0.35 * (1.0 - drift).clamp(0.0, 1.0)).clamp(0.0, 1.0),
        noether_consistency: (1.0 - drift).clamp(0.0, 1.0),
        delta_ratio: drift.clamp(0.0, 1.0),
        changed_bytes: size_bytes,
        anomaly_flags,
        kolmogorov_k: 0.0,
        anchor_coverage_ratio: 0.0,
    }
}

fn fallback_structure_map_state(symmetry: f32) -> StructureMapViewState {
    StructureMapViewState {
        region_label: "REGION LOCAL".to_owned(),
        node_count: 4,
        edge_count: 0,
        anchor_count: 0,
        anomaly_count: 1,
        locked: false,
        trust_score: symmetry.clamp(0.0, 1.0),
        coherence_score: symmetry.clamp(0.0, 1.0),
    }
}

fn structure_map_state_from_result(result: &serde_json::Value) -> StructureMapViewState {
    let structure_map = result.get("structure_map").cloned().unwrap_or(serde_json::Value::Null);
    StructureMapViewState::from_json(&structure_map)
}

fn pipeline_python_executable() -> String {
    let settings = load_hybrid_settings();
    let configured = settings.python_path.trim();
    if configured.is_empty() {
        "python".to_owned()
    } else {
        configured.to_owned()
    }
}

fn pipeline_project_root() -> std::path::PathBuf {
    // Walk up from the current executable to find the directory containing aether_pipeline.py.
    if let Ok(exe) = std::env::current_exe() {
        let mut candidate = exe.parent().map(|p| p.to_path_buf());
        while let Some(dir) = candidate {
            if dir.join("aether_pipeline.py").exists() {
                return dir;
            }
            candidate = dir.parent().map(|p| p.to_path_buf());
        }
    }
    // Fallback: current working directory
    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
}

fn current_epoch_label() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

fn run_pipeline_json(script: &str, args: &[String], context: &str) -> Result<serde_json::Value, String> {
    use std::process::Command;

    let python = pipeline_python_executable();
    let root = pipeline_project_root();
    // Prepend a sys.path injection so the import always resolves even when the
    // OS-level PYTHONPATH variable is not forwarded by the shell (Windows edge case).
    let prefixed = format!(
        "import os,sys;sys.path.insert(0,os.getcwd());sys.path.insert(0,r'{}');{script}",
        root.to_string_lossy().replace('\\', "\\\\")
    );
    let mut command = Command::new(python);
    command
        .current_dir(&root)
        .env("PYTHONPATH", root.to_string_lossy().as_ref())
        .env("AETHER_PIPELINE_TRIGGER", "rust_shell")
        .env("AETHER_PIPELINE_MODE", "deterministic")
        .env("PYTHONHASHSEED", "0")
        .arg("-c")
        .arg(&prefixed);
    for arg in args {
        command.arg(arg);
    }

    let output = command
        .output()
        .map_err(|err| format!("Python konnte nicht gestartet werden: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(format!("{} Python-Pipeline fehlgeschlagen: {}", context, stderr));
    }

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    serde_json::from_str::<serde_json::Value>(&raw)
        .map_err(|err| format!("{} JSON konnte nicht gelesen werden: {err}", context))
}

async fn analyze_file_for_register(
    path: PathBuf,
    username: String,
    _data_key: Option<DataKey>,
) -> Result<FileAnalysisResult, String> {
    use std::f32::consts::TAU;

    let bytes = fs::read(&path).map_err(|err| format!("Datei konnte nicht gelesen werden: {err}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|err| format!("Metadaten konnten nicht gelesen werden: {err}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unbekannt")
        .to_owned();
    let source_kind = detect_source_kind(&path, &bytes);

    let script = "import json,sys; from pathlib import Path; from aether_pipeline import AetherPipeline; print(json.dumps(AetherPipeline().process(Path(sys.argv[1])), ensure_ascii=True))";
    let parsed = run_pipeline_json(
        script,
        &[path.to_string_lossy().to_string()],
        "Pipeline",
    );

    let result = match parsed {
        Ok(payload) => payload,
        Err(pipeline_error) => {
            let entropy = shannon_entropy_local(&bytes);
            let symmetry = symmetry_from_histogram(&histogram64(&bytes));
            let drift = byte_drift_local(&bytes);
            let delta_size = metadata.len();
            let capsule_state = fallback_capsule_state(
                &path.to_string_lossy(),
                "file",
                &detect_file_type_from_name(&file_name),
                metadata.len(),
                entropy,
                symmetry,
                drift,
                vec!["pipeline_fallback".to_owned()],
            );
            let structure_map_state = fallback_structure_map_state(symmetry);
            let preview_note = format!(
                "{} | Entropie {:.2} bit | Symmetrie {:.1}% | Drift {:.2} | Fallback aktiv",
                source_kind,
                entropy,
                symmetry * 100.0,
                drift,
            );
            let anchor_summary = format!(
                "Fallback | Noether {:.1}% | Drift {:.2}",
                symmetry * 100.0,
                drift,
            );
            let process_summary = format!(
                "Quelle: {}\nScope: explicit_file_drop | Privacy: explicit_user_signal | Artefakt: private_signal | Segmente: 1\nFallback-Analyse lokal aktiv\n{}",
                source_kind,
                pipeline_error,
            );
            return Ok(FileAnalysisResult {
                entry: RegisterEntry {
                    id: 0,
                    owner_username: username,
                    file_name: file_name.clone(),
                    full_path: path.to_string_lossy().to_string(),
                    source_kind: source_kind.clone(),
                    original_size: metadata.len(),
                    delta_size,
                    compression_gain_percent: 0.0,
                    anchor_summary: anchor_summary.clone(),
                    process_summary: process_summary.clone(),
                    preview_note: preview_note.clone(),
                    plain_note: preview_note.clone(),
                },
                snapshot: AnalysisSnapshot {
                    file_name,
                    original_size: metadata.len(),
                    compression_gain_percent: 0.0,
                    anchor_summary,
                    process_summary,
                    preview_note,
                },
                byte_hist: histogram64(&bytes),
                xor_delta: histogram64(pipeline_error.as_bytes()),
                capsule_state,
                structure_map_state,
                aelab_state: None,
                compression_state: None,
                reconstruction_state: None,
                structure_map_nodes: vec![vec![0.0, TAU / 4.0, TAU / 2.0, 3.0 * TAU / 4.0]],
                source_date_secs: None,  // Fallback-Analyse: kein source_date verfügbar
            });
        }
    };

    let capsule_state = CapsuleViewState::from_pipeline_result(&result);
    let structure_map_state = structure_map_state_from_result(&result);
    let aelab_state = AelabViewState::from_result(&result);
    let compression_state = CompressionViewState::from_result(&result);
    let reconstruction_state = ReconstructionAuditViewState::from_result(&result);

    let anchors = result
        .get("anchors")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let anomaly_flags = result
        .get("anomaly_flags")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let delta_size = result
        .get("capsule")
        .and_then(|value| value.get("local_delta"))
        .and_then(|value| value.get("changed_bytes"))
        .and_then(|value| value.as_u64())
        .unwrap_or(capsule_state.changed_bytes.max(metadata.len()));
    let compression_gain_percent = if metadata.len() == 0 {
        0.0
    } else {
        ((1.0 - (delta_size as f32 / metadata.len() as f32)).clamp(0.0, 1.0) * 10000.0).round() / 100.0
    };
    let preview_note = format!(
        "{} | Entropie {:.2} bit | Symmetrie {:.1}% | Trust {:.1}% | H_lambda {:.2}",
        source_kind,
        capsule_state.entropy,
        capsule_state.symmetry * 100.0,
        capsule_state.trust_score * 100.0,
        capsule_state.h_lambda,
    );
    let anchor_summary = format!(
        "{} Anchors | {} Flags | SCE {:.1}%",
        anchors.len(),
        anomaly_flags.len(),
        capsule_state.sce_score * 100.0,
    );
    let process_summary = format!(
        "Quelle: {}\nScope: {} | Privacy: {} | Artefakt: {} | Segmente: {}\nVerdichtung: {:.2}% Gewinn\nSCE: {:.1}% | Trust {:.1}% | H_lambda {:.2}",
        source_kind,
        capsule_state.source_scope,
        capsule_state.privacy_class,
        capsule_state.artifact_class,
        capsule_state.segment_count,
        compression_gain_percent,
        capsule_state.sce_score * 100.0,
        capsule_state.trust_score * 100.0,
        capsule_state.h_lambda,
    );

    let structure_map = result.get("structure_map").cloned().unwrap_or(serde_json::Value::Null);
    let structure_map_nodes = structure_map_rings(&structure_map);
    Ok(FileAnalysisResult {
        entry: RegisterEntry {
            id: 0,
            owner_username: username,
            file_name: file_name.clone(),
            full_path: path.to_string_lossy().to_string(),
            source_kind: source_kind.clone(),
            original_size: metadata.len(),
            delta_size,
            compression_gain_percent,
            anchor_summary: anchor_summary.clone(),
            process_summary: process_summary.clone(),
            preview_note: preview_note.clone(),
            plain_note: preview_note.clone(),
        },
        snapshot: AnalysisSnapshot {
            file_name,
            original_size: metadata.len(),
            compression_gain_percent,
            anchor_summary,
            process_summary,
            preview_note,
        },
        byte_hist: histogram64(&bytes),
        xor_delta: histogram64(
            result
                .get("xor_delta")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .as_bytes(),
        ),
        capsule_state,
        structure_map_state,
        aelab_state,
        compression_state,
        reconstruction_state,
        structure_map_nodes,
        // source_date aus Pipeline-JSON: nur gesetzt wenn temporal_metadata_consent=true
        source_date_secs: result
            .get("source_date")
            .and_then(|v| v.as_f64())
            .map(|f| f as u64),
    })
}

async fn analyze_live_signal_for_shell(
    raw: Vec<u8>,
    previous_signal: Vec<u8>,
    tick: u64,
) -> Result<LiveRenderAnalysisResult, String> {
    let raw_b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_slice());
    let previous_b64 = if previous_signal.is_empty() {
        String::new()
    } else {
        base64::engine::general_purpose::STANDARD.encode(previous_signal.as_slice())
    };
    let source_label = format!("live_render:{tick}");
    let script = "import base64,json,sys; from aether_pipeline import AetherPipeline; raw=base64.b64decode(sys.argv[1]); prev=base64.b64decode(sys.argv[2]) if sys.argv[2] else None; print(json.dumps(AetherPipeline().process_live_signal(raw, source_label=sys.argv[3], previous_signal=prev), ensure_ascii=True))";
    let result = run_pipeline_json(
        script,
        &[raw_b64, previous_b64, source_label],
        "Live-Render",
    )?;

    let structure_map = result.get("structure_map").cloned().unwrap_or(serde_json::Value::Null);
    Ok(LiveRenderAnalysisResult {
        capsule_state: CapsuleViewState::from_pipeline_result(&result),
        structure_map_state: structure_map_state_from_result(&result),
        aelab_state: AelabViewState::from_result(&result),
        compression_state: CompressionViewState::from_result(&result),
        reconstruction_state: ReconstructionAuditViewState::from_result(&result),
        structure_map_nodes: structure_map_rings(&structure_map),
    })
}

fn value_as_f32(value: Option<&serde_json::Value>) -> f32 {
    value
        .and_then(|item| item.as_f64())
        .map(|item| item as f32)
        .unwrap_or(0.0)
}

fn histogram64(bytes: &[u8]) -> Vec<f32> {
    if bytes.is_empty() {
        return vec![0.0; 64];
    }
    let mut buckets = vec![0.0f32; 64];
    for byte in bytes {
        let idx = ((*byte as usize) * 64) / 256;
        buckets[idx] += 1.0;
    }
    let total = bytes.len() as f32;
    for value in &mut buckets {
        *value /= total;
    }
    buckets
}

fn symmetry_from_histogram(hist: &[f32]) -> f32 {
    if hist.is_empty() {
        return 1.0;
    }
    let mean = hist.iter().copied().sum::<f32>() / hist.len() as f32;
    if mean <= 1e-9 {
        return 1.0;
    }
    let deviation = hist.iter().map(|value| (*value - mean).abs()).sum::<f32>() / hist.len() as f32;
    (1.0 - (deviation / mean)).clamp(0.0, 1.0)
}

fn shannon_entropy_local(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = bytes.len() as f32;
    counts
        .iter()
        .map(|count| {
            let probability = *count as f32 / total;
            -(probability * probability.log2())
        })
        .sum()
}

/// Liest bis zu 4096 Bytes vom Dateianfang und liefert eine Shannon-Entropie-Schätzung (0–8 bit/byte).
/// Dient der Schnellvorschau im Drop-Annotation-Modal — keine vollständige Analyse.
fn quick_file_entropy(path: &std::path::Path) -> f32 {
    use std::io::Read;
    let mut buf = [0u8; 4096];
    let read_len = match std::fs::File::open(path) {
        Ok(mut f) => f.read(&mut buf).unwrap_or(0),
        Err(_) => return 0.0,
    };
    shannon_entropy_local(&buf[..read_len])
}

fn parse_visual_source_date_input(raw: &str) -> Result<Option<u64>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    for format in ["%Y-%m-%d", "%d.%m.%Y", "%d-%m-%Y", "%Y/%m/%d", "%d/%m/%Y"] {
        if let Ok(date) = chrono::NaiveDate::parse_from_str(trimmed, format) {
            let Some(naive_dt) = date.and_hms_opt(12, 0, 0) else {
                return Err("Quelldatum konnte nicht in einen Kalenderzeitpunkt umgerechnet werden.".to_owned());
            };
            let ts = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                naive_dt,
                chrono::Utc,
            )
            .timestamp();
            if ts > 0 {
                return Ok(Some(ts as u64));
            }
        }
    }

    Err("Datum bitte als YYYY-MM-DD oder DD.MM.YYYY eingeben. Es wirkt nur auf die Grafik, nicht auf die Analyse.".to_owned())
}

fn format_unix_date(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .map(|value| value.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unbekannt".to_owned())
}

/// Pr\u{fc}ft, ob bekannte Windows-Telemetrieprozesse gerade aktive TCP-Verbindungen nach au\u{df}en aufgebaut haben.
/// Gibt erkannte Verbindungen als `TelemetryAlert`-Liste zur\u{fc}ck.
/// Auf Nicht-Windows-Systemen immer leer.
async fn scan_telemetry_activity(_apply_block: bool) -> Vec<TelemetryAlert> {
    #[cfg(not(target_os = "windows"))]
    return Vec::new();

    #[cfg(target_os = "windows")]
    {
        const PS_SCRIPT: &str = concat!(
            "$t=@('CompatTelRunner','DiagTrack','WerFault','wsqmcons','DeviceCensus',",
            "'MicrosoftEdgeUpdate','GoogleUpdate','AdobeARM');",
            "Get-NetTCPConnection -State Established -EA SilentlyContinue|",
            "Where-Object{$_.OwningProcess -gt 4}|ForEach-Object{",
            "try{$n=(Get-Process -Id $_.OwningProcess -EA Stop).Name;",
            "if($t -contains $n){\"$n`t$($_.RemoteAddress):$($_.RemotePort)\"}}catch{}}"
        );
        let Ok(out) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT])
            .output()
        else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let ts = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let s = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("{:02}:{:02}:{:02}", (s % 86400) / 3600, (s % 3600) / 60, s % 60)
        };
        let mut seen = std::collections::HashSet::new();
        text.lines()
            .filter_map(|line| {
                let mut parts = line.splitn(2, '\t');
                let process = parts.next()?.trim().to_owned();
                let remote  = parts.next().unwrap_or("?").trim().to_owned();
                if process.is_empty() { return None; }
                if seen.insert((process.clone(), remote.clone())) {
                    Some(TelemetryAlert { timestamp: ts.clone(), remote, process })
                } else {
                    None
                }
            })
            .collect()
    }
}

/// F\u{fc}gt Windows-Firewall-Ausgangsregeln f\u{fc}r bekannte Telemetrie-Executables hinzu oder entfernt sie.
/// Erfordert Administratorrechte; Fehler werden ignoriert (best-effort).
fn apply_telemetry_firewall(enable: bool) {
    #[cfg(not(target_os = "windows"))]
    { let _ = enable; }

    #[cfg(target_os = "windows")]
    {
        const RULE: &str = "AetherShield_Telemetry";
        // Bestehende Regel l\u{f6}schen (idempotent)
        let _ = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", &format!("name={RULE}")])
            .output();
        if !enable { return; }
        const PATHS: &[&str] = &[
            "%SystemRoot%\\System32\\CompatTelRunner.exe",
            "%SystemRoot%\\System32\\wsqmcons.exe",
            "%SystemRoot%\\System32\\DeviceCensus.exe",
            "%SystemRoot%\\System32\\WerFault.exe",
            "%SystemRoot%\\System32\\WerFaultSecure.exe",
        ];
        for path in PATHS {
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={RULE}"),
                    "dir=out", "action=block",
                    &format!("program={path}"),
                    "enable=yes",
                ])
                .output();
        }
    }
}

fn byte_drift_local(bytes: &[u8]) -> f32 {
    if bytes.len() < 2 {
        return 0.0;
    }
    let total: u64 = bytes
        .windows(2)
        .map(|window| (window[0] as i32 - window[1] as i32).unsigned_abs() as u64)
        .sum();
    total as f32 / bytes.len().saturating_sub(1) as f32
}

fn structure_map_rings(payload: &serde_json::Value) -> Vec<Vec<f32>> {
    use std::f32::consts::PI;
    const RING_COUNT: usize = 10;
    let mut rings = vec![Vec::new(); RING_COUNT];
    let Some(nodes) = payload.get("nodes").and_then(|value| value.as_array()) else {
        return rings;
    };
    for node in nodes {
        let x = value_as_f32(node.get("x"));
        let y = value_as_f32(node.get("y"));
        let t = value_as_f32(node.get("t")).clamp(0.0, 1.0);
        let ring_idx = ((t * (RING_COUNT.saturating_sub(1) as f32)).round() as usize)
            .min(RING_COUNT.saturating_sub(1));
        let angle = (y - 0.5).atan2(x - 0.5).rem_euclid(2.0 * PI);
        rings[ring_idx].push(angle);
    }
    for ring in &mut rings {
        ring.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    }
    rings
}

fn detect_source_kind(path: &Path, bytes: &[u8]) -> String {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tif" | "tiff" | "webp" => "Bild".to_owned(),
        "txt" | "md" | "json" | "toml" | "yaml" | "yml" | "rs" | "py" | "js" | "html" | "css" => {
            "Text / Code".to_owned()
        }
        "wav" | "mp3" | "flac" | "ogg" => "Audio".to_owned(),
        "mp4" | "mov" | "mkv" | "avi" | "webm" => "Video".to_owned(),
        _ if bytes.starts_with(b"%PDF") => "PDF".to_owned(),
        _ => "Binaer".to_owned(),
    }
}

fn detect_file_type_from_name(file_name: &str) -> String {
    let extension = Path::new(file_name)
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tif" | "tiff" | "webp" => "image".to_owned(),
        "txt" | "md" | "json" | "toml" | "yaml" | "yml" | "rs" | "py" | "js" | "html" | "css" => {
            "text".to_owned()
        }
        "wav" | "mp3" | "flac" | "ogg" => "audio".to_owned(),
        "mp4" | "mov" | "mkv" | "avi" | "webm" => "video".to_owned(),
        "pdf" => "pdf".to_owned(),
        _ => "binary".to_owned(),
    }
}

// END impl AetherIcedShell


