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
use crate::browser_embed::{EmbeddedBrowser, BrowserHostRect};
use crate::browser::{BrowserProbePolicy, BrowserProbeResult, BrowserSearchContext, BrowserInspector};
use crate::launcher_dashboard::{LauncherState, LauncherMode, ServiceStatus, BuildTaskResult};
use crate::py_bridge::{DropperBridge, PythonBridgeManager, load_hybrid_settings, read_hybrid_status};
use crate::aef::{AefDecodeResult, AefDecoder, VaultStore};
use crate::hardware;
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use base64::Engine;
use zeroize::Zeroize;
use std::io::Write;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Home, Control, Symbiont, SwarmOps, Privacy, Chat,
    Browser, YouTube, Data, Anchors, Logs, Settings,
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
            Tab::Browser => "Browser",
            Tab::YouTube => "YouTube",
            Tab::Data => "Data",
            Tab::Anchors => "Anchors",
            Tab::Logs => "Logs",
            Tab::Settings => "Settings",
            Tab::ADE => "ADE",
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
    fn from_capsule_state(capsule: &CapsuleViewState, structure_map: &StructureMapViewState) -> Self {
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
}

#[derive(Debug, Clone)]
struct AnalysisSnapshot {
    file_name: String,
    #[allow(dead_code)]
    original_size: u64,
    compression_gain_percent: f32,
    anchor_summary: String,
    process_summary: String,
    preview_note: String,
}

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
    GroupMessageChanged(String),
    GroupMessageSend,
    BrowserAddressChanged(String),
    BrowserSearchQueryChanged(String),
    BrowserLoadPressed,
    BrowserInspectPressed,
    BrowserSearchPressed,
    BrowserInspectCompleted(BrowserProbeResult),
    BrowserSearchCompleted(BrowserSearchContext),
    YouTubeAddressChanged(String),
    YouTubeLoadPressed,
    YouTubeKiAnalysisPressed,
    FileHovered(PathBuf),
    FileHoverCleared,
    ShowTooltip(String),
    FileDropped(PathBuf),
    FileAnalysisCompleted(Result<FileAnalysisResult, String>),
    LiveRenderAnalysisCompleted(Result<LiveRenderAnalysisResult, String>),
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
    FlowSphereBroadcastReject,
    FlowSphereExplain(String),
    FlowSphereNodeClicked(usize),
    FlowSphereExportPressed,
    OpenFullTab(Tab),
    ToggleMode,
    LiveRenderToggle,
    SymbiontInputChanged(String),
    SymbiontProfilePressed,
    SymbiontRazorPressed,
    SymbiontSnapshotPressed,
    SymbiontStatusPressed,
    SymbiontDecodeDnaPressed,
    SymbiontRpcCompleted(Result<String, String>),
    SymbiontEventsReceived(Result<(Vec<String>, u64), String>),
    SymbiontEventsClearPressed,
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
    group_message_draft: String,
    browser_address: String,
    browser_search_query: String,
    browser_note: String,
    browser_probe: Option<BrowserProbeResult>,
    browser_search_context: Option<BrowserSearchContext>,
    browser_probe_policy: BrowserProbePolicy,
    browser_embed: EmbeddedBrowser,
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
    browser_sync_stride: u64,
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
    // --- YouTube ---
    youtube_address: String,
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
    #[allow(dead_code)]
    backup_enabled: bool, // Wird über die GUI gesetzt (Checkbox)
    swarm_consented: bool, // Swarm-Teilnahme: opt-in/out über UI steuerbar
    /// Pending swarm domain-overlap contact requests, polled from data/interbus/.
    swarm_overlap_requests: Vec<SwarmOverlapRequest>,

    // Cascade result state
    #[allow(dead_code)]
    dropper_bridge: DropperBridge,
    cascade_run_id: Option<String>,
    cascade_metrics: Option<CascadeMetrics>,
    /// Emergent OS capability score 0.0–1.0, filled by capability_score.py.
    backend_capability_score: f32,
    /// Human-readable stage label for the capability score.
    backend_capability_stage: String,
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
        let dropper_bridge = DropperBridge::new();
        let auth_store = AuthStore::load_default();
        let known_user_count = auth_store.user_count();
        let state_store = StateStore::load_default();
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
                dropper_bridge,
                login_username: String::new(),
            login_password: String::new(),
            status_line: if known_user_count > 0 {
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
            group_message_draft: String::new(),
            browser_address: "https://duckduckgo.com/".to_owned(),
            browser_search_query: String::new(),
            browser_note:
                "DuckDuckGo wird lokal eingebettet. Strukturprobe und Webflaeche laufen getrennt."
                    .to_owned(),
            browser_probe: None,
            browser_search_context: None,
            browser_probe_policy: BrowserProbePolicy::default(),
            browser_embed: EmbeddedBrowser::new(),
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
            browser_sync_stride: 3,
            runtime_profile: {
                use crate::hardware::RecommendedProfile;
                match hardware::detect().recommended_profile() {
                    RecommendedProfile::Legacy   => RuntimeProfile::Legacy,
                    RecommendedProfile::LowPower => RuntimeProfile::LowPower,
                    RecommendedProfile::Auto     => RuntimeProfile::Auto,
                }
            },
            ui_language: UiLanguage::German,
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
            youtube_address: "https://www.youtube.com/".to_owned(),
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
            cascade_run_id: None,
            cascade_metrics: None,
            backend_capability_score: 0.0,
            backend_capability_stage: String::new(),
            backup_enabled: true, // Standardmäßig aktiviert
            swarm_consented: read_swarm_consent(),
            swarm_overlap_requests: Vec::new(),
        };
        shell.browser_sync_stride = shell.profile_browser_sync_stride();
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
    let path = std::path::Path::new("data").join("swarm_consent.json");
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            return val.get("consented").and_then(|v| v.as_bool()).unwrap_or(true);
        }
    }
    true // opt-in by default
}

fn write_swarm_consent(enabled: bool) -> Result<(), String> {
    let path = std::path::Path::new("data").join("swarm_consent.json");
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
    state["consent_ok"] = serde_json::Value::Bool(true);
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
                Tab::Browser      => "Browser: eingebetteter Web-Browser f\u{fc}r sichere Recherche direkt in Aether \u{2014} ohne externen Browser.",
                Tab::YouTube      => "YouTube: Videos laden und gleichzeitig strukturell analysieren. KI-Mustererkennung l\u{e4}uft im Hintergrund.",
                Tab::Data         => "Daten: Dateien ablegen, analysieren und als Artefakte sichern \u{2014} hier landen alle Analyse-Ergebnisse.",
                Tab::Settings     => "Einstellungen: Laufzeit-Profil w\u{e4}hlen (Legacy f\u{fc}r \u{e4}ltere Hardware), Takt und Bridge-Verbindungen konfigurieren.",
                Tab::Logs         => "Protokoll: alle Ereignisse, Fehler und Sicherheitsmeldungen chronologisch \u{2014} der Blick hinter die Kulissen.",
                Tab::Anchors      => "Anker: unver\u{e4}nderliche Strukturpunkte anzeigen, die beweisen dass Daten nicht manipuliert wurden.",
                Tab::FlowSphere   => "FlowSphere: 3D-Musterbild \u{2014} zeigt Zusammenh\u{e4}nge, Ausrei\u{df}er und Stabilit\u{e4}t des Gesamtbilds.",
                Tab::StructureMap => "Strukturkarte: Delta-Konvergenz und Kompressionspfad \u{2014} wie stark haben sich Daten ver\u{e4}ndert, wie gut lassen sie sich rekonstruieren.",
                Tab::Gaming       => "Gaming-Welt: misst wie viel Aether \u{fc}ber interaktive Muster gelernt hat und wann ein stabiler Rollout sinnvoll ist.",
                Tab::Media        => "Medien-Welt: Sequenzen, Videos und Audio werden offline verdichtet \u{2014} je mehr Material, desto besser die Modelle.",
                Tab::Research     => "Forschungs-Welt: Messdaten und Archive r\u{fc}ckwirkend verkn\u{fc}pfen und reproduzierbar machen.",
                Tab::ADE          => "Bedrohungsanalyse: Dateien auf Malware, Obfuskation und Anomalien pr\u{fc}fen \u{2014} mit erkl\u{e4}rbaren Ergebnissen.",
                Tab::Imprint      => "Impressum: Version, Datenschutzprinzipien und rechtliche Hinweise zu Aether.",
                Tab::Rekonstruktion => "Rekonstruktion: Artefakte aus dem Vault wiederherstellen und den Rekonstruktionspfad nachvollziehen.",
                Tab::Launcher     => "Launcher: Dienste starten und stoppen, Build-Aufgaben ausf\u{fc}hren und Live-Logs beobachten.",
            },
            UiLanguage::English => match self.active_tab {
                Tab::Home         => "Dashboard: current system state, alerts, readiness score and quick access.",
                Tab::Control      => "Control Center: run checks, stabilize the system, resolve issues \u{2014} everything at a glance.",
                Tab::Symbiont     => "Manage companion nodes: connected Python agents and co-pilot runtimes.",
                Tab::SwarmOps     => "Swarm: start, connect and coordinate nodes. Shows who is active and which invariants are shared.",
                Tab::Privacy      => "Privacy: define who sees what data, how long it is retained, and what gets redacted.",
                Tab::Chat         => "Chat: ask questions, control workflows, and exchange messages with other local users.",
                Tab::Browser      => "Browser: embedded web browser for secure research directly inside Aether.",
                Tab::YouTube      => "YouTube: load and structurally analyze videos simultaneously. AI pattern recognition runs in the background.",
                Tab::Data         => "Data: store files, run analysis, and save results as artifacts.",
                Tab::Settings     => "Settings: choose runtime profile, configure tick cadence and bridge connections.",
                Tab::Logs         => "Logs: all events, errors and security messages in chronological order.",
                Tab::Anchors      => "Anchors: view immutable structural checkpoints that prove data has not been tampered with.",
                Tab::FlowSphere   => "FlowSphere: 3D pattern view \u{2014} shows relationships, outliers and overall stability.",
                Tab::StructureMap => "Structure Map: delta convergence and compression path \u{2014} how much data changed and how well it can be reconstructed.",
                Tab::Gaming       => "Gaming World: measures how much Aether learned from interactive patterns and when a stable rollout makes sense.",
                Tab::Media        => "Media World: sequences, videos and audio are compressed offline \u{2014} more material means better models.",
                Tab::Research     => "Research World: link measurement series and archives retroactively and make them reproducible.",
                Tab::ADE          => "Threat Analysis: scan files for malware, obfuscation and anomalies \u{2014} with explainable results.",
                Tab::Imprint      => "About: version, privacy principles and legal information about Aether.",
                Tab::Rekonstruktion => "Reconstruction: restore artifacts from the vault and trace the reconstruction path.",
                Tab::Launcher     => "Launcher: start and stop services, run build tasks, and monitor live logs.",
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
            .unwrap_or_else(|| if self.structure_map_locked { 1.0 } else { self.structure_map_compression / 100.0 });
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
            ((self.backend_swarm_reachable_node_count as f32 / self.backend_swarm_node_count as f32) * 0.7
                + (self.backend_swarm_candidate_count as f32 / self.backend_swarm_node_count.max(1) as f32).min(1.0) * 0.3)
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
                format!("Delta-Pulse zeigen Versatz und Takt bei {:.0}% Delta", self.cascade_metrics.as_ref().map(|metrics| metrics.delta_convergence as f32).unwrap_or(0.0) * 100.0),
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
                    format!("{} Knoten, {:.0}% Kopplung nach aussen", self.backend_swarm_node_count, external_link_strength * 100.0)
                },
                "Die cyanfarbenen Knoten und Leitungen zeigen, wie stark der aktuelle Bereich nach aussen verbunden ist. Dichte, ruhige Linien sprechen fuer gemeinsame Bewegung ueber Domaenengrenzen hinweg. Lockere oder rot kipppende Verbindungen deuten eher auf Drift, geringe Uebereinstimmung oder instabile Kopplung hin.".to_owned(),
                Color::from_rgb8(0x59, 0xD5, 0xE9),
            ),
            _ if key.starts_with("attractor_") => {
                let idx = key.trim_start_matches("attractor_").parse::<usize>().unwrap_or(0);
                (
                    format!("Attraktor {}", idx + 1),
                    format!("Musterkern {} von {}", idx + 1, self.structure_map_anchor_count.max(1)),
                    format!("Dieser gruene Knoten ist ein stabiler Sammelpunkt im Innenbild. Er steht fuer einen wiederkehrenden Zustand oder eine Form, zu der der Verlauf immer wieder zurueckfindet. Je ruhiger die Umgebung und je hoeher Noether/Bayes stehen, desto belastbarer ist dieser Knoten als Erklaerungskern."),
                    Color::from_rgb8(0x4C, 0xD9, 0x6E),
                )
            }
            _ if key.starts_with("swarm_") => {
                let idx = key.trim_start_matches("swarm_").parse::<usize>().unwrap_or(0);
                let label = self
                    .backend_swarm_summary
                    .split_whitespace()
                    .next()
                    .unwrap_or("Swarm");
                (
                    format!("Swarm-Knoten {}", idx + 1),
                    format!("Externer Bezug im Netzkontext {}", label),
                    format!("Dieser Knoten repraesentiert einen externen Vergleichspunkt. Die Linie dorthin zeigt, ob die lokale Bewegung auch ausserhalb des aktuellen Bereichs wieder auftaucht. Hohe Kopplung und ein ruhiger Bayes-Wert sprechen eher fuer geteilte Struktur als fuer Zufall oder isolierte Spitzen. Bayes aktuell {:.0}%.", bayes * 100.0),
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
            ((self.backend_swarm_reachable_node_count as f32 / self.backend_swarm_node_count as f32) * 0.7
                + (self.backend_swarm_candidate_count as f32 / self.backend_swarm_node_count.max(1) as f32).min(1.0) * 0.3)
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

        let domain_hint = self
            .flow_sphere_domain_names
            .iter()
            .find_map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) }
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

        let prefix = if user_hint.is_empty() {
            domain_hint
        } else {
            format!("{} / {}", user_hint, domain_hint)
        };

        Some(format!(
            "{} · {} · {:.0}% Kopplung · {} erreichbare Peers",
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
            ((self.backend_swarm_reachable_node_count as f32 / self.backend_swarm_node_count as f32) * 0.7
                + (self.backend_swarm_candidate_count as f32 / self.backend_swarm_node_count.max(1) as f32).min(1.0) * 0.3)
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
        let path = std::path::Path::new("data/interbus/backend_state.json");
        if !path.exists() {
            return;
        }
        let Ok(raw) = std::fs::read_to_string(path) else {
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
        // Read emergent OS capability score (written by capability_score.py)
        let cap_path = std::path::Path::new("data").join("interbus").join("capability_score.json");
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
    }

    /// Reads `data/interbus/swarm_overlap_events.json` and appends new entries to
    /// `self.swarm_overlap_requests`. Duplicate entries (same `anchor_hash_a`) are skipped.
    fn poll_swarm_overlap_events(&mut self) {
        let path = std::path::Path::new("data")
            .join("interbus")
            .join("swarm_overlap_events.json");
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

    fn other_usernames(&self) -> Vec<String> {
        let current = self.current_username();
        let query = self.chat_user_search.trim().to_ascii_lowercase();
        self.auth_store
            .usernames()
            .into_iter()
            .filter(|username| Some(username.clone()) != current)
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

    fn browser_embed_rect(&self) -> BrowserHostRect {
        if self.active_tab == Tab::Home
            && (self.dashboard_nav == "Browser" || self.dashboard_nav == "YouTube")
        {
            let x = (self.window_width * 0.42)
                .clamp(260.0, (self.window_width - 360.0).max(260.0));
            let width = (self.window_width - x - 20.0).max(320.0);
            return BrowserHostRect {
                x: x as i32,
                y: 178,
                width: width as i32,
                height: (self.window_height - 210.0).max(220.0) as i32,
            }
            .normalized();
        }

        // Responsive Navigator width: 140px—200px depending on window size
        let nav_width = ((self.window_width * 0.15).clamp(140.0, 200.0)).floor();
        let left_margin = 18.0;
        let nav_gap = 12.0;
        let right_column_x = left_margin + nav_width + nav_gap;
        let main_width = (self.window_width - right_column_x - 18.0).max(360.0);
        let top_tabs_height = 58.0;
        let status_height = 30.0;
        let content_top = 18.0 + top_tabs_height + status_height + 12.0;
        let browser_inner_padding = 10.0;
        let control_column_width = (main_width * 0.36).clamp(280.0, 420.0);
        let split_gap = 12.0;
        BrowserHostRect {
            x: (right_column_x + browser_inner_padding + control_column_width + split_gap) as i32,
            y: (content_top + browser_inner_padding) as i32,
            width: (main_width - control_column_width - split_gap - browser_inner_padding * 2.0)
                .max(320.0) as i32,
            height: (self.window_height - content_top - 24.0).max(220.0) as i32,
        }
        .normalized()
    }

    fn sync_browser_embed(&mut self) {
        if self.browser_surface_mode().is_none() {
            self.browser_embed.hide();
            return;
        }
        if !self.browser_embed.available() {
            self.browser_note =
                "Eingebetteter Browser ist lokal noch nicht verfuegbar. DuckDuckGo bleibt als Ziel gesetzt."
                    .to_owned();
            return;
        }
        let rect = self.browser_embed_rect();
        match self.browser_embed.show_docked("Aether", rect) {
            Ok(()) => {
                let _ = self.browser_embed.sync_bounds(rect);
                self.browser_embed.show();
            }
            Err(err) => {
                self.browser_note = format!("Browser-Einbettung noch nicht bereit: {err}");
            }
        }
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
                },
                AnchorClusterView {
                    title: "Analyse-Gruppe A".to_owned(),
                    descriptor: "Vorbereitung".to_owned(),
                    item_count: 0,
                    total_bytes: 0,
                    sample_note:
                        "Keine Ausfuehrung. Nur isolierte Verarbeitung und Anchor-Signale."
                            .to_owned(),
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
                AnchorClusterView {
                    title: format!("Cluster {:02}", index + 1),
                    descriptor: format!("{} / .{}", source, extension),
                    item_count: items.len(),
                    total_bytes,
                    sample_note,
                }
            })
            .collect()
    }

    #[allow(dead_code)]
    fn tab_button(&self, tab: Tab, icon: &'static str, label: &'static str) -> Element<'_, Message> {
        let is_active = self.active_tab == tab;
        let accent = c(ACCENT());
        let text_active = c(TEXT_H());
        let text_idle = c(TEXT_D());

        container(
            button(
                Column::new()
                    .push(text(icon).size(16).color(if is_active { accent } else { text_idle }))
                    .push(text(label).size(11).color(if is_active { text_active } else { text_idle }))
                    .spacing(2)
                    .align_x(Alignment::Center),
            )
            .padding([8, 16])
            .on_press(Message::TabSelected(tab))
            .style(move |_: &Theme, _| button::Style {
                background: None,
                text_color: if is_active { text_active } else { text_idle },
                ..Default::default()
            }),
        )
        .style(move |_: &Theme| container::Style {
            background: if is_active {
                Some(Background::Color(Color::from_rgba(0.502, 0.31, 0.98, 0.08)))
            } else {
                None
            },
            border: Border {
                color: if is_active { c(BORDER_ACT()) } else { Color::TRANSPARENT },
                width: if is_active { 2.0 } else { 0.0 },
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
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


// struct FlowSphereScene wurde auf Modulebene verschoben (siehe oben)
#[allow(dead_code)]
fn view_header<'a>(&'a self, logo: Element<'a, Message>, tabs: Element<'a, Message>) -> Element<'a, Message> {
        let all_ok = self.security_snapshot.trust_state.to_uppercase().contains("HIGH")
            || self.security_snapshot.trust_state.to_uppercase().contains("OK");

        let status_border = if all_ok {
            c(ACCENT())
        } else {
            c(DANGER())
        };

        let status_content: Element<'_, Message> = Row::new()
            .spacing(6)
            .align_y(Alignment::Center)
            .push(canvas::Canvas::new(DotScene { color: if all_ok { c(ACCENT()) } else { c(DANGER()) }})
                .width(Length::Fixed(8.0)).height(Length::Fixed(8.0)))
            .push(
                text(
                    if all_ok { "Operational" } else { "Degraded" }
                )
                .size(11)
                .color(c(TEXT_M()))
            )
            .into();

        let nodes_content: Element<'_, Message> = Row::new()
            .spacing(6)
            .align_y(Alignment::Center)
            .push(text("\u{2b21}").size(11).color(c(ACCENT2())))
            .push(
                text(
                    format!("{} Nodes", self.anchor_clusters().len())
                )
                .size(11)
                .color(c(TEXT_M()))
            )
            .into();

        let time_content: Element<'_, Message> = Row::new()
            .spacing(6)
            .align_y(Alignment::Center)
            .push(text("\u{25d4}").size(11).color(c(TEXT_D())))
            .push(
                text(
                    format!(
                        "{:02}:{:02} Live",
                        (self.tick_counter / 60) % 24,
                        self.tick_counter % 60
                    )
                )
                .size(11)
                .color(c(TEXT_D()))
            )
            .into();

        let key_content: Element<'_, Message> = Row::new()
            .spacing(6)
            .align_y(Alignment::Center)
            .push(text("\u{1f511}").size(11).color(c(ACCENT())))
            .push(
                text(
                    if self.data_key_fingerprint.is_empty() {
                        "KEY --".to_owned()
                    } else {
                        format!("KEY {}", self.data_key_fingerprint)
                    }
                )
                .size(11)
                .color(c(TEXT_M()))
            )
            .into();

        let badge_style_ok = move |_: &Theme| container::Style {
            background: None,
            border: Border { color: status_border, width: 1.0, radius: 20.0.into() },
            ..Default::default()
        };
        let badge_style_cyan = |_: &Theme| container::Style {
            background: None,
            border: Border { color: c(ACCENT2()), width: 1.0, radius: 20.0.into() },
            ..Default::default()
        };
        let badge_style_dim = |_: &Theme| container::Style {
            background: None,
            border: Border { color: c(BORDER()), width: 1.0, radius: 20.0.into() },
            ..Default::default()
        };

        container(
            Row::new()
                .spacing(16)
                .align_y(Alignment::Center)
                .push(logo)
                .push(container(iced::widget::Space::new(1.0, 32.0))
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgb8(0x20, 0x1E, 0x30))),
                        ..Default::default()
                    })
                    .width(Length::Fixed(1.0)))
                .push(tabs)
                .push(iced::widget::Space::new(Length::Fill, Length::Shrink))
                .push(
                    Row::new()
                        .spacing(8)
                        .align_y(Alignment::Center)
                        .push(container(status_content).style(badge_style_ok).padding([4, 14]))
                        .push(container(nodes_content).style(badge_style_cyan).padding([4, 14]))
                        .push(container(time_content).style(badge_style_dim).padding([4, 14]))
                        .push(container(key_content).style(badge_style_dim).padding([4, 14]))
                )
            )
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(c(BG_BASE()))),
            border: Border {
                color: c(BORDER()),
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .padding([0, 16])
        .height(Length::Fixed(52.0))
        .into()
    }

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

        let threat_rows: Vec<(String, String, String, String, String)> = vec![
            ("12-05-2024".to_owned(), "crazyfish228".to_owned(), "Code Red".to_owned(), "C:/Users/opened/file_a.jpg".to_owned(), "jpeg".to_owned()),
            ("12-05-2024".to_owned(), "angryswan732".to_owned(), "MyDoom".to_owned(), "D:/vault/tmp/log_88.bin".to_owned(), "bin".to_owned()),
            ("11-05-2024".to_owned(), "node-aether-3".to_owned(), "Sasser".to_owned(), "C:/snapshots/arc_19.dat".to_owned(), "dat".to_owned()),
        ];
        let device_rows: Vec<(String, f32)> = vec![
            ("crazyfish228".to_owned(), (0.38 + 0.16 * (t * 0.04).sin()).clamp(0.0, 1.0)),
            ("angryswan732".to_owned(), (0.61 + 0.12 * (t * 0.03).cos()).clamp(0.0, 1.0)),
            ("node-aether-3".to_owned(), (0.44 + 0.14 * (t * 0.05).sin()).clamp(0.0, 1.0)),
        ];

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
                        button(text("Threat Analysis").size(13))
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
                "Threat Analysis" => self.view_ade(),
                "FlowSphere" => self.view_flow_sphere(),
                "Threat Graph" => self.view_flow_sphere(),
                "Delta Convergence" => self.view_delta_convergence(),
                "Anchors" => self.view_anchors(),
                "Browser" => self.view_browser(),
                "YouTube" => self.view_youtube(),
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
                // col = col.push(topbar); // TODO: topbar nicht definiert
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
                    "Runtime {} | Tick {}ms | Sync {} | Poll {}",
                    self.runtime_profile_label(),
                    self.tick_interval_ms(),
                    self.browser_sync_stride,
                    self.profile_browser_poll_batch()
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
        let browser_mode = match self.browser_surface_mode() {
            Some(Tab::Browser) => "NETWORK",
            Some(Tab::YouTube) => "COMPUTE",
            _ => "OFF",
        };
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
            row3 = row3.push(info_card("Browser-Sync", &format!("jede {} Ticks", self.browser_sync_stride)));
            row3 = row3.push(info_card("Poll-Batch", &format!("{} Events", self.profile_browser_poll_batch())));
            row3 = row3.push(info_card("Browser-Modus", browser_mode));
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

    fn view_browser(&self) -> Element<'_, Message> {
        let browser_status = if self.browser_embed.is_running() {
            container(text("● Browser-Bridge aktiv").size(11).color(Color::from_rgb8(0x5A, 0xAE, 0x84)))
                .padding([4, 8])
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x0A, 0x1A, 0x0F))),
                    border: Border { color: Color::from_rgb8(0x5A, 0xAE, 0x84), width: 1.0, ..Default::default() },
                    ..Default::default()
                })
        } else {
            container(text("⚠ Browser-Bridge nicht aktiv — starte Aether vollständig oder prüfe Python-Pfad in Einstellungen.").size(11).color(Color::from_rgb8(0xD4, 0x6A, 0x6A)))
                .padding([6, 10])
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x1A, 0x0A, 0x0A))),
                    border: Border { color: Color::from_rgb8(0xD4, 0x6A, 0x6A), width: 1.0, ..Default::default() },
                    ..Default::default()
                })
        };

        let url_bar = container(
            Row::new()
                .push(container(
                    text("\u{1f50d}").size(14).color(Color::from_rgb8(0x4E, 0x4A, 0x76))
                ).padding([0, 8]))
                .push(text_input("https://duckduckgo.com", &self.browser_address)
                    .on_input(Message::BrowserAddressChanged)
                    .on_submit(Message::BrowserLoadPressed)
                    .size(13)
                    .padding([8, 12])
                    .width(Length::Fill))
                .push(button(
                    text("\u{2192}").size(14).color(Color::from_rgb8(0xF6, 0xED, 0xFF))
                )
                .padding([8, 14])
                .on_press(Message::BrowserLoadPressed)
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x96, 0x57, 0xF7))),
                    text_color: Color::from_rgb8(0xF6, 0xED, 0xFF),
                    border: Border { radius: 6.0.into(), ..Default::default() },
                    ..Default::default()
                }))
                .spacing(4)
                .align_y(Alignment::Center),
        )
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x17, 0x16, 0x24))),
            border: Border { color: Color::from_rgb8(0x36, 0x34, 0x56), width: 1.1, radius: 8.0.into() },
            ..Default::default()
        })
        .padding([4, 4]);

        container(
            Row::new()
                .push(
                    container(scrollable(
                        {
                            let mut col = Column::new().spacing(14);
                            col = col.push(text("Browser").size(20).color(Color::from_rgb8(0xEE, 0xEA, 0xFF)));
                            col = col.push(browser_status);
                            col = col.push(url_bar);
                            col = col.push(
                                Row::new()
                                    .push(
                                        button(text("Seite pruefen").size(13))
                                            .padding([8, 14])
                                            .on_press(Message::BrowserInspectPressed)
                                            .style(secondary_button_style)
                                    )
                                    .spacing(10)
                            );
                            col = col.push(text("Eingabehilfe: URL-Feld fuer direkte Seiten, Suchfeld fuer Begriffe/Fragen (DuckDuckGo).")
                                .size(11)
                                .color(c(TEXT_D())));
                            col = col.push(text_input("z.B. malware hash lookup, suspicious script pattern, channel name", &self.browser_search_query)
                                .on_input(Message::BrowserSearchQueryChanged)
                                .padding(10)
                                .size(14));
                            col = col.push(button(text("DuckDuckGo suchen"))
                                .padding([10, 16])
                                .on_press(Message::BrowserSearchPressed)
                                .style(primary_button_style));
                            col = col.push(info_card("Browser-Status", &self.browser_note));
                            col = col.push(
                                if let Some(probe) = &self.browser_probe {
                                    info_card(
                                        "Seitenanalyse",
                                        &format!(
                                            "URL: {}\nStatus: {} | Risiko: {} ({:.0}%)\nTyp: {}\n{}\n{}",
                                            probe.final_url,
                                            probe.status_code,
                                            probe.risk_label,
                                            probe.risk_score * 100.0,
                                            probe.content_type,
                                            probe.frontend_summary,
                                            probe.summary
                                        ),
                                    )
                                } else {
                                    info_card(
                                        "Seitenanalyse",
                                        "Noch keine Seitenanalyse vorhanden. Aether prueft nur strukturell und fuehrt nichts aus.",
                                    )
                                }
                            );
                            col = col.push(
                                if let Some(context) = &self.browser_search_context {
                                    info_card(
                                        "Suchkontext",
                                        &format!(
                                            "Provider: {}\nQuelle: {}\n{}",
                                            context.provider,
                                            context.search_url,
                                            context.summary
                                        ),
                                    )
                                } else {
                                    info_card(
                                        "Suchkontext",
                                        "Noch kein Suchkontext geladen. DuckDuckGo bleibt explizit und fail-closed.",
                                    )
                                }
                            );
                            col
                        }
                    )
                    .width(Length::Fixed(420.0))
                )
                .style(panel_frame_style)
                .padding(14)
            )
                .push(
                    container(
                        {
                            let mut col = Column::new().spacing(10);
                            col = col.push(text("Eingebettete Browserflaeche").size(18).color(Color::from_rgb8(0xEE, 0xEA, 0xFF)));
                            col = col.push(text("DuckDuckGo und geladene Seiten erscheinen hier direkt im Hauptprogramm.")
                                .size(13).color(Color::from_rgb8(0x90, 0x88, 0xBC)));
                            col = col.push(container(text(" "))
                                .height(Length::Fill)
                                .width(Length::Fill));
                            col
                        }
                    )
                    .padding(16)
                    .style(panel_frame_style)
                    .width(Length::Fill)
                    .height(Length::Fill)
                )
                .spacing(18)
                .height(Length::Fill)
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
                "Gaming bleibt als Welt erhalten, ohne die bestehenden Analyse-Tabs zu ersetzen: diese Ansicht ordnet nur zusammen, wie viel interaktive Struktur Aether bereits kennt, exakt rekonstruieren kann und spaeter konservativ freigeben darf.",
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
                    ("YouTube", Tab::YouTube),
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
                    ("Threat", Tab::ADE),
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
                    "{}\nPreview: {}\nAnchors: {}\nProcess: {}",
                    last.file_name,
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
        let selected_partner = self.active_private_partner();
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

        let messages = self.active_private_messages();
        let conversation = if let Some(partner) = &selected_partner {
            let mut content = Column::new();
            content = content.push(text(format!("Privater Kanal | {partner}")).size(20));
            content = content.push(text("Suche nach Nutzernamen oeffnet lokale Threads. Inhalte bleiben im privaten Bereich.").size(15));
            content = content.spacing(10);
            if messages.is_empty() {
                content = content.push(info_card(
                    "Leerer Thread",
                    "Noch keine lokalen Nachrichten. Du kannst den Thread sofort beginnen.",
                ));
            } else {
                for message in messages.iter().take(32) {
                    content = content.push(info_card(&message.author, &message.body));
                }
            }
            content = content.push(
                text_input("Nachricht verfassen", &self.private_message_draft)
                    .on_input(Message::PrivateMessageChanged)
                    .padding(10)
                    .size(16),
            );
            content = content.push(
                button(text("Nachricht lokal speichern"))
                    .padding([10, 16])
                    .on_press(Message::PrivateMessageSend)
                    .style(primary_button_style),
            );
            container(scrollable(content).height(Length::Fill))
                .padding(16)
                .style(panel_frame_style)
                .into()
        } else {
            info_card(
                "Kein Nutzer gewaehlt",
                "Suche links nach einem vorhandenen Nutzernamen, um einen privaten Thread zu oeffnen.",
            )
        };

        let mut row = Row::new();
        row = row.push(
            container(scrollable(partners).height(Length::Fill))
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
        let rooms = self.group_rooms();
        let mut content = Column::new()
            .push(text("Gruppen").size(20))
            .push(text("Gruppen bleiben lokal organisiert. Der Standardraum dient als gemeinsamer lokaler Arbeitskontext.").size(15))
            .spacing(12);

        if rooms.is_empty() {
            content = content.push(info_card(
                "Keine Gruppenraeume",
                "Sobald du eine lokale Gruppennachricht speicherst, erscheint hier der Raum Allgemein.",
            ));
        } else {
            for room in rooms.iter().take(8) {
                let body = if room.messages.is_empty() {
                    "Noch keine lokalen Nachrichten.".to_owned()
                } else {
                    room.messages
                        .iter()
                        .rev()
                        .take(3)
                        .map(|message| format!("{}: {}", message.author, message.body))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                content = content.push(info_card(&room.name, &body));
            }
        }

        content = content.push(
            text_input("Nachricht an Allgemein", &self.group_message_draft)
                .on_input(Message::GroupMessageChanged)
                .padding(10)
                .size(16),
        );
        content = content.push(
            button(text("Gruppennachricht lokal speichern"))
                .padding([10, 16])
                .on_press(Message::GroupMessageSend)
                .style(primary_button_style),
        );

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
                    col = col.push(
                        {
                            let mut row = Row::new();
                            row = row.push(info_card("OS-Layer",
                                self.ui_text(
                                    "Sandbox: strikt\nPrivacy-Boundary: hard block\nIntegrationsgrad: lokal",
                                    "Sandbox: strict\nPrivacy boundary: hard block\nIntegration level: local",
                                )));
                            row = row.push(info_card(self.ui_text("Telemetrie", "Telemetry"),
                                self.ui_text(
                                    "Standard: nur lokal\nOptionen: aus, gedrosselt, sicherheitsrelevant",
                                    "Default: local only\nOptions: off, throttled, security-relevant",
                                )));
                            row = row.push(info_card(self.ui_text("Agenten", "Agents"),
                                self.ui_text(
                                    "Lokale Agenten k\u{f6}nnen aktiviert, begrenzt und mit Sicherheitsprofilen versehen werden.",
                                    "Local agents can be activated, restricted and assigned security profiles.",
                                )));
                            row.spacing(14)
                        }
                    );
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
                    col = col.push(text(self.ui_text("Runtime-Profil (Hardware-Inklusion)", "Runtime profile (hardware tier)")).size(20));
                    col = col.push(text(self.ui_text(
                        "AUTO passt dynamisch an. LEGACY priorisiert niedrige Dauerlast f\u{fc}r \u{e4}ltere Systeme.",
                        "AUTO adapts dynamically. LEGACY prioritises low sustained load for older hardware.",
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
                            "{} {}\n{} {} ms\n{} {} {}",
                            self.ui_text("Profil:", "Profile:"),
                            self.runtime_profile_label(),
                            self.ui_text("Tick-Intervall:", "Tick interval:"),
                            self.tick_interval_ms(),
                            self.ui_text("Browser-Sync: alle", "Browser sync: every"),
                            self.browser_sync_stride,
                            self.ui_text("Ticks", "ticks"),
                        ),
                    ));
                    col = col.push(text(self.ui_text("Hybrid Runtime (Rust + Python + Symbiont)", "Hybrid runtime (Rust + Python + Symbiont)")).size(20));
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
                    text("Noch keine Anchor-Cluster vorhanden.").size(14),
                    text("Analysiere eine Datei um erste Strukturanker zu erzeugen.").size(13),
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
            .push(text("\u{25c6} CLUSTER \u{2014} Anchor-Gruppen").size(22))
            .push(text("Kategorien entstehen datengetrieben aus Strukturmerkmalen.").size(13))
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
                            .push(text(format!("Groesse: {} B", selected.total_bytes)).size(14))
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
        container(
            scrollable(
                Column::new()
                    .push(text("Impressum").size(24))
                    .push(info_card(
                        "Status",
                        "Kurz: Die Logik ist schon richtig gebaut. Die volle selbstverstaerkende Skalierung ist vorbereitet, aber noch nicht komplett end-to-end operationalisiert.",
                    ))
                    .push(info_card("Symbionten", &format!("Aktuell registrierte Symbionten: {symbiont_count}")))
                    .push(info_card("Zweck", "Aether macht lokale Analyse, Technik und Wissen ohne Cloud-Zwang verstaendlich und nutzbar."))
                    .push(info_card("Datenschutz", "Account, Deltas und Restanteile bleiben auf dem Geraet. Keine zentrale Wiederherstellung."))
                    .push(info_card("Formeln", "P(n) = base + (1-base) * ln(1+n) / ln(1+Nmax)\nC(t) = vault_hits / total_chunks"))
                    .push(info_card("Systembild", "Aether arbeitet eher wie eine Leitstelle als wie ein Agent: lokale Signale werden geordnet, priorisiert und in stabile Entscheidungen ueberfuehrt."))
                    .spacing(16),
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
                                text("\u{26a0} Diese Datei wurde noch nicht als AEF analysiert. Ziehe sie erneut in das Fenster.")
                                    .size(13)
                                    .color(Color::from_rgb8(0xFF, 0xCC, 0x44)),
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
    // Aether.YouTube – Eingebetteter Video-Browser
    // -----------------------------------------------------------------------

    fn view_youtube(&self) -> Element<'_, Message> {
        let nav_bar = row![
            text_input("YouTube-URL ...", &self.youtube_address)
                .on_input(Message::YouTubeAddressChanged)
                .padding(10)
                .size(16)
                .width(Length::Fill),
            button(text("\u{25b6} Laden").size(15))
                .padding([10, 16])
                .on_press(Message::YouTubeLoadPressed),
        ]
        .spacing(8);

        column![
            row![
                text("\u{25b6} YouTube").size(22),
                text("\u{2014} URL anpassen und Laden dr\u{fc}cken").size(14),
            ]
            .spacing(12),
            nav_bar,
            text(&self.browser_note).size(13),
            text("YouTube-Tab: URL direkt eingeben (youtube.com/watch?v=...) oder Suchbegriff fuer DuckDuckGo-Suche im Browser-Tab. KI-Slop-Erkennung wird aktiviert sobald Bridge laeuft.").size(11).color(c(TEXT_D())),
            container(
                column![
                    text("Eingebetteter Browser aktiv.").size(16),
                    text("Das Video-Fenster erscheint als natives Overlay.").size(14),
                    text("Tipp: youtube.com/watch?v=... direkt eintippen.").size(13),
                ]
                .spacing(10)
                .padding(30)
            )
            .width(Length::Fill)
            .height(Length::Fill),
            button(text("🔍 KI-Analyse starten").size(12).color(c(TEXT_H())))
                .on_press(Message::YouTubeKiAnalysisPressed)
                .padding([8, 12])
                .style(secondary_button_style),
        ]
        .spacing(10)
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

            container(
                scrollable(
                    column![
                        text("FLOWSPHERE LESEHILFE").size(11).color(cyan),
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
            container(text(format!("Sichtbar: {}", visible)).size(10).color(c(TEXT_H())))
                .padding([8, 10])
                .width(Length::Fill)
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgba(0.08, 0.18, 0.14, 0.92))),
                    border: Border { color: Color::from_rgba(0.30, 0.85, 0.45, 0.60), width: 1.0, radius: 8.0.into() },
                    ..Default::default()
                })
                .into()
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
        } else if self.flow_sphere_broadcast_visible.is_some() {
            "Vorschau: Ein freigegebener Broadcast ist sichtbar und bleibt an die aktuelle Strukturentscheidung gebunden.".to_owned()
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
                text(format!("nodes: {} | depth: {} | anchor: {} | evolved: {}", aelab.nodes, aelab.depth, aelab.has_anchor, aelab.evolved)).size(14).color(dim),
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

        let main_content = scrollable(
            column![
                metric_help_panel,
                capsule_panel,
                structure_map_panel,
                aelab_panel,
                compression_panel,
                reconstruction_panel,
                lineage_panel,
            ]
            .spacing(12)
            .padding([0.0f32, 8.0]),
        );

        main_content.into()
    }

    fn view_ade(&self) -> Element<'_, Message> {
        let panel_s = Color::from_rgb8(0x05, 0x10, 0x1C);
        let cyan    = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let red     = Color::from_rgb8(0xD9, 0x50, 0x50);
        let green   = Color::from_rgb8(0x4C, 0xD9, 0x6E);
        let dim     = Color::from_rgb8(0x50, 0x6A, 0x7A);

        let capsule_panel = if let Some(capsule) = &self.capsule_state {
            let mut rows = column![
                text(format!("source: {}", capsule.source_label)).size(14).color(cyan),
                text(format!("trigger: {} | type: {} | domain: {}", capsule.trigger, capsule.source_type, capsule.domain_hint)).size(13).color(dim),
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
            if !capsule.anomaly_flags.is_empty() {
                let flags = capsule.anomaly_flags.join(", ");
                rows = rows.push(text(format!("Anomalies: {}", flags)).size(14).color(red));
            }
            ade_subpanel("CAPSULE · THREAT SIGNALS", rows.into(), panel_s)
        } else {
            ade_subpanel("CAPSULE · THREAT SIGNALS", text("No capsule result available").size(13).color(dim).into(), panel_s)
        };

        let structure_panel = if let Some(state) = &self.structure_map_state {
            let rows = column![
                text(format!("region: {}", state.region_label)).size(14).color(cyan),
                text(format!("coherence: {:.4} | trust: {:.4}", state.coherence_score, state.trust_score)).size(14).color(dim),
                text(format!("anchors: {} | anomalies: {}", state.anchor_count, state.anomaly_count)).size(14).color(dim),
                text(format!("locked: {}", if state.locked { "yes" } else { "no" })).size(14).color(if state.locked { green } else { dim }),
            ];
            ade_subpanel("STRUCTURE SNAPSHOT · THREAT CONTEXT", rows.into(), panel_s)
        } else {
            ade_subpanel("STRUCTURE SNAPSHOT · THREAT CONTEXT", text("No structure snapshot available").size(13).color(dim).into(), panel_s)
        };

        let aelab_panel = if let Some(aelab) = &self.aelab_state {
            let rows = column![
                text(format!("fitness: {:.4} | lossless: {:.1}%", aelab.fitness, aelab.lossless * 100.0)).size(14).color(cyan),
                text(format!("coupling: {:.3} | coherence: {:.3}", aelab.seed_coupling, aelab.seed_coherence)).size(13).color(dim),
                text(format!("vault total: {} | integrity: {}", aelab.vault_total_entries, if aelab.vault_integrity_ok { "ok" } else { "check" })).size(13).color(if aelab.vault_integrity_ok { green } else { red }),
                text(format!("vault root: {}", aelab.vault_root)).size(12).color(dim),
            ];
            ade_subpanel("AELAB · THREAT CORRELATION", rows.into(), panel_s)
        } else {
            ade_subpanel("AELAB · THREAT CORRELATION", text("No AELab correlation available yet").size(13).color(dim).into(), panel_s)
        };

        let compression_panel_ade = if let Some(compression) = &self.compression_state {
            let rows = column![
                text(format!("format: {}", compression.format)).size(14).color(cyan),
                text(format!("original: {} B  |  compressed: {} B", compression.original_bytes, compression.compressed_bytes)).size(14).color(dim),
                text(format!("ratio: {:.4}  |  gain: {:.2}%", compression.ratio, compression.gain_percent)).size(16).color(if compression.gain_percent > 0.0 { green } else { dim }),
                text(format!("changed bytes: {}", self.capsule_state.as_ref().map_or(0, |c| c.changed_bytes))).size(13).color(dim),
            ];
            ade_subpanel("COMPRESSION · RATIO", rows.into(), panel_s)
        } else {
            ade_subpanel("COMPRESSION · RATIO", text("Datei analysieren um Kompressionswerte zu sehen.").size(13).color(dim).into(), panel_s)
        };

        let reconstruct_link: Element<'_, Message> = if self.capsule_state.is_some() {
            button(text("→ Rekonstruktion pruefen").size(12).color(Color::from_rgb8(0xD0, 0xE8, 0xF8)))
                .on_press(Message::TabSelected(Tab::Rekonstruktion))
                .padding([6, 14])
                .style(primary_button_style)
                .into()
        } else {
            iced::widget::Space::new(Length::Shrink, Length::Shrink).into()
        };

        scrollable(
            column![
                reconstruct_link,
                capsule_panel,
                structure_panel,
                aelab_panel,
                compression_panel_ade,
            ]
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
            Tab::Browser => self.view_browser(),
            Tab::YouTube => self.view_youtube(),
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
                nav_item("8. Threat Analysis", Tab::ADE, self.active_tab),
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
                nav_item("16. Research", Tab::Research, self.active_tab),
                text("Workspace").size(12).color(c(TEXT_D())),
                nav_item("17. Reconstruction", Tab::Rekonstruktion, self.active_tab),
                nav_item("18. Info", Tab::Imprint, self.active_tab),
                text("System").size(12).color(c(TEXT_D())),
                nav_item("19. Runtime", Tab::Settings, self.active_tab),
                nav_item("20. Launcher", Tab::Launcher, self.active_tab),
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
                        Tab::Browser => "Browser",
                        Tab::YouTube => "YouTube",
                        Tab::Data => "Files",
                        Tab::Settings => "Runtime",
                        Tab::Logs => "Logs",
                        Tab::Anchors => "Anchors",
                        Tab::FlowSphere => "FlowSphere",
                        Tab::StructureMap => "Delta Convergence",
                        Tab::Gaming => "Gaming",
                        Tab::Media => "Media",
                        Tab::Research => "Research",
                        Tab::ADE => "Threat Analysis",
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
            quick_button("ADE", Tab::ADE),
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
        let body = self.group_message_draft.trim().to_owned();
        if body.is_empty() {
            self.status_line = "Leere Gruppennachrichten werden nicht gespeichert.".to_owned();
            return;
        }
        match self
            .state_store
            .add_group_message(&author, "Allgemein", &author, &body)
        {
            Ok(()) => {
                self.group_message_draft.clear();
                self.status_line = "Gruppennachricht in Allgemein gespeichert.".to_owned();
            }
            Err(err) => self.status_line = err,
        }
    }

    #[allow(dead_code)]
    fn normalize_live_command(text: &str) -> String {
        let mut normalized = text.trim().to_lowercase();
        for dash in ['‑', '–', '—'] {
            normalized = normalized.replace(dash, "-");
        }
        normalized
            .replace('ä', "ae")
            .replace('ö', "oe")
            .replace('ü', "ue")
            .replace('ß', "ss")
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

    #[allow(dead_code)]
    fn parse_live_render_mode_command(&self, prompt: &str) -> Option<bool> {
        let normalized = Self::normalize_live_command(prompt);
        let mentions_live = normalized.contains("live")
            || normalized.contains("liverender")
            || normalized.contains("liverenderer")
            || normalized.contains("laufrenderer")
            || normalized.contains("laufrenderer");
        let mentions_render = normalized.contains("render")
            || normalized.contains("renderer")
            || normalized.contains("analyse")
            || normalized.contains("frame");
        let mentions_live_render = (mentions_live && mentions_render)
            || normalized.contains("liverender")
            || normalized.contains("liverenderer")
            || normalized.contains("laufrenderer")
            || normalized.contains("laufrenderer");
        if !mentions_live_render {
            return None;
        }
        let activation_markers = [
            "aktiviere",
            "aktivieren",
            "einschalten",
            "an",
            "ein",
            "live-analyse an",
            "live analyse an",
        ];
        let deactivation_markers = [
            "deaktiviere",
            "deaktivieren",
            "aus",
            "live-analyse aus",
            "live analyse aus",
            "passiven normalmodus",
            "passiv",
            "stoppe alle frame-hooks",
            "stoppe alle frame hooks",
        ];
        let last_activation = activation_markers
            .iter()
            .filter_map(|marker| normalized.rfind(marker))
            .max();
        let last_deactivation = deactivation_markers
            .iter()
            .filter_map(|marker| normalized.rfind(marker))
            .max();

        match (last_activation, last_deactivation) {
            (Some(a), Some(d)) => Some(a > d),
            (Some(_), None) => Some(true),
            (None, Some(_)) => Some(false),
            (None, None) => None,
        }
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
        let os_sample_interval = 10u64;
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

    fn dashboard_search_help(&self) -> &'static str {
        self.ui_text("Suche: Datei, Anchor, Bedrohung \u{2026}", "Search: file, anchor, threat \u{2026}")
    }

    fn dashboard_search_placeholder(&self) -> &'static str {
        self.ui_text("Suche \u{2026}", "Search \u{2026}")
    }

    fn browser_surface_mode(&self) -> Option<Tab> {
        if self.current_user.is_none() {
            return None;
        }

        match self.active_tab {
            Tab::Browser => Some(Tab::Browser),
            Tab::YouTube => Some(Tab::YouTube),
            Tab::Home => None,
            _ => None,
        }
    }

    fn profile_tick_interval_ms(&self) -> u64 {
        let browser_like = self.browser_surface_mode().is_some();
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

    fn profile_browser_sync_stride(&self) -> u64 {
        match self.runtime_profile {
            RuntimeProfile::Auto => 3,
            RuntimeProfile::Balanced => 3,
            RuntimeProfile::LowPower => 5,
            RuntimeProfile::Legacy => 7,
        }
    }

    fn profile_browser_poll_batch(&self) -> usize {
        match self.runtime_profile {
            RuntimeProfile::Auto => 4,
            RuntimeProfile::Balanced => 4,
            RuntimeProfile::LowPower => 3,
            RuntimeProfile::Legacy => 2,
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
                        self.status_line = format!(
                            "Anmeldung erfolgreich. Data-Key aktiv: {}",
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
                            self.status_line = format!(
                                "Registrierung abgeschlossen. Data-Key aktiv: {}",
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
                self.active_tab = tab;
                if self.active_tab == Tab::Browser {
                    self.browser_address = "https://duckduckgo.com/".to_owned();
                    match self.browser_embed.navigate(&self.browser_address) {
                        Ok(()) => {
                            self.sync_browser_embed();
                            self.browser_note = "DuckDuckGo wurde automatisch geladen.".to_owned();
                            self.status_line = self.browser_note.clone();
                        }
                        Err(err) => {
                            self.browser_note = format!(
                                "DuckDuckGo konnte beim Tab-Wechsel nicht geladen werden: {err}"
                            );
                            self.status_line = self.browser_note.clone();
                        }
                    }
                } else if self.active_tab == Tab::YouTube {
                    self.youtube_address = "https://www.youtube.com/".to_owned();
                    let url = self.youtube_address.clone();
                    match self.browser_embed.navigate(&url) {
                        Ok(()) => {
                            self.sync_browser_embed();
                            self.browser_note = "YouTube wurde automatisch geladen.".to_owned();
                            self.status_line = self.browser_note.clone();
                        }
                        Err(err) => {
                            self.browser_note =
                                format!("YouTube konnte beim Tab-Wechsel nicht geladen werden: {err}");
                            self.status_line = self.browser_note.clone();
                        }
                    }
                } else {
                    self.browser_embed.hide();
                }
            }
            Message::ChatContextSelected(context) => self.chat_context = context,
            Message::SecurityModeSelected(mode) => self.set_security_mode(&mode),
            Message::RuntimeProfileSelected(profile) => {
                self.runtime_profile = profile;
                self.browser_sync_stride = self.profile_browser_sync_stride();
                self.status_line = format!(
                    "Runtime-Profil aktiv: {} | Tick {} ms | Browser-Sync jede {} Ticks",
                    self.runtime_profile_label(),
                    self.tick_interval_ms(),
                    self.browser_sync_stride
                );
            }
            Message::UiLanguageSelected(lang) => {
                self.ui_language = lang;
                self.status_line = match self.ui_language {
                    UiLanguage::German => "Sprache auf Deutsch gesetzt.".to_owned(),
                    UiLanguage::English => "Interface language switched to English.".to_owned(),
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
            Message::GroupMessageChanged(value) => self.group_message_draft = value,
            Message::GroupMessageSend => self.send_group_message(),
            Message::BrowserAddressChanged(value) => self.browser_address = value,
            Message::BrowserSearchQueryChanged(value) => self.browser_search_query = value,
            Message::YouTubeAddressChanged(value) => {
                self.youtube_address = value;
            }
            Message::YouTubeLoadPressed => {
                let url = self.youtube_address.trim().to_owned();
                if url.is_empty() {
                    self.status_line = "Bitte eine YouTube-URL eingeben.".to_owned();
                    return Task::none();
                }
                self.active_tab = Tab::YouTube;
                match self.browser_embed.navigate(&url) {
                    Ok(()) => {
                        self.sync_browser_embed();
                        self.browser_note = format!("YouTube laedt {url}");
                        self.status_line = self.browser_note.clone();
                    }
                    Err(err) => {
                        self.browser_note = format!("Video konnte nicht geladen werden: {err}");
                        self.status_line = self.browser_note.clone();
                    }
                }
            }
            Message::YouTubeKiAnalysisPressed => {
                if self.youtube_address.trim().is_empty() {
                    self.status_line = "YouTube-URL oder Suchbegriff eingeben vor KI-Analyse.".to_owned();
                    return Task::none();
                }
                if !self.hybrid_bridge_running {
                    self.status_line = "KI-Analyse: Bridge-Verbindung wird benoetigt (Symbiont Control -> Bridge starten)".to_owned();
                    return Task::none();
                }
                let analysis_addr = self.youtube_address.clone();
                self.status_line = format!("KI-Analyse gestartet fuer {} - Ergebnis erscheint im Log.", analysis_addr);
            }
            Message::BrowserLoadPressed => {
                let url = self.browser_address.trim().to_owned();
                if url.is_empty() {
                    self.status_line = "Bitte zuerst eine URL eingeben.".to_owned();
                    return Task::none();
                }
                self.active_tab = Tab::Browser;
                match self.browser_embed.navigate(&url) {
                    Ok(()) => {
                        self.sync_browser_embed();
                        self.browser_note = format!("Browser laedt {url}");
                        self.status_line = self.browser_note.clone();
                    }
                    Err(err) => {
                        self.browser_note = format!("Browser konnte nicht geladen werden: {err}");
                        self.status_line = self.browser_note.clone();
                    }
                }
            }
            Message::BrowserInspectPressed => {
                let url = self.browser_address.trim().to_owned();
                if url.is_empty() {
                    self.status_line = "Bitte zuerst eine URL eingeben.".to_owned();
                    return Task::none();
                }
                self.active_tab = Tab::Browser;
                self.browser_note = format!("Strukturanalyse gestartet fuer {url}");
                self.status_line = self.browser_note.clone();
                let policy = self.browser_probe_policy.clone();
                return Task::perform(
                    async move { BrowserInspector::inspect_url(&url, &policy) },
                    Message::BrowserInspectCompleted,
                );
            }
            Message::BrowserSearchPressed => {
                let query = self.browser_search_query.trim().to_owned();
                if query.is_empty() {
                    self.status_line = "Bitte zuerst einen Suchbegriff eingeben.".to_owned();
                    return Task::none();
                }
                self.active_tab = Tab::Browser;
                match self.browser_embed.search_duckduckgo(&query) {
                    Ok(()) => {
                        self.sync_browser_embed();
                        self.browser_note = format!(
                            "DuckDuckGo wird geladen und Suchkontext wird ermittelt: {query}"
                        );
                        self.status_line = self.browser_note.clone();
                    }
                    Err(err) => {
                        self.browser_note =
                            format!("DuckDuckGo konnte nicht geladen werden: {err}");
                        self.status_line = self.browser_note.clone();
                    }
                }
                return Task::perform(
                    async move { BrowserInspector::fetch_search_context(&query, "duckduckgo", 6.0, "") },
                    Message::BrowserSearchCompleted,
                );
            }
            Message::BrowserInspectCompleted(result) => {
                self.browser_note = if result.ok {
                    format!(
                        "Analyse abgeschlossen: {} | {} ({:.0}%)",
                        result.final_url,
                        result.risk_label,
                        result.risk_score * 100.0
                    )
                } else {
                    format!("Analyse fehlgeschlagen: {}", result.error)
                };
                self.status_line = self.browser_note.clone();
                self.browser_probe = Some(result);
            }
            Message::BrowserSearchCompleted(context) => {
                self.browser_note = if context.ok {
                    format!("Suchkontext geladen von {}", context.provider)
                } else {
                    format!("Suchkontext fehlgeschlagen: {}", context.error)
                };
                self.status_line = self.browser_note.clone();
                self.browser_search_context = Some(context);
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
                let Some(username) = self.current_username() else {
                    self.status_line =
                        "Bitte zuerst lokal anmelden, bevor du Artefakte analysierst.".to_owned();
                    return Task::none();
                };
                let drop_world = match self.active_tab {
                    Tab::Gaming => Some(Tab::Gaming),
                    Tab::Media => Some(Tab::Media),
                    Tab::Research => Some(Tab::Research),
                    _ => None,
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
                match result {
                    Ok(result) => match self.state_store.add_register_entry(result.entry.clone()) {
                        Ok(_) => {
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
                            self.status_line = self.analysis_status.clone();
                            self.active_tab = Tab::Data;
                            self.refresh_security_snapshot(true, "file_loaded");
                        }
                        Err(err) => {
                            self.analysis_progress = 0.0;
                            self.analysis_status =
                                format!("Analyse konnte nicht gespeichert werden: {err}");
                            self.status_line = self.analysis_status.clone();
                        }
                    },
                    Err(err) => {
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
                        self.apply_projection_state(
                            result.capsule_state,
                            result.structure_map_state,
                            result.structure_map_nodes,
                            result.aelab_state,
                            result.compression_state,
                            result.reconstruction_state,
                        );
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
                let out_dir = PathBuf::from("data").join("rust_shell").join("reconstructed");
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
                        let src = PathBuf::from("data")
                            .join("rust_shell")
                            .join("reconstructed")
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
                if self.active_tab == Tab::Browser {
                    self.sync_browser_embed();
                }
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
                    self.status_line = "FlowSphere: Broadcast-Vorschlag freigegeben und sichtbar geschaltet.".to_owned();
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
                let path = std::path::Path::new("data").join(format!("flow_sphere_snapshot_{}.json", self.tick_counter));
                if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
                    let _ = std::fs::create_dir_all("data");
                    let _ = std::fs::write(&path, json);
                    self.status_line = format!("FlowSphere-Snapshot exportiert: {}", path.display());
                }
            }
            Message::OpenFullTab(tab) => {
                self.active_tab = tab;
                self.app_mode = AppMode::Full;
                return window::get_latest().then(|id_opt| {
                    if let Some(id) = id_opt {
                        window::resize(id, iced::Size::new(FULL_WINDOW_WIDTH, FULL_WINDOW_HEIGHT))
                    } else {
                        Task::none()
                    }
                });
            }
            Message::SymbiontInputChanged(value) => {
                self.symbiont_input = value;
            }
            Message::SymbiontProfilePressed => {
                let host = self.symbiont_host.clone();
                let port = self.symbiont_port;
                let signal = self.symbiont_input.clone();
                self.symbiont_busy = true;
                self.symbiont_result = "Symbiont profile wird berechnet...".to_owned();
                return Task::perform(
                    async move {
                        let result = symbiont_rpc::request_json(
                            &host,
                            port,
                            "aether/profile",
                            serde_json::json!({ "signal": signal }),
                        )?;
                        serde_json::to_string_pretty(&result)
                            .map_err(|err| format!("Symbiont Ergebnis-Formatfehler: {err}"))
                    },
                    Message::SymbiontRpcCompleted,
                );
            }
            Message::SymbiontRazorPressed => {
                let host = self.symbiont_host.clone();
                let port = self.symbiont_port;
                let signals: Vec<String> = self
                    .symbiont_input
                    .lines()
                    .map(|line| line.trim().to_owned())
                    .filter(|line| !line.is_empty())
                    .collect();
                self.symbiont_busy = true;
                self.symbiont_result = "Symbiont razor wird berechnet...".to_owned();
                return Task::perform(
                    async move {
                        let result = symbiont_rpc::request_json(
                            &host,
                            port,
                            "aether/razor",
                            serde_json::json!({ "signals": signals }),
                        )?;
                        serde_json::to_string_pretty(&result)
                            .map_err(|err| format!("Symbiont Ergebnis-Formatfehler: {err}"))
                    },
                    Message::SymbiontRpcCompleted,
                );
            }
            Message::SymbiontSnapshotPressed => {
                let host = self.symbiont_host.clone();
                let port = self.symbiont_port;
                let signal = self.symbiont_input.clone();
                self.symbiont_busy = true;
                self.symbiont_result = "Symbiont snapshot wird gespeichert...".to_owned();
                return Task::perform(
                    async move {
                        let result = symbiont_rpc::request_json(
                            &host,
                            port,
                            "aether/snapshot",
                            serde_json::json!({ "signal": signal }),
                        )?;
                        serde_json::to_string_pretty(&result)
                            .map_err(|err| format!("Symbiont Ergebnis-Formatfehler: {err}"))
                    },
                    Message::SymbiontRpcCompleted,
                );
            }
            Message::SymbiontStatusPressed => {
                let host = self.symbiont_host.clone();
                let port = self.symbiont_port;
                self.symbiont_busy = true;
                self.symbiont_result = "Symbiont status wird geladen...".to_owned();
                return Task::perform(
                    async move {
                        let result = symbiont_rpc::request_json(
                            &host,
                            port,
                            "aether/status",
                            serde_json::json!({}),
                        )?;
                        serde_json::to_string_pretty(&result)
                            .map_err(|err| format!("Symbiont Ergebnis-Formatfehler: {err}"))
                    },
                    Message::SymbiontRpcCompleted,
                );
            }
            Message::SymbiontDecodeDnaPressed => {
                let host  = self.symbiont_host.clone();
                let port  = self.symbiont_port;
                let input = self.symbiont_input.trim().to_owned();
                self.symbiont_busy   = true;
                self.symbiont_result = "DNA-Rekonstruktion laeuft...".to_owned();
                return Task::perform(
                    async move {
                        // 64-stellige Hex-Signatur → sig-Lookup; sonst direkt als DNA
                        let params = if input.len() == 64
                            && input.chars().all(|c| c.is_ascii_hexdigit())
                        {
                            serde_json::json!({ "sig": input, "length": 256 })
                        } else {
                            serde_json::json!({ "dna": input, "length": 256 })
                        };
                        let result = symbiont_rpc::request_json(
                            &host, port, "aether/decode_dna", params,
                        )?;
                        serde_json::to_string_pretty(&result)
                            .map_err(|err| format!("Decode-DNA Formatfehler: {err}"))
                    },
                    Message::SymbiontRpcCompleted,
                );
            }
            Message::SymbiontRpcCompleted(result) => {
                self.symbiont_busy = false;
                match result {
                    Ok(pretty) => {
                        self.symbiont_result = pretty;
                        self.status_line = "Symbiont-RPC abgeschlossen.".to_owned();
                    }
                    Err(err) => {
                        self.symbiont_result = format!("Fehler: {err}");
                        self.status_line = format!("Symbiont-RPC fehlgeschlagen: {err}");
                    }
                }
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
                return window::get_latest().then(move |id_opt| {
                    if let Some(id) = id_opt {
                        window::resize(id, iced::Size::new(new_w, new_h))
                    } else {
                        Task::none()
                    }
                });
            }
            Message::LiveRenderToggle => {
                let enable = !self.live_render_mode;
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
                self.launcher_state.poll_processes();
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
                    if !self.live_render_analysis_running
                        && self.tick_counter % 8 == 0
                        && !self.live_render_last_frame.is_empty()
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
                if self.tick_counter % 60 == 0 {
                    self.poll_hybrid_state();
                }
                if self.tick_counter % 120 == 0 {
                    self.poll_backend_state();
                }
                // Poll swarm overlap contact requests every ~60 ticks (offset to avoid collision).
                if self.tick_counter % 60 == 30 {
                    self.poll_swarm_overlap_events();
                }
                // Poll Symbiont live events every ~8 ticks while the server is running
                if self.tick_counter % 8 == 3
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
                                .and_then(|v| v.as_u64())
                                .unwrap_or(since);
                            let entries: Vec<String> = result
                                .get("events")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|e| {
                                            let idx = e.get("idx")?.as_u64()?;
                                            let ts = e.get("ts")?.as_f64()?;
                                            let kind = e.get("kind")?.as_str()?;
                                            let detail = e
                                                .get("detail")
                                                .and_then(|v| v.as_str())
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
                if self.browser_surface_mode().is_none() {
                    self.browser_embed.hide();
                    return if queued_tasks.is_empty() {
                        Task::none()
                    } else {
                        Task::batch(queued_tasks)
                    };
                }
                let effective_browser_stride = self.browser_sync_stride.max(1);
                if self.tick_counter % effective_browser_stride == 0 {
                    self.sync_browser_embed();
                }
                for event in self
                    .browser_embed
                    .poll_events(self.profile_browser_poll_batch())
                {
                    match event.kind.as_str() {
                        "ready" | "bridge_ready" => {
                            self.browser_note =
                                "Eingebetteter Browser ist bereit. DuckDuckGo kann direkt geladen werden."
                                    .to_owned();
                            self.status_line = self.browser_note.clone();
                        }
                        "loaded" => {
                            if !event.url.trim().is_empty() {
                                self.browser_address = event.url.clone();
                            }
                            let title = if event.title.trim().is_empty() {
                                "Seite geladen".to_owned()
                            } else {
                                event.title.clone()
                            };
                            self.browser_note = format!(
                                "{} | {} | {}",
                                title,
                                self.browser_address,
                                if event.secure { "HTTPS" } else { "ohne HTTPS" }
                            );
                            self.status_line = self.browser_note.clone();
                        }
                        "error" | "stderr" => {
                            if !event.message.trim().is_empty() {
                                self.browser_note = format!("Browserfehler: {}", event.message);
                                self.status_line = self.browser_note.clone();
                            }
                        }
                        _ => {}
                    }
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
                        text("Razor-Signale: Mehrzeilige Eingabe im Signalfeld. Jede Zeile wird als separates strukturelles Signal analysiert, nicht als Freitext.").size(11).color(c(TEXT_D())),
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
                container(
                    text("Tipp: Zuerst Bridge starten, dann Symbiont - warte auf Status 'online' bevor Signale eingegeben werden.").size(11).color(c(WARN()))
                )
                .padding(8)
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x1A, 0x14, 0x0A))),
                    border: Border { color: Color::from_rgb8(0xD4, 0xA0, 0x42), width: 1.0, ..Default::default() },
                    ..Default::default()
                }),
                container(
                    column![
                        text(format!("RPC Endpoint: {}:{}", self.symbiont_host, self.symbiont_port))
                            .size(12)
                            .color(c(TEXT_D())),
                        text_input("Signal eingeben (mehrere Zeilen = Razor-Signale)", &self.symbiont_input)
                            .on_input(Message::SymbiontInputChanged)
                            .padding(8),
                        text("Info: Profil = ein Gesamtsignal. Razor = mehrere Zeilen (jede Zeile ein separates Signal). Snapshot speichert den aktuellen Zustand.")
                            .size(11)
                            .color(c(TEXT_D())),
                        row![
                            button(text(if self.symbiont_busy { "Profil ..." } else { "Profil" }).size(12).color(c(TEXT_H())))
                                .on_press_maybe((!self.symbiont_busy).then_some(Message::SymbiontProfilePressed))
                                .padding([8, 12])
                                .style(primary_button_style),
                            button(text(if self.symbiont_busy { "Razor ..." } else { "Razor" }).size(12).color(c(TEXT_H())))
                                .on_press_maybe((!self.symbiont_busy).then_some(Message::SymbiontRazorPressed))
                                .padding([8, 12])
                                .style(primary_button_style),
                            button(text(if self.symbiont_busy { "Snapshot ..." } else { "Snapshot" }).size(12).color(c(TEXT_H())))
                                .on_press_maybe((!self.symbiont_busy).then_some(Message::SymbiontSnapshotPressed))
                                .padding([8, 12])
                                .style(primary_button_style),
                            button(text(if self.symbiont_busy { "Status ..." } else { "Status" }).size(12).color(c(TEXT_H())))
                                .on_press_maybe((!self.symbiont_busy).then_some(Message::SymbiontStatusPressed))
                                .padding([8, 12])
                                .style(secondary_button_style),
                            button(text(if self.symbiont_busy { "Decode DNA ..." } else { "Decode DNA" }).size(12).color(c(TEXT_H())))
                                .on_press_maybe((!self.symbiont_busy).then_some(Message::SymbiontDecodeDnaPressed))
                                .padding([8, 12])
                                .style(primary_button_style),
                        ]
                        .spacing(10),
                        container(scrollable(text(self.symbiont_result.clone()).size(11).color(c(TEXT_M()))).height(Length::Fixed(160.0)))
                            .padding(8)
                            .style(panel_frame_style),
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
                    "aether-symbiont (VSCode) und symbiont_core.py sind separate Ebenen. Dieser Tab ist die zentrale Steuerflaeche im Hauptprogramm.",
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
        let swarm_state = if self.swarm_startup.node_initialized {
            format!(
                "Node bereit | nodes={} | new_packs={}",
                self.swarm_startup.node_count,
                self.swarm_startup.new_pack_count
            )
        } else {
            "Node noch nicht initialisiert".to_owned()
        };

        container(
            column![
                text("Swarm Operations").size(28).color(c(TEXT_H())),
                text("Alles rund um Anchors, P2P, Sync und Runtime-Status an einer Stelle.")
                    .size(13)
                    .color(c(TEXT_M())),
                container(text(swarm_state).size(12).color(c(TEXT_D())))
                    .padding(10)
                    .style(panel_frame_style),
                row![
                    cyber_kpi_card(
                        "Swarm Nodes",
                        format!("{}", self.swarm_startup.node_count),
                        "bootstrap",
                        Color::from_rgb8(0x3F, 0xBA, 0xC2),
                        "swarm_nodes"
                    ),
                    cyber_kpi_card(
                        "New Packs",
                        format!("{}", self.swarm_startup.new_pack_count),
                        "transport",
                        Color::from_rgb8(0x5A, 0xAE, 0x84),
                        "swarm_packs"
                    ),
                    cyber_kpi_card(
                        "Runtime",
                        self.runtime_profile_label().to_owned(),
                        "tick scheduler",
                        Color::from_rgb8(0xC7, 0xA0, 0x4A),
                        "swarm_runtime"
                    ),
                ]
                .spacing(10),
                row![
                    button(text(if self.swarm_consented { "Swarm-Teilnahme [aktiv]" } else { "Swarm aktivieren" }).size(12).color(c(TEXT_H())))
                        .on_press(Message::SwarmConsentToggled(true))
                        .padding([8, 12])
                        .style(if self.swarm_consented { primary_button_style } else { secondary_button_style }),
                    button(text(if !self.swarm_consented { "Swarm-Teilnahme [aus]" } else { "Swarm deaktivieren" }).size(12).color(c(TEXT_H())))
                        .on_press(Message::SwarmConsentToggled(false))
                        .padding([8, 12])
                        .style(if !self.swarm_consented { primary_button_style } else { secondary_button_style }),
                ]
                .spacing(10),
                container(
                    text(if self.swarm_consented {
                        "Aktiv — es werden ausschließlich SHA-256-Fingerabdrücke und aggregierte Strukturmetriken geteilt. Keine Rohdaten."
                    } else {
                        "Deaktiviert — dieser Knoten sendet keine Daten an den Swarm."
                    }).size(11).color(c(TEXT_M()))
                )
                .padding(10)
                .style(panel_frame_style),
                row![
                    button(text("Open Anchors").size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::Anchors))
                        .padding([8, 12])
                        .style(primary_button_style),
                    button(text("Open Runtime").size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::Settings))
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
                    "P2P-Anchor-Pool, swarm_sync und public_ttd_transport laufen im Backend. Dieser Tab ist dein UI-Kontrollpunkt.",
                ),
            ]
            .spacing(12),
        )
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
                    button(text("Open Browser").size(12).color(c(TEXT_H())))
                        .on_press(Message::TabSelected(Tab::Browser))
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
                text("AetherDropper: Local GUI").size(11).color(c(TEXT_D())),
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

pub fn run() -> iced::Result {
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

#[allow(dead_code)]
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
// Aether.StructureMap – legacy Canvas-Renderer (fraktaler 3D-Suchbaum)
// Kept for data generation; rendering now handled by FlowSphereScene.
// ---------------------------------------------------------------------------

/// Trägt die vorberechneten Knoten-Positionen (Theta-Winkel pro Ring).
#[allow(dead_code)]
struct StructureMapScene {
    nodes: Vec<Vec<f32>>,
}

impl canvas::Program<Message> for StructureMapScene {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        use std::f32::consts::TAU;

        let mut frame = canvas::Frame::new(renderer, bounds.size());

        // Hintergrund – tiefschwarz
        frame.fill_rectangle(
            Point::new(0.0, 0.0),
            bounds.size(),
            Color::from_rgb8(0x02, 0x04, 0x08),
        );

        if self.nodes.is_empty() {
            return vec![frame.into_geometry()];
        }

        let cx = bounds.width * 0.5;
        let cy = bounds.height * 0.5;
        let max_r = cx.min(cy) * 0.90;
        const N_RINGS: usize = 10;

        let ring_colors: [Color; N_RINGS] = [
            Color::from_rgb8(0xFF, 0x44, 0x44), // 1  Rohdaten
            Color::from_rgb8(0xAA, 0xFF, 0x00), // 2
            Color::from_rgb8(0x7F, 0xFF, 0x00), // 3
            Color::from_rgb8(0xFF, 0xD7, 0x00), // 4
            Color::from_rgb8(0xFF, 0xA5, 0x00), // 5  Mutation
            Color::from_rgb8(0xFF, 0xCC, 0x00), // 6
            Color::from_rgb8(0xFF, 0xFF, 0xFF), // 7  Ockham-Cut
            Color::from_rgb8(0x9B, 0xD4, 0xFF), // 8  Kompression
            Color::from_rgb8(0xC0, 0xE8, 0xFF), // 9  Kompression
            Color::from_rgb8(0xE0, 0xF7, 0xFF), // 10 Anker
        ];

        let polar = |theta: f32, ring_idx: usize| -> Point {
            let r = max_r * ((ring_idx + 1) as f32 / N_RINGS as f32);
            Point::new(cx + r * theta.cos(), cy + r * theta.sin())
        };

        for ring_idx in 0..N_RINGS {
            let color = ring_colors[ring_idx];
            let curr = match self.nodes.get(ring_idx) {
                Some(v) => v.clone(),
                None => continue,
            };

            // Ring-Führungskreis (schwach sichtbar)
            {
                let r = max_r * ((ring_idx + 1) as f32 / N_RINGS as f32);
                let guide = canvas::Path::circle(Point::new(cx, cy), r);
                let mut gc = color;
                gc.a = 0.07;
                frame.stroke(
                    &guide,
                    canvas::Stroke {
                        style: canvas::Style::Solid(gc),
                        width: 0.7,
                        ..canvas::Stroke::default()
                    },
                );
            }

            // Verbindungslinien zum Elternring
            if ring_idx > 0 {
                let prev = match self.nodes.get(ring_idx - 1) {
                    Some(v) => v.clone(),
                    None => vec![],
                };
                let lw: f32 = if ring_idx == 6 { 2.0 } else if ring_idx >= 7 { 1.2 } else { 0.65 };
                let alpha: f32 = if ring_idx >= 6 { 0.82 } else { 0.45 };
                let mut lc = color;
                lc.a = alpha;

                for &theta in &curr {
                    if let Some(&parent) = prev.iter().min_by(|&&a, &&b| {
                        let da = (a - theta).abs().min(TAU - (a - theta).abs());
                        let db = (b - theta).abs().min(TAU - (b - theta).abs());
                        da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
                    }) {
                        let from = polar(parent, ring_idx - 1);
                        let to   = polar(theta,  ring_idx);
                        let p = canvas::Path::new(|b| {
                            b.move_to(from);
                            b.line_to(to);
                        });
                        frame.stroke(
                            &p,
                            canvas::Stroke {
                                style: canvas::Style::Solid(lc),
                                width: lw,
                                ..canvas::Stroke::default()
                            },
                        );
                    }
                }
            }

            // Ockham-Schnittlinie (Ring 7)
            if ring_idx == 6 {
                let r = max_r * 7.0 / N_RINGS as f32;
                let arc = canvas::Path::circle(Point::new(cx, cy), r);
                let mut cut = Color::WHITE;
                cut.a = 0.22;
                frame.stroke(&arc, canvas::Stroke {
                    style: canvas::Style::Solid(cut),
                    width: 2.0,
                    ..canvas::Stroke::default()
                });
            } else if ring_idx >= 7 {
                // frame.fill(&canvas::Path::circle(pt, 2.5), color); // TODO: pt nicht definiert
            } else {
                let _sz = (4.0 - ring_idx as f32 * 0.28).max(1.2);
                // TODO: pt not defined — fill call below is incomplete
                // frame.fill(&canvas::Path::circle(pt, _sz), nc); // TODO: pt nicht definiert
            }
        }

        vec![frame.into_geometry()]
    }
}

// ── AetherLogoScene ──────────────────────────────────────────────────────────

#[allow(dead_code)]
struct AetherLogoScene;
impl canvas::Program<Message> for AetherLogoScene {
    type State = ();
    fn draw(&self, _: &(), renderer: &iced::Renderer, _: &Theme, bounds: Rectangle, _: mouse::Cursor) -> Vec<canvas::Geometry<iced::Renderer>> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let w = bounds.width;
        let h = bounds.height;
        let cx = w * 0.5;
        let cy = h * 0.5;

        let top = Point::new(cx, cy - h * 0.38);
        let bl  = Point::new(cx - w * 0.38, cy + h * 0.35);
        let br  = Point::new(cx + w * 0.38, cy + h * 0.35);
        let ml  = Point::new(cx - w * 0.18, cy + h * 0.05);
        let mr  = Point::new(cx + w * 0.18, cy + h * 0.05);

        let a_path = canvas::Path::new(|b| {
            b.move_to(bl); b.line_to(top); b.line_to(br);
        });
        frame.stroke(&a_path, canvas::Stroke {
            style: canvas::Style::Solid(Color::from_rgb8(0xFF, 0xFF, 0xFF)),
            width: 2.8,
            ..canvas::Stroke::default()
        });
        let cross = canvas::Path::new(|b| { b.move_to(ml); b.line_to(mr); });
        frame.stroke(&cross, canvas::Stroke {
            style: canvas::Style::Solid(Color::from_rgb8(0xFF, 0xFF, 0xFF)),
            width: 2.0,
            ..canvas::Stroke::default()
        });

        let nodes = [top, bl, br, Point::new(cx, cy + h * 0.10)];
        let net_color = Color::from_rgb8(0xA0, 0x70, 0xFF);
        for &n in &nodes {
            frame.fill(&canvas::Path::circle(n, 2.2), net_color);
        }
        for i in 0..nodes.len() {
            for j in (i+1)..nodes.len() {
                let mut lc = net_color; lc.a = 0.55;
                let l = canvas::Path::new(|b| { b.move_to(nodes[i]); b.line_to(nodes[j]); });
                frame.stroke(&l, canvas::Stroke { style: canvas::Style::Solid(lc), width: 0.8, ..canvas::Stroke::default() });
            }
        }
        vec![frame.into_geometry()]
    }
}

// ── Orchestration Canvas ────────────────────────────────────────────────────

#[allow(dead_code)]
struct OrchestrationScene {
    tick: u64,
    cluster_count: usize,
    analysis_running: bool,
    trust_ok: bool,
}

impl canvas::Program<Message> for OrchestrationScene {
    type State = ();
    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        frame.fill_rectangle(
            Point::new(0.0, 0.0), bounds.size(),
            Color::from_rgb8(0x04, 0x0C, 0x18),
        );

        let w = bounds.width;
        let h = bounds.height;
        let t = self.tick as f32;
        let analysis_alpha = if self.analysis_running { 0.95 } else { 0.55 };

        // Node definitions: (label, cx_frac, cy_frac, color)
        let nodes: &[(&str, f32, f32, Color)] = &[
            ("API Gateway",     0.14, 0.42, Color::from_rgb8(0x3A, 0x8A, 0xC0)),
            ("Compute Node A",  0.50, 0.18, Color::from_rgb8(0x3A, 0xC0, 0x8A)),
            ("Event Router",    0.50, 0.50, Color::from_rgb8(0x1E, 0x90, 0xFF)),
            ("Task Queue",      0.74, 0.42, Color::from_rgb8(0x3A, 0x8A, 0xC0)),
            ("Alert Handler",   0.90, 0.42, Color::from_rgb8(0xD0, 0x60, 0x60)),
            ("Database Cluster",0.50, 0.78, Color::from_rgb8(0x3A, 0x8A, 0xC0)),
        ];

        // Edges (from_idx, to_idx)
        let edges: &[(usize, usize)] = &[
            (0, 2), (2, 0), // API <-> Router
            (2, 1), (1, 2), // Router <-> Compute
            (2, 3), (3, 2), // Router <-> Queue
            (3, 4),         // Queue -> Alert
            (2, 5), (5, 2), // Router <-> DB
        ];

        let nx = |i: usize| nodes[i].1 * w;
        let ny = |i: usize| nodes[i].2 * h;

        // Draw edges with animated pulse
        for &(from, to) in edges {
            let fx = nx(from); let fy = ny(from);
            let tx = nx(to);   let ty = ny(to);
            let mut ec = nodes[from].3;
            ec.a = 0.28;
            let edge = canvas::Path::new(|b| { b.move_to(Point::new(fx, fy)); b.line_to(Point::new(tx, ty)); });
            frame.stroke(&edge, canvas::Stroke { style: canvas::Style::Solid(ec), width: 1.2, line_dash: canvas::LineDash { segments: &[6.0, 4.0], offset: 0 }, ..canvas::Stroke::default() });

            // Animated pulses along edges
            let phase = (t * 0.04 + (from + to * 3) as f32 * 0.7).rem_euclid(1.0);
            let px = fx + (tx - fx) * phase;
            let py = fy + (ty - fy) * phase;
            let mut pc = nodes[from].3; pc.a = analysis_alpha;
            frame.fill(&canvas::Path::circle(Point::new(px, py), 3.0), pc);
        }

        frame.fill_text(canvas::Text {
            content: format!("Nodes {} | Analysis {}", self.cluster_count, if self.analysis_running { "active" } else { "idle" }),
            position: Point::new(16.0, h - 16.0),
            color: Color::from_rgb8(0x70, 0x90, 0xA8),
            size: iced::Pixels(10.0),
            horizontal_alignment: iced::alignment::Horizontal::Left,
            vertical_alignment: iced::alignment::Vertical::Center,
            ..canvas::Text::default()
        });

        // Draw nodes
        for (label, fx, fy, col) in nodes {
            let cx = fx * w; let cy = fy * h;
            let is_router = *label == "Event Router";
            let r = if is_router { 42.0f32 } else { 34.0f32 };
            let rh = r * 0.55;

            if is_router {
                // Roboter-Kopf statt Box
                let rw = 28.0f32; let robot_h = 22.0f32;
                let mut hbg = *col; hbg.a = 0.14;
                let head_rect = canvas::Path::new(|b| {
                    b.move_to(Point::new(cx - rw, cy - robot_h - 8.0));
                    b.line_to(Point::new(cx + rw, cy - robot_h - 8.0));
                    b.line_to(Point::new(cx + rw, cy + robot_h - 8.0));
                    b.line_to(Point::new(cx - rw, cy + robot_h - 8.0));
                    b.close();
                });
                frame.fill(&head_rect, hbg);
                frame.stroke(&head_rect, canvas::Stroke {
                    style: canvas::Style::Solid(*col), width: 2.0, ..canvas::Stroke::default()
                });
                // Antenne
                frame.stroke(&canvas::Path::new(|b| {
                    b.move_to(Point::new(cx, cy - robot_h - 8.0));
                    b.line_to(Point::new(cx, cy - robot_h - 18.0));
                }), canvas::Stroke { style: canvas::Style::Solid(*col), width: 1.5, ..canvas::Stroke::default() });
                frame.fill(&canvas::Path::circle(Point::new(cx, cy - robot_h - 18.0), 2.5), *col);
                // Augen
                let blink = (t * 1.0 % 120.0) > 116.0;
                let er = if blink { 1.0 } else { 3.5 };
                let ecy = cy - 8.0 - robot_h * 0.12;
                let cyan_c = Color::from_rgb8(0x00, 0xC8, 0xD4);
                for &ex in &[cx - rw * 0.42, cx + rw * 0.42] {
                    frame.fill(&canvas::Path::circle(Point::new(ex, ecy), er), cyan_c);
                }
                // Label
                frame.fill_text(canvas::Text {
                    content: "Router".to_string(),
                    position: Point::new(cx, cy + robot_h - 4.0),
                    color: Color::from_rgb8(0xCC, 0xC6, 0xF4),
                    size: iced::Pixels(9.0),
                    horizontal_alignment: iced::alignment::Horizontal::Center,
                    vertical_alignment: iced::alignment::Vertical::Center,
                    ..canvas::Text::default()
                });
                // Glow-Ring
                let glow_r = rw * 1.5 + 3.0 * (t * 0.06).sin();
                let mut gc = *col; gc.a = 0.07;
                frame.stroke(&canvas::Path::circle(Point::new(cx, cy - 8.0), glow_r),
                    canvas::Stroke { style: canvas::Style::Solid(gc), width: 3.0, ..canvas::Stroke::default() });
            } else {
            // Box fill
            let mut fc = *col; fc.a = 0.18;
            let rect = canvas::Path::new(|b| {
                b.move_to(Point::new(cx - r, cy - rh));
                b.line_to(Point::new(cx + r, cy - rh));
                b.line_to(Point::new(cx + r, cy + rh));
                b.line_to(Point::new(cx - r, cy + rh));
                b.close();
            });
            frame.fill(&rect, fc);

            // Box border
            let mut bc = *col; bc.a = 0.65;
            frame.stroke(&rect, canvas::Stroke { style: canvas::Style::Solid(bc), width: 1.2, ..canvas::Stroke::default() });

            // Label
            frame.fill_text(canvas::Text {
                content: label.to_string(),
                position: Point::new(cx, cy),
                color: Color::from_rgb8(0xCC, 0xC6, 0xF4),
                size: iced::Pixels(10.0),
                horizontal_alignment: iced::alignment::Horizontal::Center,
                vertical_alignment: iced::alignment::Vertical::Center,
                ..canvas::Text::default()
            });
            }
        }

        // Status dot top-left
        let dot_col = if self.trust_ok {
            Color::from_rgb8(0x4C, 0xD9, 0x6E)
        } else {
            Color::from_rgb8(0xD9, 0x80, 0x40)
        };
        frame.fill(&canvas::Path::circle(Point::new(10.0, 10.0), 4.5), dot_col);

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

struct DotScene { color: Color }
impl canvas::Program<Message> for DotScene {
    type State = ();
    fn draw(&self, _s: &(), renderer: &iced::Renderer, _t: &Theme, bounds: Rectangle, _c: mouse::Cursor) -> Vec<canvas::Geometry<iced::Renderer>> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let r = bounds.width.min(bounds.height) * 0.45;
        frame.fill(&canvas::Path::circle(Point::new(bounds.width * 0.5, bounds.height * 0.5), r), self.color);
        vec![frame.into_geometry()]
    }
}

#[allow(dead_code)]
struct ThreatTrendScene {
    tick: u64,
    reveal: f32,
}

impl canvas::Program<Message> for ThreatTrendScene {
    type State = ();
    fn draw(&self, _s: &(), renderer: &iced::Renderer, _t: &Theme, bounds: Rectangle, _c: mouse::Cursor) -> Vec<canvas::Geometry<iced::Renderer>> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let w = bounds.width;
        let h = bounds.height;
        let t = self.tick as f32;
        frame.fill_rectangle(Point::new(0.0, 0.0), bounds.size(), Color::from_rgb8(0x0C, 0x0B, 0x12));
        let points = 60usize;
        let reveal_count = ((points as f32) * self.reveal.clamp(0.02, 1.0)) as usize;
        let mut last: Option<Point> = None;
        for i in 0..reveal_count.max(2) {
            let x = (i as f32 / (points - 1) as f32) * (w - 18.0) + 9.0;
            let yv = 0.52 + 0.18 * ((i as f32 * 0.31 + t * 0.03).sin()) + 0.06 * ((i as f32 * 0.91 + t * 0.02).cos());
            let y = (1.0 - yv.clamp(0.08, 0.92)) * (h - 20.0) + 10.0;
            let p = Point::new(x, y);
            if let Some(lp) = last {
                let seg = canvas::Path::new(|b| {
                    b.move_to(lp);
                    b.line_to(p);
                });
                frame.stroke(&seg, canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(0.72, 0.30, 1.0, 0.85)),
                    width: 2.0,
                    ..canvas::Stroke::default()
                });
            }
            last = Some(p);
        }
        vec![frame.into_geometry()]
    }
}

#[allow(dead_code)]
struct RiskGaugeScene {
    score: u32,
    pulse: f32,
    flash: f32,
}

impl canvas::Program<Message> for RiskGaugeScene {
    type State = ();
    fn draw(&self, _s: &(), renderer: &iced::Renderer, _t: &Theme, bounds: Rectangle, _c: mouse::Cursor) -> Vec<canvas::Geometry<iced::Renderer>> {
        use std::f32::consts::PI;
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let cxy = Point::new(bounds.width * 0.5, bounds.height * 0.56);
        let r = bounds.width.min(bounds.height) * 0.34;
        let ratio = (self.score as f32 / 1000.0).clamp(0.0, 1.0);
        let start = PI * 0.84;
        let end = PI * 2.16;
        let span = end - start;
        let track = canvas::Path::new(|b| {
            b.arc(canvas::path::Arc { center: cxy, radius: r, start_angle: iced::Radians(start), end_angle: iced::Radians(end) });
        });
        frame.stroke(&track, canvas::Stroke { style: canvas::Style::Solid(Color::from_rgba(0.18, 0.25, 0.35, 0.9)), width: 14.0, ..canvas::Stroke::default() });
        let val = canvas::Path::new(|b| {
            b.arc(canvas::path::Arc { center: cxy, radius: r, start_angle: iced::Radians(start), end_angle: iced::Radians(start + span * ratio) });
        });
        frame.stroke(&val, canvas::Stroke {
            style: canvas::Style::Solid(Color::from_rgba(1.0, 0.48 + 0.30 * self.flash, 0.26, 0.95)),
            width: 14.0 * self.pulse,
            ..canvas::Stroke::default()
        });
        frame.fill_text(canvas::Text {
            content: format!("{}", self.score),
            position: Point::new(cxy.x, cxy.y),
            color: Color::from_rgb8(0xF8, 0xFD, 0xFF),
            size: iced::Pixels(28.0),
            horizontal_alignment: iced::alignment::Horizontal::Center,
            vertical_alignment: iced::alignment::Vertical::Center,
            ..canvas::Text::default()
        });
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

#[allow(dead_code)]
struct CyberPaneGraphScene {
    tick: u64,
    pulse: f32,
    slide: f32,
}

impl canvas::Program<Message> for CyberPaneGraphScene {
    type State = ();
    fn draw(&self, _s: &(), renderer: &iced::Renderer, _t: &Theme, bounds: Rectangle, _c: mouse::Cursor) -> Vec<canvas::Geometry<iced::Renderer>> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        frame.fill_rectangle(Point::new(0.0, 0.0), bounds.size(), Color::from_rgb8(0x0B, 0x12, 0x18));
        let t = self.tick as f32;
        let panes = [
            (0.12f32, 0.22f32, 0.24f32, 0.52f32, Color::from_rgba(0.18, 0.33, 0.38, 0.34), "Background"),
            (0.42f32, 0.14f32, 0.22f32, 0.66f32, Color::from_rgba(0.25, 0.45, 0.48, 0.34), "Mid"),
            (0.70f32, 0.24f32, 0.18f32, 0.50f32, Color::from_rgba(0.35, 0.38, 0.24, 0.30), "Overlay"),
        ];
        let mut centers: Vec<Point> = Vec::with_capacity(panes.len());
        for (idx, (x, y, w, h, color, label)) in panes.iter().enumerate() {
            let px = bounds.width * x + (1.0 - self.slide) * 22.0;
            let py = bounds.height * y;
            let pw = bounds.width * w;
            let ph = bounds.height * h;
            let pane = canvas::Path::rectangle(Point::new(px, py), iced::Size::new(pw, ph));
            frame.fill(&pane, *color);
            frame.stroke(&pane, canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.25, 0.60, 0.64, 0.55)),
                width: 1.0 + 0.4 * self.pulse,
                ..canvas::Stroke::default()
            });
            let cx = px + pw * 0.5;
            let cy = py + ph * 0.5;
            centers.push(Point::new(cx, cy));
            frame.fill_text(canvas::Text {
                content: format!("{} / {}", label, idx + 1),
                position: Point::new(cx, py + 18.0),
                color: Color::from_rgb8(0xA7, 0xB0, 0xB7),
                size: iced::Pixels(11.0),
                horizontal_alignment: iced::alignment::Horizontal::Center,
                vertical_alignment: iced::alignment::Vertical::Center,
                ..canvas::Text::default()
            });
            let pulse_r = 4.0 + 2.5 * (t * 0.09 + idx as f32).sin().abs();
            frame.fill(&canvas::Path::circle(Point::new(cx, cy), pulse_r), Color::from_rgba(0.25, 0.73, 0.76, 0.78));
        }
        for i in 0..centers.len().saturating_sub(1) {
            let edge = canvas::Path::new(|b| {
                b.move_to(centers[i]);
                b.line_to(centers[i + 1]);
            });
            frame.stroke(&edge, canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.25, 0.60, 0.64, 0.55)),
                width: 1.0,
                ..canvas::Stroke::default()
            });
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

#[allow(dead_code)]
fn sys_metric_card(label: &str, value: String, fill: f32, accent: Color) -> Element<'static, Message> {
    container(
        Column::new()
            .push(text(label.to_owned())
                .size(11)
                .color(Color::from_rgb8(0x4E, 0x4A, 0x76)))
            .push(text(value)
                .size(22)
                .color(accent))
            .push(
                container(
                    container(iced::widget::Space::new(Length::Fill, Length::Fixed(3.0)))
                        .style(move |_: &Theme| container::Style {
                            background: Some(Background::Color(accent)),
                            border: Border { radius: 2.0.into(), ..Default::default() },
                            ..Default::default()
                        })
                        .width(Length::FillPortion((fill.clamp(0.0, 1.0) * 100.0) as u16))
                )
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x12, 0x22, 0x34))),
                    border: Border { radius: 2.0.into(), ..Default::default() },
                    ..Default::default()
                })
                .width(Length::Fill)
                .height(Length::Fixed(3.0))
            )
            .spacing(8)
    )
    .style(accent_card_style)
    .padding([14, 18])
    .width(Length::Fill)
    .into()
}

#[allow(dead_code)]
fn event_row<'a>(time: &str, tag: &str, msg: &str, tag_color: Color) -> Element<'a, Message> {
    container(
        Row::new()
            .push(text(time.to_owned()).size(11).color(Color::from_rgb8(0x62, 0x5E, 0x90)))
            .push(
                container(text(tag.to_owned()).size(11).color(tag_color))
                    .padding([2, 6])
                    .style(move |_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgba(tag_color.r * 0.15, tag_color.g * 0.15, tag_color.b * 0.15, 1.0))),
                        border: Border { color: tag_color, width: 1.0, radius: 4.0.into() },
                        ..Default::default()
                    })
            )
            .push(text(msg.to_owned()).size(12).color(Color::from_rgb8(0xA8, 0xC4, 0xD8)))
            .spacing(8)
            .align_y(iced::Alignment::Center),
    )
    .padding([6, 0])
    .width(Length::Fill)
    .into()
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

#[allow(dead_code)]
fn alert_row<'a>(icon: &str, icon_color: Color, title: &str, sub: &str) -> Element<'a, Message> {
    container(
        row![
            text(icon.to_owned()).size(14).color(icon_color),
            column![
                text(title.to_owned()).size(13).color(Color::from_rgb8(0xCC, 0xC6, 0xF4)),
                text(sub.to_owned()).size(11).color(Color::from_rgb8(0x70, 0x90, 0xA8)),
            ]
            .spacing(2),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center),
    )
    .style(move |_: &Theme| container::Style {
        background: Some(Background::Color(Color::from_rgba(icon_color.r * 0.10, icon_color.g * 0.10, icon_color.b * 0.10, 1.0))),
        border: Border { color: Color::from_rgba(icon_color.r, icon_color.g, icon_color.b, 0.5), width: 1.0, radius: 6.0.into() },
        ..Default::default()
    })
    .padding([8, 12])
    .width(Length::Fill)
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

/// Erzeugt eine menschenlesbare Erklaerungszeile aus den Analyse-Metriken.
#[allow(dead_code)]
fn plain_note_from_metrics(
    trust_score: f32,
    anchor_count: u32,
    compression_gain: f32,
    suspicious: bool,
    eicar_hit: bool,
    lossless: bool,
) -> String {
    if eicar_hit {
        return "Bekanntes Testmuster fuer Schadsoftware gefunden \u{2014} Datei wurde blockiert.".to_owned();
    }
    if suspicious && trust_score < 0.35 {
        return "Diese Datei verhaelt sich anders als erwartet und wurde zur Pruefung zurueckgestellt.".to_owned();
    }
    if suspicious {
        return "Diese Datei enthaelt ungewoehnliche Muster \u{2014} sie wird beobachtet aber nicht blockiert.".to_owned();
    }
    if trust_score >= 0.80 && lossless {
        return format!(
            "Gut verstandene Datei \u{2014} {} strukturelle Muster erkannt, verlustfrei rekonstruierbar.",
            anchor_count
        );
    }
    if trust_score >= 0.60 {
        return format!(
            "Datei weitgehend verstanden \u{2014} {} Muster gefunden, {:.0}% kompakter als das Original.",
            anchor_count, compression_gain
        );
    }
    if anchor_count == 0 {
        return "Keine bekannten Strukturmuster gefunden \u{2014} Datei ist fuer das System neu.".to_owned();
    }
    format!(
        "Datei teilweise analysiert \u{2014} {} Muster gefunden, wird mit der Zeit besser verstanden.",
        anchor_count
    )
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
        size_bytes,
        entropy,
        h_lambda: (entropy * drift * (1.0 - symmetry + 0.1)).clamp(0.0, 8.0),
        symmetry,
        periodicity: 0.0,
        zipf_alpha: 0.0,
        benford_score: 0.0,
        katz_dimension: 1.0,
        sce_score: symmetry.clamp(0.0, 1.0),
        bayes_confidence: symmetry.clamp(0.0, 1.0),
        trust_score: (0.65 * symmetry + 0.35 * (1.0 - drift).clamp(0.0, 1.0)).clamp(0.0, 1.0),
        noether_consistency: (1.0 - drift).clamp(0.0, 1.0),
        delta_ratio: drift.clamp(0.0, 1.0),
        changed_bytes: size_bytes,
        anomaly_flags,
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

async fn analyze_file_for_register(
    path: PathBuf,
    username: String,
    _data_key: Option<DataKey>,
) -> Result<FileAnalysisResult, String> {
    use std::f32::consts::TAU;
    use std::process::Command;

    let bytes = fs::read(&path).map_err(|err| format!("Datei konnte nicht gelesen werden: {err}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|err| format!("Metadaten konnten nicht gelesen werden: {err}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unbekannt")
        .to_owned();
    let source_kind = detect_source_kind(&path, &bytes);

    let python_output = Command::new("python")
        .arg("-c")
        .arg(
            "import json,sys; from pathlib import Path; from aether_pipeline import AetherPipeline; print(json.dumps(AetherPipeline().process(Path(sys.argv[1])), ensure_ascii=True))",
        )
        .arg(path.to_string_lossy().to_string())
        .output();

    let parsed = match python_output {
        Ok(output) if output.status.success() => {
            let raw = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            serde_json::from_str::<serde_json::Value>(&raw)
                .map_err(|err| format!("Pipeline-JSON konnte nicht gelesen werden: {err}"))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            Err(format!("Python-Pipeline fehlgeschlagen: {}", stderr))
        }
        Err(err) => Err(format!("Python konnte nicht gestartet werden: {err}")),
    };

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
                "Quelle: {}\nFallback-Analyse lokal aktiv\n{}",
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
        "Quelle: {}\nVerdichtung: {:.2}% Gewinn\nSCE: {:.1}% | Trust {:.1}% | H_lambda {:.2}",
        source_kind,
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
    })
}

async fn analyze_live_signal_for_shell(
    raw: Vec<u8>,
    previous_signal: Vec<u8>,
    tick: u64,
) -> Result<LiveRenderAnalysisResult, String> {
    use std::process::Command;

    let raw_b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_slice());
    let previous_b64 = if previous_signal.is_empty() {
        String::new()
    } else {
        base64::engine::general_purpose::STANDARD.encode(previous_signal.as_slice())
    };
    let source_label = format!("live_render:{tick}");
    let python_output = Command::new("python")
        .arg("-c")
        .arg(
            "import base64,json,sys; from aether_pipeline import AetherPipeline; raw=base64.b64decode(sys.argv[1]); prev=base64.b64decode(sys.argv[2]) if sys.argv[2] else None; print(json.dumps(AetherPipeline().process_live_signal(raw, source_label=sys.argv[3], previous_signal=prev), ensure_ascii=True))",
        )
        .arg(raw_b64)
        .arg(previous_b64)
        .arg(source_label)
        .output();

    let result = match python_output {
        Ok(output) if output.status.success() => {
            let raw = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            serde_json::from_str::<serde_json::Value>(&raw)
                .map_err(|err| format!("Live-Render JSON konnte nicht gelesen werden: {err}"))?
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(format!("Live-Render Python-Pipeline fehlgeschlagen: {}", stderr));
        }
        Err(err) => {
            return Err(format!("Python konnte fuer Live-Render nicht gestartet werden: {err}"));
        }
    };

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
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f32 / total;
            -(probability * probability.log2())
        })
        .sum()
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
fn is_text_like_file(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "txt"
            | "md"
            | "json"
            | "toml"
            | "yaml"
            | "yml"
            | "rs"
            | "py"
            | "js"
            | "ts"
            | "html"
            | "css"
            | "xml"
            | "csv"
            | "ini"
            | "log"
    )
}
// END impl AetherIcedShell


