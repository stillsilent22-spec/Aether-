use crate::aef::{
    AefEncoder, AefInspector, AefProjection, AefReport, EnginePipeline, SignalType, VaultStore,
};
use crate::auth::{AuthStore, UserRecord};
use crate::browser::{
    BrowserInspector, BrowserProbePolicy, BrowserProbeResult, BrowserSearchContext,
};
use crate::bus_ipc;
use crate::chat_sync::{ChatRelayClient, ChatRelayConfig, ChatRelayEnvelope, ChatRelayStateStore};
use crate::gfx::AetherGfx;
use crate::inter_layer_bus::{BusEvent, BusPublisher, InterLayerBus, PackInstalledEvent};
use crate::offline_cache::{CacheTarget, OfflineCacheManager, OfflinePrepRequest};
use crate::pack::{AutoPackGenerator, PackManager, PackRegistry, ShanwayPackAdvisor, UsageProfile};
use crate::public_ttd::{
    pseudonymous_network_identity, validate_public_ttd_candidate, PublicTtdCandidateValidation,
    PublicTtdMetrics, PublicTtdPoolStore, PublicTtdSubmission, PublicTtdTransport,
};
use crate::shanway::{
    render_reply as render_shanway_reply, ShanwayBrowserContext, ShanwayInput,
    ShanwayObserverContext, ShanwayPackHint,
};
use crate::state::{ChatMessage, RegisterEntry, StateStore};
use crate::theory_of_mind::{
    ComprehensionDetector, ComprehensionSignal, MindModelEngine, ObserverModelScope,
    ProcessedSignal, ToMOutputAdapter,
};
use crate::vault_access::VaultAccessLayer;
use crate::workflow_anchor::WorkflowSignalCollector;
use chrono::Utc;
use eframe::egui::{
    self, Align2, Color32, ColorImage, FontId, Pos2, Rect, RichText, Sense, Stroke, TextEdit,
    TextureHandle, Vec2,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use tokio::runtime::Builder;
use tokio::sync::broadcast::{
    error::{RecvError, TryRecvError},
    Receiver,
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopTab {
    Analyse,
    Struktur,
    Browser,
    Chats,
    Register,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatTab {
    Private,
    Group,
    Shanway,
}

#[derive(Debug, Clone)]
enum ConsentAction {
    BrowserProbe { url: String },
    BrowserSearch { query: String },
    ShareStableTtd { signed: bool },
    SyncPublicTtd,
    ChatRelayPublishBatch { envelopes: Vec<QueuedRelayEnvelope> },
    ChatRelayFetch,
}

#[derive(Debug, Clone)]
struct ConsentDialogState {
    title: String,
    body: String,
    action: ConsentAction,
}

#[derive(Debug, Clone)]
struct QueuedRelayEnvelope {
    room_kind: String,
    room_name: String,
    author: String,
    body: String,
}

#[derive(Debug, Clone)]
struct ProcessedFile {
    file_name: String,
    full_path: String,
    fingerprint_hash: String,
    source_kind: String,
    original_size: u64,
    delta_size: u64,
    compression_gain_percent: f32,
    entropy: f32,
    symmetry: f32,
    drift: f32,
    anchor_summary: String,
    process_summary: String,
    preview_note: String,
    excerpt: String,
}

#[derive(Debug, Clone, Copy)]
struct VisualizationMetrics {
    entropy_norm: f32,
    symmetry: f32,
    drift_norm: f32,
    compression_gain: f32,
    residual_ratio: f32,
    coherence: f32,
    trust: f32,
    hit_rate: f32,
    coverage: f32,
    anchor_density: f32,
    projection_gain: f32,
    resonance: f32,
    godel_zone: f32,
    network_pressure: f32,
}

pub struct AetherRustShell {
    auth_store: AuthStore,
    state_store: StateStore,
    current_user: Option<UserRecord>,
    login_username: String,
    login_password: String,
    status_line: String,
    activity_log: Vec<String>,
    top_tab: TopTab,
    chat_tab: ChatTab,
    browser_address: String,
    browser_note: String,
    browser_probe: Option<BrowserProbeResult>,
    browser_search_context: Option<BrowserSearchContext>,
    browser_probe_policy: BrowserProbePolicy,
    preview_texture: Option<TextureHandle>,
    current_file: Option<ProcessedFile>,
    last_aef_report: Option<AefReport>,
    last_aef_projection: Option<AefProjection>,
    aef_vault: Arc<RwLock<VaultStore>>,
    aef_engine: Arc<EnginePipeline>,
    selected_register_id: Option<u64>,
    selected_private_partner: String,
    private_partner_input: String,
    private_message_input: String,
    selected_group_name: String,
    group_name_input: String,
    group_message_input: String,
    shanway_message_input: String,
    last_drop_token: Option<String>,
    observer_id: Uuid,
    mind_model: MindModelEngine,
    vault_access: Arc<VaultAccessLayer>,
    pack_registry: Arc<RwLock<PackRegistry>>,
    pack_manager: PackManager,
    pack_advisor: ShanwayPackAdvisor,
    pack_generator: AutoPackGenerator,
    offline_cache_manager: OfflineCacheManager,
    workflow_collector: WorkflowSignalCollector,
    gfx: AetherGfx,
    bus_publisher: BusPublisher,
    bus_receiver: Receiver<BusEvent>,
    bus_drain_handle: Option<JoinHandle<()>>,
    bus_publish_offset: u64,
    public_ttd_pool: PublicTtdPoolStore,
    public_ttd_transport: PublicTtdTransport,
    chat_relay_store: ChatRelayStateStore,
    chat_relay_client: ChatRelayClient,
    chat_relay_config: ChatRelayConfig,
    chat_relay_base_url_input: String,
    chat_relay_secret_input: String,
    chat_relay_node_id_input: String,
    relay_status_line: String,
    consent_dialog: Option<ConsentDialogState>,
}

impl AetherRustShell {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_aether_theme(&cc.egui_ctx);
        let aef_vault = Arc::new(RwLock::new(load_local_vault_store()));
        let aef_engine = Arc::new(EnginePipeline::new());
        let observer_id = Uuid::new_v4();
        let mut mind_model = MindModelEngine::new(ObserverModelScope::SessionOnly);
        mind_model.ensure_observer(observer_id);
        let inter_layer_bus = InterLayerBus::new(128);
        let bus_publisher = inter_layer_bus.publisher();
        let bus_receiver = inter_layer_bus.subscriber();
        let mut background_receiver = inter_layer_bus.subscriber();
        let _ = bus_ipc::ensure_transport_dir();
        let bus_drain_handle = std::thread::Builder::new()
            .name("aether-bus-drain".to_owned())
            .spawn(move || loop {
                match background_receiver.blocking_recv() {
                    Ok(event) => {
                        let _ = bus_ipc::append_event(&event);
                    }
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                }
            })
            .ok();
        let pack_registry = Arc::new(RwLock::new(
            PackRegistry::load_default().unwrap_or(PackRegistry {
                index_url: "github-releases://stillsilent22-spec/Aether-/anchor-packs".to_owned(),
                local_cache: PathBuf::from("data")
                    .join("rust_shell")
                    .join("packs")
                    .join("pack_registry.json"),
                last_updated: 0,
                entries: Vec::new(),
            }),
        ));
        let vault_access = Arc::new(VaultAccessLayer::new(
            Arc::clone(&aef_vault),
            Arc::clone(&aef_engine),
        ));
        let pack_manager = PackManager::new(Arc::clone(&vault_access), Arc::clone(&pack_registry));
        let pack_advisor =
            ShanwayPackAdvisor::with_bus(Arc::clone(&pack_registry), bus_publisher.clone());
        let pack_generator = AutoPackGenerator::new(Arc::clone(&vault_access));
        let offline_cache_manager = OfflineCacheManager::new(
            Arc::clone(&vault_access),
            PathBuf::from("data")
                .join("rust_shell")
                .join("offline_cache"),
            bus_publisher.clone(),
        );
        let workflow_collector =
            WorkflowSignalCollector::new(Arc::clone(&vault_access), bus_publisher.clone());
        let gfx = AetherGfx::new_auto(Arc::clone(&vault_access), bus_publisher.clone());
        let public_ttd_pool = PublicTtdPoolStore::new_default();
        let public_ttd_transport = PublicTtdTransport::new_default();
        let chat_relay_store = ChatRelayStateStore::new_default();
        let chat_relay_config = ChatRelayStateStore::load_default().unwrap_or_default();
        let chat_relay_client = ChatRelayClient::new(6.0);
        let relay_status_line = if chat_relay_config.base_url.trim().is_empty()
            || chat_relay_config.shared_secret.trim().is_empty()
        {
            "Chat-Relay bleibt lokal / fail-closed, bis URL und Secret gesetzt sind.".to_owned()
        } else {
            format!(
                "Chat-Relay bereit: {} @ {}",
                chat_relay_config.node_id, chat_relay_config.base_url
            )
        };
        Self {
            auth_store: AuthStore::load_default(),
            state_store: StateStore::load_default(),
            current_user: None,
            login_username: String::new(),
            login_password: String::new(),
            status_line: "Bitte anmelden oder registrieren.".to_owned(),
            activity_log: vec!["Rust-Shell bereit. Dateien kommen nur per Drag and Drop herein.".to_owned()],
            top_tab: TopTab::Analyse,
            chat_tab: ChatTab::Shanway,
            browser_address: "https://".to_owned(),
            browser_note: "Browser-Probe arbeitet lokal und fail-closed. Netzschritte laufen nur nach explizitem Consent.".to_owned(),
            browser_probe: None,
            browser_search_context: None,
            browser_probe_policy: BrowserProbePolicy::default(),
            preview_texture: None,
            current_file: None,
            last_aef_report: None,
            last_aef_projection: None,
            aef_vault,
            aef_engine,
            selected_register_id: None,
            selected_private_partner: "Kontakt".to_owned(),
            private_partner_input: String::new(),
            private_message_input: String::new(),
            selected_group_name: "Team".to_owned(),
            group_name_input: String::new(),
            group_message_input: String::new(),
            shanway_message_input: String::new(),
            last_drop_token: None,
            observer_id,
            mind_model,
            vault_access,
            pack_registry,
            pack_manager,
            pack_advisor,
            pack_generator,
            offline_cache_manager,
            workflow_collector,
            gfx,
            bus_publisher,
            bus_receiver,
            bus_drain_handle,
            bus_publish_offset: 0,
            public_ttd_pool,
            public_ttd_transport,
            chat_relay_store,
            chat_relay_client,
            chat_relay_config: chat_relay_config.clone(),
            chat_relay_base_url_input: chat_relay_config.base_url.clone(),
            chat_relay_secret_input: chat_relay_config.shared_secret.clone(),
            chat_relay_node_id_input: chat_relay_config.node_id.clone(),
            relay_status_line,
            consent_dialog: None,
        }
    }

    fn current_username(&self) -> Option<String> {
        self.current_user.as_ref().map(|user| user.username.clone())
    }

    fn encode_aef_for_path(&self, path: &Path) -> Result<AefReport, String> {
        let output_path = aef_output_path(path);
        let encoder = AefEncoder::new(Arc::clone(&self.aef_vault), Arc::clone(&self.aef_engine));
        encoder
            .encode_sync(path, &output_path)
            .map_err(|err| format!("AEF-Encoding fehlgeschlagen: {err}"))?;
        AefInspector::inspect(&output_path)
            .map_err(|err| format!("AEF-Inspektion fehlgeschlagen: {err}"))
    }

    fn refresh_projection_for_path(&mut self, path: &Path) {
        let output_path = aef_output_path(path);
        let projection = self.aef_vault.read().ok().and_then(|vault| {
            let projected_vault_size = vault.entry_count().saturating_mul(2).max(32);
            AefInspector::project_future_compression_sync(
                &output_path,
                &vault,
                projected_vault_size,
            )
            .ok()
        });
        self.last_aef_projection = projection;
    }

    fn current_shanway_input(&mut self) -> Option<ShanwayInput> {
        let synthetic_browser_file = self.current_file.is_none() && self.browser_probe.is_some();
        let file = if let Some(file) = self.current_file.as_ref() {
            file.clone()
        } else {
            build_browser_processed_file(self.browser_probe.as_ref()?)
        };
        let signal = build_processed_signal(&file);
        let observer_delta = self
            .mind_model
            .calculate_observer_delta(&signal, self.observer_id);
        let usage_profile = build_usage_profile(&file, self.current_hit_rate());
        let pack_hints = self
            .pack_advisor
            .evaluate_and_recommend(&usage_profile)
            .into_iter()
            .take(2)
            .map(|hint| ShanwayPackHint {
                title: hint.title,
                message: hint.message,
                estimated_hit_rate_improvement: hint.estimated_hit_rate_improvement,
                estimated_compression_improvement: hint.estimated_compression_improvement,
            })
            .collect::<Vec<_>>();
        let browser_context = self
            .browser_probe
            .as_ref()
            .map(|probe| ShanwayBrowserContext {
                url: probe.final_url.clone(),
                risk_label: probe.risk_label.clone(),
                risk_score: probe.risk_score,
                reasons: probe.risk_reasons.clone(),
                frontend_summary: probe.frontend_summary.clone(),
                backend_summary: probe.backend_summary.clone(),
                search_context_summary: self
                    .browser_search_context
                    .as_ref()
                    .map(|context| trimmed_at_boundary(&context.summary, 240))
                    .unwrap_or_default(),
            });
        Some(ShanwayInput {
            file_name: file.file_name,
            file_type: if synthetic_browser_file {
                format!("browser_{}", file.source_kind)
            } else {
                file.source_kind
            },
            entropy_mean: file.entropy,
            knowledge_ratio: (1.0 - file.drift / 255.0).clamp(0.0, 1.0),
            symmetry_gini: (1.0 - file.symmetry).clamp(0.0, 1.0),
            delta_paths: ((file.drift / 8.0).round() as i32).max(1) as u32,
            bayes_priors: format!(
                "symmetry={:.3}, entropy={:.3}, gain={:.3}",
                file.symmetry,
                file.entropy,
                (file.compression_gain_percent / 100.0).clamp(0.0, 1.0)
            ),
            residual_ratio: (file.delta_size as f32 / file.original_size.max(1) as f32)
                .clamp(0.0, 1.0),
            observer_mutual_info: (file.symmetry * (1.0 - (file.drift / 255.0).clamp(0.0, 1.0)))
                .clamp(0.0, 1.0),
            h_lambda: (file.entropy * (1.0 - file.symmetry).clamp(0.0, 1.0)).max(0.0),
            boundary: if file.symmetry < 0.58 {
                "GOEDEL_LIMIT".to_owned()
            } else if file.symmetry < 0.76 {
                "STRUCTURAL_HYPOTHESIS".to_owned()
            } else {
                "RECONSTRUCTABLE".to_owned()
            },
            anchor_summary: file.anchor_summary,
            process_summary: file.process_summary,
            observer_context: Some(ShanwayObserverContext {
                o1_knowledge: observer_delta.o1_knowledge,
                o2_estimated_knowledge: observer_delta.o2_estimated_knowledge,
                delta: observer_delta.delta,
                confidence: observer_delta.confidence,
                recommended_depth: observer_delta.recommended_depth,
                bridge_anchor_count: observer_delta.recommended_anchors.len(),
            }),
            pack_hints,
            browser_context,
            public_ttd_status: Some(self.public_ttd_pool.summary_line()),
        })
    }

    fn current_hit_rate(&self) -> f32 {
        self.vault_access.current_hit_rate().unwrap_or_else(|_| {
            let count = self
                .aef_vault
                .read()
                .map(|vault| vault.entry_count() as f32)
                .unwrap_or(0.0);
            (count / (count + 24.0)).clamp(0.0, 1.0)
        })
    }

    fn current_usage_profile(&self) -> Option<UsageProfile> {
        self.current_file
            .as_ref()
            .map(|file| build_usage_profile(file, self.current_hit_rate()))
    }

    fn current_domain_key(&self) -> Option<String> {
        self.current_file
            .as_ref()
            .map(|file| domain_from_source_kind(&file.source_kind))
    }

    fn active_visualization_file(&self) -> Option<ProcessedFile> {
        self.current_file.as_ref().cloned().or_else(|| {
            self.browser_probe
                .as_ref()
                .map(build_browser_processed_file)
        })
    }

    fn current_visualization_metrics(&self) -> Option<VisualizationMetrics> {
        let file = self.active_visualization_file()?;
        let residual_ratio =
            (file.delta_size as f32 / file.original_size.max(1) as f32).clamp(0.0, 1.0);
        let drift_norm = (file.drift / 255.0).clamp(0.0, 1.0);
        let entropy_norm = (file.entropy / 8.0).clamp(0.0, 1.0);
        let hit_rate = self.current_hit_rate().clamp(0.0, 1.0);
        let coherence = self
            .last_aef_report
            .as_ref()
            .map(|report| report.coherence_index as f32)
            .unwrap_or_else(|| {
                (0.48 * file.symmetry + 0.26 * (1.0 - drift_norm) + 0.26 * (1.0 - residual_ratio))
                    .clamp(0.0, 1.0)
            })
            .clamp(0.0, 1.0);
        let trust = self
            .last_aef_report
            .as_ref()
            .map(|report| report.trust_score)
            .unwrap_or_else(|| {
                (0.42 * file.symmetry
                    + 0.24 * (1.0 - drift_norm)
                    + 0.18 * (1.0 - residual_ratio)
                    + 0.16 * (file.compression_gain_percent / 100.0))
                    .clamp(0.0, 1.0)
            })
            .clamp(0.0, 1.0);
        let coverage = self
            .last_aef_report
            .as_ref()
            .map(|report| report.vault_coverage)
            .unwrap_or(hit_rate)
            .clamp(0.0, 1.0);
        let anchor_density = self
            .last_aef_report
            .as_ref()
            .map(|report| (report.anchor_count as f32 / 28.0).clamp(0.0, 1.0))
            .unwrap_or_else(|| {
                ((file.compression_gain_percent / 100.0) * 0.65 + coverage * 0.35).clamp(0.0, 1.0)
            });
        let projection_gain = self
            .last_aef_projection
            .as_ref()
            .map(|projection| {
                1.0 - (projection.projected_delta_size as f32
                    / projection.current_delta_size.max(1) as f32)
            })
            .unwrap_or_else(|| ((file.compression_gain_percent / 100.0) * 0.55).clamp(0.0, 1.0))
            .clamp(0.0, 1.0);
        let network_pressure = self
            .browser_probe
            .as_ref()
            .map(|probe| probe.risk_score)
            .unwrap_or_else(|| (drift_norm * 0.45 + (1.0 - trust) * 0.35).clamp(0.0, 1.0))
            .clamp(0.0, 1.0);
        let resonance = (0.30 * coherence
            + 0.24 * trust
            + 0.18 * coverage
            + 0.16 * (1.0 - drift_norm)
            + 0.12 * projection_gain)
            .clamp(0.0, 1.0);
        let godel_zone = (0.45 * (1.0 - file.symmetry) + 0.32 * entropy_norm + 0.23 * drift_norm)
            .clamp(0.0, 1.0);
        Some(VisualizationMetrics {
            entropy_norm,
            symmetry: file.symmetry.clamp(0.0, 1.0),
            drift_norm,
            compression_gain: (file.compression_gain_percent / 100.0).clamp(0.0, 1.0),
            residual_ratio,
            coherence,
            trust,
            hit_rate,
            coverage,
            anchor_density,
            projection_gain,
            resonance,
            godel_zone,
            network_pressure,
        })
    }

    fn current_ttd_candidate(&self) -> Option<(PublicTtdSubmission, PublicTtdCandidateValidation)> {
        let file = self.current_file.as_ref()?;
        if file.fingerprint_hash.trim().is_empty() {
            return None;
        }
        let interaction_count = self
            .mind_model
            .observer_model(self.observer_id)
            .map(|model| model.interaction_history.len() as u32)
            .unwrap_or(0);
        let residual = (file.delta_size as f32 / file.original_size.max(1) as f32).clamp(0.0, 1.0);
        let knowledge_ratio = (1.0 - file.drift / 255.0).clamp(0.0, 1.0);
        let metrics = PublicTtdMetrics {
            residual,
            symmetry: file.symmetry.clamp(0.0, 1.0),
            i_obs_ratio: knowledge_ratio,
            delta_stability: (file.symmetry * knowledge_ratio * (1.0 - residual)).clamp(0.0, 1.0),
            delta_i_obs_percent: (knowledge_ratio * 100.0).clamp(0.0, 100.0),
            recursive_count: interaction_count.max(1).min(7),
        };
        let boundary = if file.symmetry < 0.58 {
            "GOEDEL_LIMIT"
        } else if file.symmetry < 0.76 {
            "STRUCTURAL_HYPOTHESIS"
        } else {
            "RECONSTRUCTABLE"
        };
        let anomaly_count = u32::from(file.symmetry < 0.50)
            + u32::from(
                self.browser_probe
                    .as_ref()
                    .map(|probe| probe.risk_label == "CRITICAL")
                    .unwrap_or(false),
            );
        let lossless_verified = self
            .last_aef_report
            .as_ref()
            .map(|report| report.lossless_confirmed)
            .unwrap_or(false);
        let validation = validate_public_ttd_candidate(
            metrics.clone(),
            anomaly_count,
            boundary,
            lossless_verified,
        );
        let user = self.current_user.as_ref()?;
        let submission = PublicTtdSubmission {
            ttd_hash: file.fingerprint_hash.clone(),
            source_label: file.source_kind.clone(),
            public_metrics: metrics,
            pseudonym: pseudonymous_network_identity(
                &format!(
                    "{}|{}|{}",
                    user.username, self.observer_id, file.fingerprint_hash
                ),
                "public_ttd",
            ),
            uploader_role: user.role.clone(),
            signature_included: false,
        };
        Some((submission, validation))
    }

    fn queue_consent(
        &mut self,
        title: impl Into<String>,
        body: impl Into<String>,
        action: ConsentAction,
    ) {
        self.consent_dialog = Some(ConsentDialogState {
            title: title.into(),
            body: body.into(),
            action,
        });
    }

    fn run_browser_probe(&mut self, url: &str) {
        let probe = BrowserInspector::inspect_url(url, &self.browser_probe_policy);
        self.browser_probe = Some(probe.clone());
        self.browser_note = format!(
            "{} | Risiko {} {:.0}% | {}",
            probe.final_url,
            probe.risk_label,
            probe.risk_score * 100.0,
            probe
                .risk_reasons
                .first()
                .cloned()
                .unwrap_or_else(|| "keine dominante Anomalie".to_owned())
        );
        self.status_line = format!(
            "Browser-Probe abgeschlossen: {} {:.0}%",
            probe.risk_label,
            probe.risk_score * 100.0
        );
        self.append_log(format!(
            "Browser-Probe: {} | {}",
            probe.final_url, probe.risk_label
        ));
    }

    fn run_browser_search(&mut self, query: &str) {
        let context = BrowserInspector::fetch_search_context(query, "duckduckgo", 6.0, "");
        self.browser_search_context = Some(context.clone());
        if context.ok {
            self.status_line = format!("Suchkontext geladen: {}", context.search_url);
            self.append_log(format!("Suchkontext geladen fuer '{}'", context.query));
        } else {
            self.status_line = format!("Suchkontext fehlgeschlagen: {}", context.error);
        }
    }

    fn share_current_ttd(&mut self, signed: bool) {
        let Some((mut submission, validation)) = self.current_ttd_candidate() else {
            self.status_line = "Es gibt aktuell keinen teilbaren TTD-Kandidaten.".to_owned();
            return;
        };
        if !validation.valid {
            self.status_line =
                format!("TTD-Kandidat abgelehnt: {}", validation.reasons.join(" | "));
            self.append_log(self.status_line.clone());
            return;
        }
        submission.signature_included = signed;
        match self.public_ttd_pool.submit_validation(&submission) {
            Ok(summary) => {
                let record = summary
                    .anchor_records
                    .iter()
                    .find(|record| record.ttd_hash == submission.ttd_hash)
                    .cloned();
                let transport_result = if let Some(record) = &record {
                    self.public_ttd_transport.publish_bundle(&json!({
                        "schema": "aether.public_ttd_anchor.bundle.v1",
                        "anchor_records": [record],
                    }))
                } else {
                    Default::default()
                };
                let network_suffix = if transport_result.published {
                    " und ins Netz gereicht"
                } else if transport_result.network_used {
                    " lokal behalten, Netzpfad fehlgeschlagen"
                } else {
                    " lokal gespeichert"
                };
                self.status_line = format!(
                    "Stabiler TTD-Anker geteilt: {} | Pool trusted {}{}",
                    &submission.ttd_hash[..submission.ttd_hash.len().min(12)],
                    summary.trusted_anchor_count,
                    network_suffix
                );
                self.append_log(self.status_line.clone());
            }
            Err(err) => {
                self.status_line = format!("TTD-Share fehlgeschlagen: {err}");
            }
        }
    }

    fn sync_public_ttd(&mut self) {
        let pulled = self.public_ttd_transport.pull_remote_bundles();
        if pulled.remote_bundles.is_empty() {
            self.status_line = if pulled.network_used {
                format!(
                    "Kein neuer Public-TTD-Bundle geladen. {}",
                    pulled.errors.join(" | ")
                )
            } else {
                "Public-TTD-Sync bleibt fail-closed deaktiviert.".to_owned()
            };
            return;
        }
        match self
            .public_ttd_pool
            .ingest_remote_bundles(&pulled.remote_bundles)
        {
            Ok(summary) => {
                self.status_line = format!(
                    "Public-TTD-Sync: {} Bundles | trusted {} | candidate {}",
                    pulled.remote_bundles.len(),
                    summary.trusted_anchor_count,
                    summary.candidate_anchor_count
                );
                self.append_log(self.status_line.clone());
            }
            Err(err) => {
                self.status_line = format!("Public-TTD-Sync fehlgeschlagen: {err}");
            }
        }
    }

    fn persist_chat_relay_config(&mut self) -> Result<(), String> {
        let node_id = if self.chat_relay_node_id_input.trim().is_empty() {
            self.chat_relay_config.node_id.clone()
        } else {
            self.chat_relay_node_id_input.trim().to_owned()
        };
        self.chat_relay_node_id_input = node_id.clone();
        self.chat_relay_config = ChatRelayConfig {
            base_url: self.chat_relay_base_url_input.trim().to_owned(),
            shared_secret: self.chat_relay_secret_input.trim().to_owned(),
            node_id,
            last_event_id: self.chat_relay_config.last_event_id,
        };
        self.chat_relay_store.save(&self.chat_relay_config)?;
        self.relay_status_line = if self.chat_relay_config.base_url.trim().is_empty()
            || self.chat_relay_config.shared_secret.trim().is_empty()
        {
            "Chat-Relay lokal gespeichert, aber weiter fail-closed deaktiviert.".to_owned()
        } else {
            format!(
                "Chat-Relay gespeichert: {} @ {}",
                self.chat_relay_config.node_id, self.chat_relay_config.base_url
            )
        };
        Ok(())
    }

    fn probe_chat_relay_health(&mut self) {
        if let Err(err) = self.persist_chat_relay_config() {
            self.status_line =
                format!("Relay-Konfiguration konnte nicht gespeichert werden: {err}");
            return;
        }
        if self.chat_relay_config.base_url.trim().is_empty() {
            self.relay_status_line =
                "Chat-Relay bleibt lokal / fail-closed. Keine URL gesetzt.".to_owned();
            return;
        }
        match self
            .chat_relay_client
            .health(&self.chat_relay_config.base_url)
        {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(|value| value.as_str())
                    .unwrap_or("ok");
                self.relay_status_line = format!(
                    "Chat-Relay erreichbar: {} | Node {}",
                    status, self.chat_relay_config.node_id
                );
                self.append_log(self.relay_status_line.clone());
            }
            Err(err) => {
                self.relay_status_line = format!("Chat-Relay-Test fehlgeschlagen: {err}");
            }
        }
    }

    fn publish_chat_relay_batch(&mut self, envelopes: Vec<QueuedRelayEnvelope>) {
        if envelopes.is_empty() {
            self.status_line = "Kein Relay-Event zum Senden vorhanden.".to_owned();
            return;
        }
        if let Err(err) = self.persist_chat_relay_config() {
            self.status_line =
                format!("Relay-Konfiguration konnte nicht gespeichert werden: {err}");
            return;
        }
        if self.chat_relay_config.base_url.trim().is_empty()
            || self.chat_relay_config.shared_secret.trim().is_empty()
        {
            self.status_line = "Chat-Relay bleibt fail-closed: URL oder Secret fehlt.".to_owned();
            return;
        }
        let mut last_event_id = self.chat_relay_config.last_event_id;
        let mut sent = 0usize;
        let mut errors = Vec::new();
        for draft in envelopes {
            let envelope = ChatRelayEnvelope {
                room_kind: draft.room_kind,
                room_name: draft.room_name,
                author: draft.author,
                body: draft.body,
                created_at: Utc::now().to_rfc3339(),
            };
            match self
                .chat_relay_client
                .publish(&self.chat_relay_config, &envelope)
            {
                Ok(event_id) => {
                    sent += 1;
                    last_event_id = last_event_id.max(event_id);
                }
                Err(err) => errors.push(err),
            }
        }
        self.chat_relay_config.last_event_id = last_event_id;
        let _ = self.chat_relay_store.save(&self.chat_relay_config);
        if errors.is_empty() {
            self.status_line = format!("Chat-Relay: {} Ereignis(se) gesendet.", sent);
            self.relay_status_line = format!(
                "Chat-Relay aktiv: letzter Event {}",
                self.chat_relay_config.last_event_id
            );
            self.append_log(self.status_line.clone());
        } else {
            self.status_line = format!(
                "Chat-Relay nur teilweise erfolgreich: {} ok | {} Fehler",
                sent,
                errors.len()
            );
            self.relay_status_line = errors.join(" | ");
        }
    }

    fn sync_chat_relay(&mut self) {
        if let Err(err) = self.persist_chat_relay_config() {
            self.status_line =
                format!("Relay-Konfiguration konnte nicht gespeichert werden: {err}");
            return;
        }
        if self.chat_relay_config.base_url.trim().is_empty()
            || self.chat_relay_config.shared_secret.trim().is_empty()
        {
            self.status_line = "Chat-Relay bleibt fail-closed: URL oder Secret fehlt.".to_owned();
            return;
        }
        match self.chat_relay_client.fetch(&self.chat_relay_config) {
            Ok(events) => {
                let mut applied = 0usize;
                let mut last_event_id = self.chat_relay_config.last_event_id;
                for (event, envelope) in events {
                    last_event_id = last_event_id.max(event.event_id);
                    if event.origin_node == self.chat_relay_config.node_id {
                        continue;
                    }
                    self.route_relay_event(envelope);
                    applied += 1;
                }
                self.chat_relay_config.last_event_id = last_event_id;
                let _ = self.chat_relay_store.save(&self.chat_relay_config);
                self.status_line = format!(
                    "Chat-Relay-Sync abgeschlossen: {} neue Ereignisse.",
                    applied
                );
                self.relay_status_line = format!(
                    "Chat-Relay aktiv: letzter Event {}",
                    self.chat_relay_config.last_event_id
                );
                self.append_log(self.status_line.clone());
            }
            Err(err) => {
                self.status_line = format!("Chat-Relay-Sync fehlgeschlagen: {err}");
            }
        }
    }

    fn route_relay_event(&mut self, envelope: ChatRelayEnvelope) {
        let Some(username) = self.current_username() else {
            return;
        };
        match envelope.room_kind.as_str() {
            "private" => {
                let partner = if envelope.author.eq_ignore_ascii_case(&username) {
                    if envelope.room_name.trim().is_empty() {
                        "Kontakt".to_owned()
                    } else {
                        envelope.room_name.clone()
                    }
                } else {
                    envelope.author.clone()
                };
                let thread = self.state_store.private_thread(&username, &partner);
                push_message_if_new(&mut thread.messages, envelope.author, envelope.body);
            }
            "group" => {
                let room_name = if envelope.room_name.trim().is_empty() {
                    "Team".to_owned()
                } else {
                    envelope.room_name.clone()
                };
                let room = self.state_store.group_room(&username, &room_name);
                push_message_if_new(&mut room.messages, envelope.author, envelope.body);
            }
            "shanway" => {
                let room_name = if envelope.room_name.trim().is_empty() {
                    "Shanway Mesh".to_owned()
                } else {
                    envelope.room_name.clone()
                };
                let room = self.state_store.group_room(&username, &room_name);
                push_message_if_new(&mut room.messages, envelope.author, envelope.body);
            }
            _ => {}
        }
        let _ = self.state_store.save();
    }

    fn append_log(&mut self, message: impl Into<String>) {
        self.activity_log.push(message.into());
        if self.activity_log.len() > 64 {
            let remove_count = self.activity_log.len().saturating_sub(64);
            self.activity_log.drain(0..remove_count);
        }
    }

    fn run_async<T>(future: impl Future<Output = T>) -> Result<T, String> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("Tokio-Runtime konnte nicht erstellt werden: {err}"))?;
        Ok(runtime.block_on(future))
    }

    fn drain_bus_events(&mut self) {
        loop {
            match self.bus_receiver.try_recv() {
                Ok(event) => self.handle_bus_event(event),
                Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
                Err(TryRecvError::Lagged(skipped)) => {
                    self.append_log(format!("Bus: {skipped} Ereignisse uebersprungen."));
                }
            }
        }
    }

    fn drain_bus_publish_requests(&mut self) {
        let (events, next_offset) =
            match bus_ipc::read_publish_requests_from(self.bus_publish_offset) {
                Ok(value) => value,
                Err(err) => {
                    self.append_log(format!("Bus-Bridge lesen fehlgeschlagen: {err}"));
                    return;
                }
            };
        self.bus_publish_offset = next_offset;
        for event in events {
            self.bus_publisher.publish(event);
        }
    }

    fn handle_bus_event(&mut self, event: BusEvent) {
        match event {
            BusEvent::PackRecommended(payload) => {
                self.append_log(format!(
                    "Pack-Empfehlung: {} | {} | +{:.0}% Hit-Rate",
                    payload.pack_name,
                    payload.domain,
                    payload.estimated_hit_rate_improvement * 100.0
                ));
            }
            BusEvent::PackDownloadConfirmed(payload) => {
                self.append_log(format!("Pack-Download bestaetigt: {}", payload.pack_id));
            }
            BusEvent::PackInstalled(payload) => {
                self.status_line = format!(
                    "Pack installiert: {} | {} neue Anker",
                    payload.pack_name, payload.installed_anchor_count
                );
                self.append_log(self.status_line.clone());
            }
            BusEvent::OfflineCachePrepared(payload) => {
                self.status_line = format!(
                    "Offline-Cache bereit: {} Aktivitaeten | {} Anker | {:.1} MB",
                    payload.activities.len(),
                    payload.anchor_count,
                    payload.cache_size_mb
                );
                self.append_log(self.status_line.clone());
            }
            BusEvent::ShanwayUserMessage(payload) => {
                self.status_line = payload.message.clone();
                self.append_log(payload.message);
            }
            BusEvent::WorkflowAnchorHit(payload) => {
                self.append_log(format!(
                    "Workflow-Hit: {} | {} | {:.0}% Vertrauen",
                    payload.program_id,
                    payload.optimization_type,
                    payload.confidence * 100.0
                ));
            }
            BusEvent::WorkflowAnchorLearned(payload) => {
                self.append_log(format!(
                    "Workflow gelernt: {} | {} Ereignisse",
                    payload.program_id, payload.event_count
                ));
            }
            BusEvent::CrossProgramVramReuse(payload) => {
                self.append_log(format!(
                    "Cross-Program-Reuse: {} -> {} | {:.1} MB",
                    payload.source_program, payload.target_program, payload.vram_saved_mb
                ));
            }
            BusEvent::VramOptimized(payload) => {
                self.append_log(format!(
                    "VRAM optimiert: {} | {:.2} MB -> {:.2} MB | Hit {:.0}%",
                    payload.texture_label,
                    payload.original_mb,
                    payload.compressed_mb,
                    payload.vault_hit_rate * 100.0
                ));
            }
            BusEvent::TextureUploadCompleted(payload) => {
                self.append_log(format!(
                    "Texture-Upload: {} | Handle {} | Delta-Pfad {}",
                    payload.texture_label,
                    payload.handle,
                    if payload.used_delta_path {
                        "ja"
                    } else {
                        "nein"
                    }
                ));
            }
            BusEvent::ShaderCacheHit(payload) => {
                self.append_log(format!(
                    "Shader-Cache-Hit: {} | {}",
                    payload.program_id, payload.shader_hash
                ));
            }
            BusEvent::VramPressureChanged(payload) => {
                self.append_log(format!(
                    "VRAM-Druck: {:?} | {:.0}% von {:.0} MB",
                    payload.pressure_level,
                    payload.pressure_ratio * 100.0,
                    payload.total_mb
                ));
            }
            _ => {}
        }
    }

    fn record_file_workflow(&mut self, source_kind: &str, file_name: &str, aef_verified: bool) {
        let program_id = format!("rust_shell::{}", domain_from_source_kind(source_kind));
        let base_ts = Utc::now().timestamp_millis().max(0) as u64;
        let mut steps = vec![
            "file_drop".to_owned(),
            format!("source::{source_kind}"),
            "preview_ready".to_owned(),
        ];
        if aef_verified {
            steps.push("aef_lossless".to_owned());
        }
        steps.push("register_saved".to_owned());
        for (index, step) in steps.iter().enumerate() {
            if let Err(err) = Self::run_async(self.workflow_collector.ingest_event(
                &program_id,
                step,
                base_ts + index as u64,
            )) {
                self.append_log(format!("Workflow-Erfassung fehlgeschlagen: {err}"));
                return;
            }
        }
        if let Err(err) = Self::run_async(self.workflow_collector.complete_program(&program_id)) {
            self.append_log(format!("Workflow-Abschluss fehlgeschlagen: {err}"));
        }
        self.append_log(format!("Workflow erfasst: {file_name} | {program_id}"));
    }

    fn draw_shanway_face(&self, ui: &mut egui::Ui) {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(236.0, 220.0), Sense::hover());
        let painter = ui.painter_at(rect);
        let center = rect.center();
        painter.circle_filled(
            egui::pos2(center.x + 6.0, center.y + 10.0),
            88.0,
            Color32::from_rgba_unmultiplied(4, 8, 16, 64),
        );
        painter.circle_filled(center, 92.0, Color32::from_rgb(12, 20, 34));

        let antenna_top = egui::pos2(center.x, center.y - 92.0);
        let antenna_base = egui::pos2(center.x, center.y - 70.0);
        painter.line_segment(
            [antenna_top, antenna_base],
            Stroke::new(3.0, Color32::from_rgb(110, 214, 232)),
        );
        painter.circle_filled(antenna_top, 8.0, Color32::from_rgb(255, 196, 92));

        let head = Rect::from_center_size(
            egui::pos2(center.x, center.y - 18.0),
            Vec2::new(132.0, 102.0),
        );
        painter.rect_filled(head, 26.0, Color32::from_rgb(54, 92, 132));
        painter.rect_filled(
            head.shrink2(Vec2::new(6.0, 6.0)),
            22.0,
            Color32::from_rgb(74, 122, 170),
        );

        let visor =
            Rect::from_center_size(egui::pos2(center.x, center.y - 18.0), Vec2::new(92.0, 40.0));
        painter.rect_filled(visor, 18.0, Color32::from_rgb(16, 32, 54));
        painter.rect_filled(
            Rect::from_center_size(egui::pos2(center.x, center.y - 26.0), Vec2::new(80.0, 12.0)),
            8.0,
            Color32::from_rgba_unmultiplied(180, 240, 255, 28),
        );
        painter.circle_filled(
            egui::pos2(center.x - 22.0, center.y - 16.0),
            9.0,
            Color32::from_rgb(148, 240, 255),
        );
        painter.circle_filled(
            egui::pos2(center.x + 22.0, center.y - 16.0),
            9.0,
            Color32::from_rgb(148, 240, 255),
        );
        painter.circle_filled(
            egui::pos2(center.x - 22.0, center.y - 16.0),
            3.0,
            Color32::from_rgb(238, 250, 255),
        );
        painter.circle_filled(
            egui::pos2(center.x + 22.0, center.y - 16.0),
            3.0,
            Color32::from_rgb(238, 250, 255),
        );

        let mouth_left = egui::pos2(center.x - 24.0, center.y + 10.0);
        let mouth_mid = egui::pos2(center.x, center.y + 20.0);
        let mouth_right = egui::pos2(center.x + 24.0, center.y + 10.0);
        painter.line_segment(
            [mouth_left, mouth_mid],
            Stroke::new(3.0, Color32::from_rgb(214, 242, 255)),
        );
        painter.line_segment(
            [mouth_mid, mouth_right],
            Stroke::new(3.0, Color32::from_rgb(214, 242, 255)),
        );

        let body = Rect::from_center_size(
            egui::pos2(center.x, center.y + 70.0),
            Vec2::new(102.0, 56.0),
        );
        painter.rect_filled(body, 22.0, Color32::from_rgb(36, 66, 100));
        painter.rect_filled(
            Rect::from_center_size(egui::pos2(center.x, center.y + 70.0), Vec2::new(46.0, 16.0)),
            8.0,
            Color32::from_rgb(255, 196, 92),
        );
        painter.circle_filled(
            egui::pos2(center.x - 18.0, center.y + 70.0),
            3.0,
            Color32::from_rgb(36, 66, 100),
        );
        painter.circle_filled(
            egui::pos2(center.x + 18.0, center.y + 70.0),
            3.0,
            Color32::from_rgb(36, 66, 100),
        );
        painter.line_segment(
            [
                egui::pos2(center.x - 50.0, center.y + 62.0),
                egui::pos2(center.x - 78.0, center.y + 86.0),
            ],
            Stroke::new(4.0, Color32::from_rgb(96, 152, 212)),
        );
        painter.line_segment(
            [
                egui::pos2(center.x + 50.0, center.y + 62.0),
                egui::pos2(center.x + 78.0, center.y + 86.0),
            ],
            Stroke::new(4.0, Color32::from_rgb(96, 152, 212)),
        );
        painter.line_segment(
            [
                egui::pos2(center.x - 24.0, center.y + 94.0),
                egui::pos2(center.x - 34.0, center.y + 112.0),
            ],
            Stroke::new(4.0, Color32::from_rgb(96, 152, 212)),
        );
        painter.line_segment(
            [
                egui::pos2(center.x + 24.0, center.y + 94.0),
                egui::pos2(center.x + 34.0, center.y + 112.0),
            ],
            Stroke::new(4.0, Color32::from_rgb(96, 152, 212)),
        );
        painter.text(
            egui::pos2(center.x, rect.bottom() - 8.0),
            Align2::CENTER_BOTTOM,
            "friendly local robot",
            FontId::proportional(12.0),
            Color32::from_rgb(166, 196, 224),
        );
    }

    fn ui_auth(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            paint_aether_backdrop(ui.painter(), ui.max_rect());
            ui.vertical_centered(|ui| {
                ui.add_space(92.0);
                ui.label(
                    RichText::new("AETHER")
                        .size(13.0)
                        .strong()
                        .color(Color32::from_rgb(124, 210, 228)),
                );
                ui.heading("Rust Shell");
                ui.label("Lokale Anmeldung bleibt Pflicht, die Oberfläche darf aber trotzdem freundlicher aussehen.");
                ui.add_space(24.0);
                ui.group(|ui| {
                    ui.set_max_width(420.0);
                    ui.label(
                        RichText::new("Anmeldung / Registrierung")
                            .strong()
                            .color(Color32::from_rgb(226, 236, 248)),
                    );
                    ui.label("Benutzername");
                    ui.add(TextEdit::singleline(&mut self.login_username).desired_width(320.0));
                    ui.label("Passwort");
                    ui.add(
                        TextEdit::singleline(&mut self.login_password)
                            .password(true)
                            .desired_width(320.0),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Anmelden").clicked() {
                            match self
                                .auth_store
                                .authenticate(&self.login_username, &self.login_password)
                            {
                                Ok(user) => {
                                    self.current_user = Some(user);
                                    self.status_line = "Anmeldung erfolgreich.".to_owned();
                                    self.append_log("Anmeldung erfolgreich.");
                                }
                                Err(err) => {
                                    self.status_line = err.clone();
                                    self.append_log(format!("Anmeldung fehlgeschlagen: {err}"));
                                }
                            }
                        }
                        if ui.button("Registrieren").clicked() {
                            match self
                                .auth_store
                                .register(&self.login_username, &self.login_password)
                            {
                                Ok(()) => {
                                    self.status_line =
                                        "Registrierung erfolgreich. Bitte anmelden.".to_owned();
                                    self.append_log("Registrierung erfolgreich.");
                                }
                                Err(err) => {
                                    self.status_line = err.clone();
                                    self.append_log(format!("Registrierung fehlgeschlagen: {err}"));
                                }
                            }
                        }
                    });
                });
                ui.add_space(16.0);
                ui.label(
                    RichText::new(&self.status_line)
                        .color(Color32::from_rgb(138, 212, 255))
                        .strong(),
                );
            });
        });
    }

    fn ui_left_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("shanway_left").resizable(false).default_width(356.0).show(ctx, |ui| {
            self.draw_shanway_face(ui);
            ui.label(
                RichText::new("LOCAL COMPANION")
                    .size(11.0)
                    .strong()
                    .color(Color32::from_rgb(128, 204, 220)),
            );
            ui.heading("Shanway");
            ui.label("Struktureller Beobachter. Dateien kommen lokal hinein, Antworten bleiben klarer und weniger unheimlich.");
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Sicherheitsfilter: aktiv").color(Color32::from_rgb(164, 232, 178)));
                ui.label(RichText::new("Netzpfad: aus").color(Color32::from_rgb(255, 208, 120)));
            });
            ui.label(
                RichText::new(self.mind_model.observer_status(self.observer_id))
                    .color(Color32::from_rgb(194, 208, 228)),
            );
            ui.separator();
            if let Some(user) = &self.current_user {
                ui.label(format!("Live-Session: {}", user.session_id));
                ui.label(format!("Session-Key-Fingerprint: {}", user.live_session_fingerprint));
                ui.label(format!("Storage-Key-Fingerprint: {}", user.raw_storage_fingerprint));
            }
            let pack_count = self
                .pack_registry
                .read()
                .map(|registry| registry.entries.len())
                .unwrap_or(0);
            ui.label(format!("Pack-Registry: {pack_count} optionale Pack-Metadaten lokal gecacht."));
            ui.label(format!(
                "Observer-Persistenz: {}",
                match self.mind_model.scope() {
                    ObserverModelScope::SessionOnly => "SessionOnly",
                    ObserverModelScope::PersistentLocal => "PersistentLocal",
                    ObserverModelScope::NeverStore => "NeverStore",
                }
            ));
            ui.label(self.public_ttd_pool.summary_line());
            ui.label(format!(
                "Public-TTD-Netz: {}",
                if self.public_ttd_transport.is_enabled() { "aktiv" } else { "aus / fail-closed" }
            ));
            ui.label(format!("Chat-Relay-Node: {}", self.chat_relay_config.node_id));
            ui.label(RichText::new(&self.relay_status_line).color(Color32::from_rgb(170, 184, 204)));
            ui.separator();
            if let Some(file) = &self.current_file {
                ui.label(RichText::new("Aktive Datei").strong());
                ui.label(format!("Name: {}", file.file_name));
                ui.label(format!("Typ: {}", file.source_kind));
                ui.label(format!("Groesse: {} Bytes", file.original_size));
                ui.label(format!("Kompressionsgewinn: {:.2}%", file.compression_gain_percent));
                if let Some(projection) = &self.last_aef_projection {
                    ui.label(format!(
                        "AEF-Projektion: Delta {} B -> {} B | Rate {:.2}% -> {:.2}%",
                        projection.current_delta_size,
                        projection.projected_delta_size,
                        projection.current_compression_rate * 100.0,
                        projection.projected_compression_rate * 100.0
                    ));
                }
            } else {
                ui.label("Noch keine Datei aktiv.");
            }
            if let Some((submission, validation)) = self.current_ttd_candidate() {
                ui.label(RichText::new("TTD-Kandidat").strong());
                ui.label(format!(
                    "Hash: {} | Symmetrie {:.0}% | I_obs {:.0}% | Residual {:.2}%",
                    &submission.ttd_hash[..submission.ttd_hash.len().min(12)],
                    validation.metrics.symmetry * 100.0,
                    validation.metrics.i_obs_ratio * 100.0,
                    validation.metrics.residual * 100.0
                ));
                if validation.valid {
                    ui.label(RichText::new("Stabiler TTD-Kandidat erkannt").color(Color32::LIGHT_GREEN));
                } else {
                    ui.label(format!("Noch nicht teilbar: {}", validation.reasons.join(" | ")));
                }
            }
            ui.separator();
            if ui.button("Register neu laden").clicked() {
                self.state_store = StateStore::load_default();
                self.status_line = "Lokales Register neu geladen.".to_owned();
            }
            if ui.button("Aktive Vorschau leeren").clicked() {
                self.current_file = None;
                self.preview_texture = None;
                self.last_aef_report = None;
                self.last_aef_projection = None;
            }
            if ui.button("Shanway-Chat oeffnen").clicked() {
                self.top_tab = TopTab::Chats;
                self.chat_tab = ChatTab::Shanway;
            }
            if ui.button("Observer lokal behalten").clicked() {
                self.mind_model.enable_persistent_local();
                self.status_line = "Observer-Modell auf PersistentLocal umgestellt.".to_owned();
                self.append_log("Observer-Modell wird jetzt lokal persistent gehalten.");
            }
            if ui.button("Observer lokal loeschen").clicked() {
                match self.mind_model.clear_persistent_state() {
                    Ok(()) => {
                        self.status_line = "Lokaler Observer-Zustand geloescht.".to_owned();
                        self.append_log("Observer-Modell lokal geloescht.");
                    }
                    Err(err) => {
                        self.status_line = format!("Observer-Zustand konnte nicht geloescht werden: {err}");
                    }
                }
            }
            if ui.button("Empfohlenen Pack installieren").clicked() {
                if let Some(profile) = self.current_usage_profile() {
                    let top_pack = self
                        .pack_registry
                        .read()
                        .ok()
                        .and_then(|registry| registry.find_relevant_packs(&profile, 0.05).into_iter().next());
                    if let Some(top_pack) = top_pack {
                        match self.pack_manager.download_and_install_sync(top_pack.pack_id, true) {
                            Ok(result) => {
                                self.bus_publisher.publish(BusEvent::PackInstalled(PackInstalledEvent {
                                    pack_id: result.pack_id.to_string(),
                                    pack_name: result.pack_name.clone(),
                                    installed_anchor_count: result.anchors_added,
                                    hit_rate_delta: (result.hit_rate_after - result.hit_rate_before).max(0.0),
                                }));
                                self.status_line = format!(
                                    "Pack installiert: {} | Hit-Rate {:.0}% -> {:.0}%",
                                    result.pack_name,
                                    result.hit_rate_before * 100.0,
                                    result.hit_rate_after * 100.0
                                );
                                self.append_log(self.status_line.clone());
                            }
                            Err(err) => {
                                self.status_line = format!("Pack-Installation fehlgeschlagen: {err}");
                            }
                        }
                    } else {
                        self.status_line = "Kein relevanter Pack ueber der Empfehlungsschwelle gefunden.".to_owned();
                    }
                } else {
                    self.status_line = "Fuer Pack-Empfehlungen braucht Shanway zuerst eine aktive Datei.".to_owned();
                }
            }
            if ui.button("Pack aus aktiver Domaene generieren").clicked() {
                if let Some(domain) = self.current_domain_key() {
                    match self.pack_generator.generate_pack_sync(domain.clone(), true) {
                        Ok(result) => {
                            if let Ok(mut registry) = self.pack_registry.write() {
                                let pack_path = result.path.clone();
                                if let Ok(pack) = crate::pack::AepPack::read_from_path(&pack_path, &EnginePipeline::new()) {
                                    let _ = registry.register_local_pack(&pack, &pack_path);
                                }
                            }
                            self.status_line = format!("Lokaler Pack erzeugt: {} | {} Anker", result.domain, result.anchor_count);
                            self.append_log(format!("Pack erzeugt: {}", result.path.display()));
                        }
                        Err(err) => {
                            self.status_line = format!("Pack-Generierung fehlgeschlagen: {err}");
                        }
                    }
                } else {
                    self.status_line = "Ohne aktive Datei kann keine Domaene fuer den Pack bestimmt werden.".to_owned();
                }
            }
            if ui.button("Offline-Cache vorbereiten").clicked() {
                let activities = self
                    .current_domain_key()
                    .map(|domain| vec![domain])
                    .unwrap_or_else(|| vec!["language_german".to_owned()]);
                match Self::run_async(self.offline_cache_manager.prepare_offline_cache(
                    OfflinePrepRequest {
                        planned_activities: activities,
                        available_cache_mb: 64,
                        target: CacheTarget::LocalCache,
                    },
                    true,
                ))
                .and_then(|result| result) {
                    Ok(()) => {
                        self.status_line = "Offline-Cache vorbereitet.".to_owned();
                        self.append_log(self.status_line.clone());
                    }
                    Err(err) => {
                        self.status_line = format!("Offline-Cache fehlgeschlagen: {err}");
                    }
                }
            }
            if ui.button("Stabilen TTD-Anker teilen").clicked() {
                if let Some((submission, validation)) = self.current_ttd_candidate() {
                    if validation.valid {
                        self.queue_consent(
                            "Stabilen TTD-Anker teilen",
                            format!(
                                "Nur Hash und Metriken werden freigegeben.\nHash: {}\nSymmetrie {:.0}% | I_obs {:.0}% | Residual {:.2}%\nDefault bleibt Nein.",
                                &submission.ttd_hash[..submission.ttd_hash.len().min(12)],
                                validation.metrics.symmetry * 100.0,
                                validation.metrics.i_obs_ratio * 100.0,
                                validation.metrics.residual * 100.0
                            ),
                            ConsentAction::ShareStableTtd { signed: false },
                        );
                    } else {
                        self.status_line = format!("TTD-Kandidat noch nicht stabil: {}", validation.reasons.join(" | "));
                    }
                } else {
                    self.status_line = "Ohne aktive Datei gibt es keinen TTD-Kandidaten.".to_owned();
                }
            }
            if ui.button("Stabilen TTD-Anker signiert teilen").clicked() {
                if let Some((submission, validation)) = self.current_ttd_candidate() {
                    if validation.valid {
                        self.queue_consent(
                            "TTD-Anker mit Signatur teilen",
                            format!(
                                "Nur Hash und Metriken werden freigegeben, zusaetzlich mit lokaler Signatur.\nHash: {}\nDefault bleibt Nein.",
                                &submission.ttd_hash[..submission.ttd_hash.len().min(12)]
                            ),
                            ConsentAction::ShareStableTtd { signed: true },
                        );
                    } else {
                        self.status_line = format!("TTD-Kandidat noch nicht stabil: {}", validation.reasons.join(" | "));
                    }
                } else {
                    self.status_line = "Ohne aktive Datei gibt es keinen TTD-Kandidaten.".to_owned();
                }
            }
            if ui.button("Oeffentliche Anker syncen").clicked() {
                self.queue_consent(
                    "Oeffentliche Anker syncen",
                    "Neue oeffentliche Hash-und-Metrik-Bundles lokal laden und in den Public-TTD-Pool integrieren? Default bleibt Nein.",
                    ConsentAction::SyncPublicTtd,
                );
            }
            ui.separator();
            egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                for line in self.activity_log.iter().rev() {
                    ui.label(line);
                }
            });
            ui.separator();
            ui.label(RichText::new(&self.status_line).color(Color32::LIGHT_BLUE));
        });
    }

    fn ui_top_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            for (tab, label) in [
                (TopTab::Analyse, "Datei"),
                (TopTab::Struktur, "Struktur"),
                (TopTab::Browser, "Browser"),
                (TopTab::Chats, "Chats"),
                (TopTab::Register, "Register"),
            ] {
                let selected = self.top_tab == tab;
                let button = egui::Button::new(RichText::new(label).strong().color(if selected {
                    Color32::from_rgb(246, 250, 255)
                } else {
                    Color32::from_rgb(188, 204, 224)
                }))
                .fill(if selected {
                    Color32::from_rgb(48, 98, 168)
                } else {
                    Color32::from_rgb(18, 28, 42)
                })
                .stroke(Stroke::new(
                    1.0,
                    if selected {
                        Color32::from_rgb(116, 218, 240)
                    } else {
                        Color32::from_rgb(44, 60, 84)
                    },
                ));
                if ui.add_sized([104.0, 34.0], button).clicked() {
                    self.top_tab = tab;
                }
            }
        });
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let Some(username) = self.current_username() else {
            return;
        };
        let dropped_files = ctx.input(|input| input.raw.dropped_files.clone());
        if dropped_files.is_empty() {
            self.last_drop_token = None;
            return;
        }
        for dropped in dropped_files {
            let Some(path) = dropped.path else {
                continue;
            };
            let token = path.to_string_lossy().to_string();
            if self.last_drop_token.as_deref() == Some(token.as_str()) {
                continue;
            }
            self.last_drop_token = Some(token);
            match self.load_file_into_state(&path, ctx, &username) {
                Ok(file) => {
                    self.status_line = format!("Datei geladen: {}", file.file_name);
                    self.append_log(format!("Drag and Drop verarbeitet: {}", file.file_name));
                    self.top_tab = TopTab::Analyse;
                }
                Err(err) => {
                    self.status_line = err.clone();
                    self.append_log(format!("Datei konnte nicht geladen werden: {err}"));
                }
            }
        }
    }

    fn load_file_into_state(
        &mut self,
        path: &Path,
        ctx: &egui::Context,
        username: &str,
    ) -> Result<ProcessedFile, String> {
        let bytes =
            fs::read(path).map_err(|err| format!("Datei konnte nicht gelesen werden: {err}"))?;
        let metadata = fs::metadata(path)
            .map_err(|err| format!("Metadaten konnten nicht gelesen werden: {err}"))?;
        let fingerprint_hash = sha256_hex(&bytes);
        let original_size = metadata.len();
        let delta_size = estimate_compressed_size(&bytes)?;
        let ratio = if original_size == 0 {
            0.0
        } else {
            delta_size as f32 / original_size as f32
        };
        let compression_gain_percent = ((1.0 - ratio).clamp(0.0, 1.0) * 10000.0).round() / 100.0;
        let entropy = shannon_entropy(&bytes);
        let preview = build_preview_image(path, &bytes);
        let symmetry = preview_symmetry(&preview);
        let drift = byte_drift(&bytes);
        let source_kind = detect_source_kind(path, &bytes);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unbekannt")
            .to_owned();
        let preview_bytes = color_image_rgba_bytes(&preview);
        let preview_note = format!(
            "{} | Entropie {:.2} bit | Symmetrie {:.1}% | Drift {:.2}",
            source_kind,
            entropy,
            symmetry * 100.0,
            drift
        );
        let anchor_summary = build_anchor_summary(entropy, symmetry, drift);
        let process_summary =
            build_process_summary(entropy, symmetry, compression_gain_percent, &source_kind);
        let excerpt = build_excerpt(&source_kind, &bytes);
        self.preview_texture = Some(ctx.load_texture(
            format!("preview::{file_name}"),
            preview,
            egui::TextureOptions::LINEAR,
        ));
        match Self::run_async(self.gfx.upload_texture(
            &format!("preview::{source_kind}::{file_name}"),
            &preview_bytes,
        )) {
            Ok(handle) => self.append_log(format!("Vorschau-Textur vorbereitet: Handle {handle}")),
            Err(err) => self.append_log(format!("Vorschau-Texturpfad fehlgeschlagen: {err}")),
        }
        let shader_handle = self.gfx.compile_shader_cached(
            "rust_shell_preview",
            &format!("preview::{source_kind}"),
            "fragment",
        );
        self.append_log(format!("Preview-Shader bereit: Handle {shader_handle}"));
        self.gfx.check_vram_pressure();

        let mut processed = ProcessedFile {
            file_name: file_name.clone(),
            full_path: path.to_string_lossy().to_string(),
            fingerprint_hash,
            source_kind: source_kind.clone(),
            original_size,
            delta_size,
            compression_gain_percent,
            entropy,
            symmetry,
            drift,
            anchor_summary: anchor_summary.clone(),
            process_summary: process_summary.clone(),
            preview_note: preview_note.clone(),
            excerpt,
        };
        let mut aef_verified = false;
        if let Ok(report) = self.encode_aef_for_path(path) {
            processed.process_summary = format!(
                "{}\nAEF: {:.2}% | Delta {:.2}% | Lossless {}",
                processed.process_summary,
                report.compression_rate_percent,
                report.delta_percent,
                if report.lossless_confirmed {
                    "JA"
                } else {
                    "NEIN"
                }
            );
            self.last_aef_report = Some(report.clone());
            self.append_log(format!(
                ".aef geschrieben: {} | Lossless {} | Trust {:.2}",
                report.filename,
                if report.lossless_confirmed {
                    "JA"
                } else {
                    "NEIN"
                },
                report.trust_score
            ));
            self.refresh_projection_for_path(path);
            aef_verified = report.lossless_confirmed;
        }
        self.current_file = Some(processed.clone());

        let entry = RegisterEntry {
            id: 0,
            owner_username: username.to_owned(),
            file_name: file_name.clone(),
            full_path: path.to_string_lossy().to_string(),
            source_kind: source_kind.clone(),
            original_size,
            delta_size,
            compression_gain_percent,
            anchor_summary: anchor_summary.clone(),
            process_summary: process_summary.clone(),
            preview_note: preview_note.clone(),
        };
        let entry_id = self.state_store.add_register_entry(entry)?;
        self.selected_register_id = Some(entry_id);
        self.record_file_workflow(&source_kind, &file_name, aef_verified);
        Ok(processed)
    }

    fn load_register_entry(&mut self, ctx: &egui::Context, entry: &RegisterEntry) {
        self.selected_register_id = Some(entry.id);
        if Path::new(&entry.full_path).exists() {
            if let Ok(file) = self.preview_existing_file(Path::new(&entry.full_path), ctx) {
                self.current_file = Some(file.clone());
                self.refresh_projection_for_path(Path::new(&entry.full_path));
                self.status_line = format!("Registereintrag geladen: {}", file.file_name);
                self.append_log(format!("Registereintrag geladen: {}", file.file_name));
                return;
            }
        }
        self.current_file = Some(ProcessedFile {
            file_name: entry.file_name.clone(),
            full_path: entry.full_path.clone(),
            fingerprint_hash: String::new(),
            source_kind: entry.source_kind.clone(),
            original_size: entry.original_size,
            delta_size: entry.delta_size,
            compression_gain_percent: entry.compression_gain_percent,
            entropy: 0.0,
            symmetry: 0.0,
            drift: 0.0,
            anchor_summary: entry.anchor_summary.clone(),
            process_summary: entry.process_summary.clone(),
            preview_note: entry.preview_note.clone(),
            excerpt: "Originaldatei ist nicht mehr lokal vorhanden. Es werden Registermetadaten angezeigt.".to_owned(),
        });
        self.last_aef_report = None;
        self.last_aef_projection = None;
        self.preview_texture = Some(ctx.load_texture(
            format!("register::{}", entry.id),
            placeholder_preview_image(),
            egui::TextureOptions::LINEAR,
        ));
    }

    fn ui_analyse_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.set_min_height(340.0);
            ui.label(RichText::new("Dateivorschau").strong());
            if let Some(texture) = &self.preview_texture {
                let available = ui.available_size_before_wrap();
                let width = available.x.max(320.0).min(940.0);
                let height = (available.y - 12.0).max(240.0).min(360.0);
                ui.image((texture.id(), Vec2::new(width, height)));
            } else {
                ui.label("Noch keine Datei geladen. Ziehe eine Datei auf das Fenster.");
            }
        });
        ui.add_space(8.0);
        ui.columns(3, |cols| {
            cols[0].group(|ui| {
                ui.label(RichText::new("DATEI").strong());
                if let Some(file) = &self.current_file {
                    ui.label(format!("Pfad: {}", file.full_path));
                    ui.label(format!("Typ: {}", file.source_kind));
                    ui.label(format!("Original: {} Bytes", file.original_size));
                    ui.label(format!("Delta: {} Bytes", file.delta_size));
                    ui.label(format!("Gewinn: {:.2}%", file.compression_gain_percent));
                    ui.separator();
                    ui.label(&file.preview_note);
                    if let Some(report) = &self.last_aef_report {
                        ui.separator();
                        ui.label(format!(
                            ".aef: {} | Cover {:.1}% | Lossless {}",
                            report.filename,
                            report.vault_coverage * 100.0,
                            if report.lossless_confirmed {
                                "JA"
                            } else {
                                "NEIN"
                            }
                        ));
                        if let Some(projection) = &self.last_aef_projection {
                            ui.label(format!(
                                "Projektion: Delta {} B -> {} B bei groesserem Vault",
                                projection.current_delta_size, projection.projected_delta_size
                            ));
                        }
                    }
                    ui.separator();
                    ui.label(&file.excerpt);
                } else {
                    ui.label("Keine aktive Datei.");
                }
            });
            cols[1].group(|ui| {
                ui.label(RichText::new("PROZESSE").strong());
                if let Some(file) = &self.current_file {
                    ui.label(format!("Entropie: {:.2} bit", file.entropy));
                    ui.label(format!("Symmetrie: {:.1}%", file.symmetry * 100.0));
                    ui.label(format!("Drift: {:.2}", file.drift));
                    ui.separator();
                    ui.label(&file.process_summary);
                    if let Some(report) = &self.last_aef_report {
                        ui.separator();
                        ui.label(format!(
                            "AEF Trust {:.2} | C(t) {:.3} | Delta {} B",
                            report.trust_score, report.coherence_index, report.delta_size_bytes
                        ));
                        if let Some(projection) = &self.last_aef_projection {
                            ui.label(format!(
                                "Rate {:.2}% -> {:.2}% | Ziel-Vault {:?}",
                                projection.current_compression_rate * 100.0,
                                projection.projected_compression_rate * 100.0,
                                projection.vault_size_needed_for_lossless
                            ));
                        }
                    }
                } else {
                    ui.label("Noch keine Prozessbeschreibung.");
                }
            });
            cols[2].group(|ui| {
                ui.label(RichText::new("ANKER").strong());
                if let Some(file) = &self.current_file {
                    ui.label(&file.anchor_summary);
                } else {
                    ui.label("Noch keine Anker erkannt.");
                }
            });
        });
    }

    fn ui_struktur_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(RichText::new("Struktur-Visualisierung").strong());
            ui.label(
                "Separater Tab fuer Interferenz, Raster, Symmetriebruch und Resonanz. Die Module zeigen die Wirkung der Struktur, nicht den Rohinhalt.",
            );
        });
        ui.add_space(8.0);
        let Some(file) = self.active_visualization_file() else {
            ui.group(|ui| {
                ui.label("Noch keine Quelle aktiv.");
                ui.label(
                    "Ziehe eine Datei ins Fenster oder fuehre eine Browser-Probe aus. Danach erscheinen die Strukturmodule hier in einem eigenen Tab.",
                );
            });
            return;
        };
        let Some(metrics) = self.current_visualization_metrics() else {
            return;
        };
        ui.columns(4, |cols| {
            cols[0].group(|ui| {
                ui.label(RichText::new("Quelle").strong());
                ui.label(&file.file_name);
                ui.label(&file.source_kind);
            });
            cols[1].group(|ui| {
                ui.label(RichText::new("Resonanz").strong());
                ui.label(format!("{:.0}%", metrics.resonance * 100.0));
                ui.label(format!("Trust {:.0}%", metrics.trust * 100.0));
            });
            cols[2].group(|ui| {
                ui.label(RichText::new("Delta").strong());
                ui.label(format!("{:.0}%", metrics.residual_ratio * 100.0));
                ui.label(format!("Drift {:.0}%", metrics.drift_norm * 100.0));
            });
            cols[3].group(|ui| {
                ui.label(RichText::new("Goedel-Zone").strong());
                ui.label(format!("{:.0}%", metrics.godel_zone * 100.0));
                ui.label(format!("Coverage {:.0}%", metrics.coverage * 100.0));
            });
        });
        ui.add_space(8.0);
        ui.columns(2, |cols| {
            cols[0].group(|ui| {
                ui.label(RichText::new("Interferenz-Map").strong());
                ui.label("Ordnung, Knoten und Verlustzonen im Feld.");
                let desired = Vec2::new(ui.available_width().max(260.0), 230.0);
                let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
                render_interference_map(ui.painter_at(rect), rect, metrics);
            });
            cols[1].group(|ui| {
                ui.label(RichText::new("Delta-Heatmap").strong());
                ui.label("Raster der aktiven Systembereiche.");
                let desired = Vec2::new(ui.available_width().max(260.0), 230.0);
                let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
                render_delta_heatmap(ui.painter_at(rect), rect, metrics);
            });
        });
        ui.add_space(8.0);
        ui.columns(2, |cols| {
            cols[0].group(|ui| {
                ui.label(RichText::new("Symmetriebruch-Radar").strong());
                ui.label("Soll-Feld gegen emergente Ausreisser.");
                let desired = Vec2::new(ui.available_width().max(260.0), 230.0);
                let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
                render_symmetry_break_radar(ui.painter_at(rect), rect, metrics);
            });
            cols[1].group(|ui| {
                ui.label(RichText::new("Resonanz-Spektrum").strong());
                ui.label("Peaks, Taeler und globale Verstaerkung.");
                let desired = Vec2::new(ui.available_width().max(260.0), 230.0);
                let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
                render_resonance_spectrum(ui.painter_at(rect), rect, metrics);
            });
        });
        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label(RichText::new("Goedel-Modus").strong());
            ui.label(
                "Graubereich fuer Muster, die Aether als wirksam erkennt, aber nur teilweise erklaeren kann.",
            );
            let unresolved = metrics.godel_zone;
            let explained = (1.0 - unresolved).clamp(0.0, 1.0);
            ui.add(
                egui::ProgressBar::new(explained)
                    .desired_width(ui.available_width())
                    .text(format!(
                        "erklaerbar {:.0}% | emergent {:.0}%",
                        explained * 100.0,
                        unresolved * 100.0
                    )),
            );
            ui.label(format!(
                "Boundary: {} | Hit-Rate {:.0}% | Projektion {:.0}%",
                if metrics.godel_zone >= 0.58 {
                    "GOEDEL_LIMIT"
                } else if metrics.godel_zone >= 0.34 {
                    "STRUCTURAL_HYPOTHESIS"
                } else {
                    "RECONSTRUCTABLE"
                },
                metrics.hit_rate * 100.0,
                metrics.projection_gain * 100.0
            ));
        });
    }

    fn ui_browser_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(RichText::new("Browser-Arbeitsflaeche").strong());
            ui.label("Lokale URL-Probe und Suchkontext bleiben fail-closed und laufen nur nach Consent.");
            ui.horizontal(|ui| {
                ui.label("Adresse");
                ui.add(TextEdit::singleline(&mut self.browser_address).desired_width(520.0));
                if ui.button("URL pruefen").clicked() {
                    self.queue_consent(
                        "Lokale URL-Probe",
                        format!(
                            "Die Ziel-URL wird mit begrenztem Bytebudget lokal gelesen und strukturell bewertet.\n{}\nDefault bleibt Nein.",
                            BrowserInspector::normalize_url(&self.browser_address)
                        ),
                        ConsentAction::BrowserProbe {
                            url: self.browser_address.clone(),
                        },
                    );
                }
                if ui.button("Suchkontext holen").clicked() {
                    self.queue_consent(
                        "Web-Suchkontext laden",
                        "Ein kurzer Suchkontext wird fuer Shanway geladen. Keine Rohdatenpersistenz, nur lokaler Kurzkontext. Default bleibt Nein.",
                        ConsentAction::BrowserSearch {
                            query: self.browser_address.clone(),
                        },
                    );
                }
                if ui.button("An Shanway uebergeben").clicked() {
                    self.top_tab = TopTab::Chats;
                    self.chat_tab = ChatTab::Shanway;
                    self.shanway_message_input = format!("Bitte Browser-Kontext strukturell pruefen: {}", self.browser_address);
                }
            });
            ui.add_space(8.0);
            ui.label(&self.browser_note);
            if let Some(probe) = &self.browser_probe {
                ui.separator();
                ui.label(RichText::new("Lokale Probe").strong());
                ui.label(format!("Titel: {}", probe.title));
                ui.label(format!("URL: {}", probe.final_url));
                ui.label(format!(
                    "Risiko: {} {:.0}% | Kategorie {} | Status {}",
                    probe.risk_label,
                    probe.risk_score * 100.0,
                    probe.category,
                    probe.status_code
                ));
                ui.label(&probe.frontend_summary);
                ui.label(&probe.backend_summary);
                if !probe.summary.trim().is_empty() {
                    ui.label(trimmed_at_boundary(&probe.summary, 240));
                }
                for reason in probe.risk_reasons.iter().take(4) {
                    ui.label(format!("• {}", reason));
                }
            }
            if let Some(context) = &self.browser_search_context {
                ui.separator();
                ui.label(RichText::new("Suchkontext").strong());
                ui.label(format!("Quelle: {}", context.search_url));
                ui.label(trimmed_at_boundary(&context.summary, 280));
            }
        });
    }

    fn ui_consent_dialog(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.consent_dialog.clone() else {
            return;
        };
        egui::Window::new(dialog.title.clone())
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label(dialog.body.clone());
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Nein").clicked() {
                        self.status_line = "Aktion abgebrochen.".to_owned();
                        self.consent_dialog = None;
                    }
                    if ui.button("Ja").clicked() {
                        let action = dialog.action.clone();
                        self.consent_dialog = None;
                        match action {
                            ConsentAction::BrowserProbe { url } => self.run_browser_probe(&url),
                            ConsentAction::BrowserSearch { query } => {
                                self.run_browser_search(&query)
                            }
                            ConsentAction::ShareStableTtd { signed } => {
                                self.share_current_ttd(signed)
                            }
                            ConsentAction::SyncPublicTtd => self.sync_public_ttd(),
                            ConsentAction::ChatRelayPublishBatch { envelopes } => {
                                self.publish_chat_relay_batch(envelopes)
                            }
                            ConsentAction::ChatRelayFetch => self.sync_chat_relay(),
                        }
                    }
                });
            });
    }

    fn ui_chat_relay_controls(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(RichText::new("Chat-Relay").strong());
            ui.label("Optionaler Internet-Relay-Pfad. Ohne URL und Secret bleibt alles lokal und fail-closed.");
            ui.horizontal(|ui| {
                ui.label("Relay URL");
                ui.add(TextEdit::singleline(&mut self.chat_relay_base_url_input).desired_width(260.0));
                if ui.button("Speichern").clicked() {
                    match self.persist_chat_relay_config() {
                        Ok(()) => {
                            self.status_line = "Chat-Relay-Konfiguration gespeichert.".to_owned();
                            self.append_log(self.status_line.clone());
                        }
                        Err(err) => {
                            self.status_line = format!("Chat-Relay-Konfiguration fehlgeschlagen: {err}");
                        }
                    }
                }
                if ui.button("Testen").clicked() {
                    self.probe_chat_relay_health();
                }
                if ui.button("Syncen").clicked() {
                    self.queue_consent(
                        "Chat-Relay syncen",
                        "Neue verschluesselte Relay-Ereignisse lokal abrufen und in die Chat-Raeume integrieren? Default bleibt Nein.",
                        ConsentAction::ChatRelayFetch,
                    );
                }
            });
            ui.horizontal(|ui| {
                ui.label("Shared Secret");
                ui.add(TextEdit::singleline(&mut self.chat_relay_secret_input).password(true).desired_width(220.0));
                ui.label("Node");
                ui.add(TextEdit::singleline(&mut self.chat_relay_node_id_input).desired_width(220.0));
            });
            ui.label(&self.relay_status_line);
        });
    }

    fn ui_chats_tab(&mut self, ui: &mut egui::Ui) {
        self.ui_chat_relay_controls(ui);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            for (tab, label) in [
                (ChatTab::Private, "Einzelchat"),
                (ChatTab::Group, "Gruppenchat"),
                (ChatTab::Shanway, "Shanway"),
            ] {
                if ui.selectable_label(self.chat_tab == tab, label).clicked() {
                    self.chat_tab = tab;
                }
            }
        });
        ui.separator();
        match self.chat_tab {
            ChatTab::Private => self.ui_private_chat(ui),
            ChatTab::Group => self.ui_group_chat(ui),
            ChatTab::Shanway => self.ui_shanway_chat(ui),
        }
    }

    fn ui_private_chat(&mut self, ui: &mut egui::Ui) {
        let Some(username) = self.current_username() else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label("Kontakt");
            ui.add(TextEdit::singleline(&mut self.private_partner_input).desired_width(180.0));
            if ui.button("Setzen").clicked() {
                let candidate = self.private_partner_input.trim();
                if !candidate.is_empty() {
                    self.selected_private_partner = candidate.to_owned();
                    self.private_partner_input.clear();
                }
            }
        });
        let threads = self.state_store.private_threads_for(&username);
        egui::ScrollArea::vertical()
            .max_height(180.0)
            .show(ui, |ui| {
                for thread in threads {
                    let label = format!("{} ({})", thread.partner_name, thread.messages.len());
                    if ui
                        .selectable_label(
                            self.selected_private_partner == thread.partner_name,
                            label,
                        )
                        .clicked()
                    {
                        self.selected_private_partner = thread.partner_name.clone();
                    }
                }
            });
        ui.separator();
        let messages = self
            .state_store
            .private_threads_for(&username)
            .into_iter()
            .find(|thread| thread.partner_name == self.selected_private_partner)
            .map(|thread| thread.messages)
            .unwrap_or_default();
        egui::ScrollArea::vertical()
            .max_height(180.0)
            .show(ui, |ui| {
                for message in messages {
                    ui.label(format!("{}: {}", message.author, message.body));
                }
            });
        ui.add(
            TextEdit::multiline(&mut self.private_message_input)
                .desired_rows(3)
                .hint_text("Nachricht eingeben"),
        );
        ui.horizontal(|ui| {
            if ui.button("Senden").clicked() {
                let body = self.private_message_input.trim().to_owned();
                if !body.is_empty() {
                    let thread = self.state_store.private_thread(&username, &self.selected_private_partner);
                    thread.messages.push(ChatMessage {
                        author: username.clone(),
                        body,
                    });
                    let _ = self.state_store.save();
                    self.private_message_input.clear();
                }
            }
            if ui.button("Senden + Relay").clicked() {
                let body = self.private_message_input.trim().to_owned();
                if !body.is_empty() {
                    let partner = self.selected_private_partner.clone();
                    let thread = self.state_store.private_thread(&username, &partner);
                    thread.messages.push(ChatMessage {
                        author: username.clone(),
                        body: body.clone(),
                    });
                    let _ = self.state_store.save();
                    self.private_message_input.clear();
                    self.queue_consent(
                        "Private Nachricht ins Relay geben",
                        format!(
                            "Die Nachricht wird verschluesselt als Relay-Ereignis veroeffentlicht.\nKontakt: {}\nDefault bleibt Nein.",
                            partner
                        ),
                        ConsentAction::ChatRelayPublishBatch {
                            envelopes: vec![QueuedRelayEnvelope {
                                room_kind: "private".to_owned(),
                                room_name: partner,
                                author: username.clone(),
                                body,
                            }],
                        },
                    );
                }
            }
        });
    }

    fn ui_group_chat(&mut self, ui: &mut egui::Ui) {
        let Some(username) = self.current_username() else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label("Gruppe");
            ui.add(TextEdit::singleline(&mut self.group_name_input).desired_width(180.0));
            if ui.button("Setzen").clicked() {
                let candidate = self.group_name_input.trim();
                if !candidate.is_empty() {
                    self.selected_group_name = candidate.to_owned();
                    self.group_name_input.clear();
                }
            }
        });
        let rooms = self.state_store.group_rooms_for(&username);
        egui::ScrollArea::vertical()
            .max_height(180.0)
            .show(ui, |ui| {
                for room in rooms {
                    let label = format!("{} ({})", room.name, room.messages.len());
                    if ui
                        .selectable_label(self.selected_group_name == room.name, label)
                        .clicked()
                    {
                        self.selected_group_name = room.name.clone();
                    }
                }
            });
        ui.separator();
        let messages = self
            .state_store
            .group_rooms_for(&username)
            .into_iter()
            .find(|room| room.name == self.selected_group_name)
            .map(|room| room.messages)
            .unwrap_or_default();
        egui::ScrollArea::vertical()
            .max_height(180.0)
            .show(ui, |ui| {
                for message in messages {
                    ui.label(format!("{}: {}", message.author, message.body));
                }
            });
        ui.add(
            TextEdit::multiline(&mut self.group_message_input)
                .desired_rows(3)
                .hint_text("Gruppennachricht eingeben"),
        );
        ui.horizontal(|ui| {
            if ui.button("In Gruppe senden").clicked() {
                let body = self.group_message_input.trim().to_owned();
                if !body.is_empty() {
                    let room = self.state_store.group_room(&username, &self.selected_group_name);
                    room.messages.push(ChatMessage {
                        author: username.clone(),
                        body,
                    });
                    let _ = self.state_store.save();
                    self.group_message_input.clear();
                }
            }
            if ui.button("Gruppe + Relay").clicked() {
                let body = self.group_message_input.trim().to_owned();
                if !body.is_empty() {
                    let room_name = self.selected_group_name.clone();
                    let room = self.state_store.group_room(&username, &room_name);
                    room.messages.push(ChatMessage {
                        author: username.clone(),
                        body: body.clone(),
                    });
                    let _ = self.state_store.save();
                    self.group_message_input.clear();
                    self.queue_consent(
                        "Gruppennachricht ins Relay geben",
                        format!(
                            "Die Gruppennachricht wird verschluesselt fuer den Raum '{}' veroeffentlicht.\nDefault bleibt Nein.",
                            room_name
                        ),
                        ConsentAction::ChatRelayPublishBatch {
                            envelopes: vec![QueuedRelayEnvelope {
                                room_kind: "group".to_owned(),
                                room_name,
                                author: username.clone(),
                                body,
                            }],
                        },
                    );
                }
            }
        });
    }

    fn ui_shanway_chat(&mut self, ui: &mut egui::Ui) {
        let Some(username) = self.current_username() else {
            return;
        };
        let messages = self
            .state_store
            .private_threads_for(&username)
            .into_iter()
            .find(|thread| thread.partner_name == "Shanway")
            .map(|thread| thread.messages)
            .unwrap_or_default();
        egui::ScrollArea::vertical()
            .max_height(300.0)
            .show(ui, |ui| {
                for message in &messages {
                    ui.label(format!("{}: {}", message.author, message.body));
                }
            });
        ui.add(
            TextEdit::multiline(&mut self.shanway_message_input)
                .desired_rows(4)
                .hint_text("Frage an Shanway"),
        );
        let mut send_local = false;
        let mut send_relay = false;
        ui.horizontal(|ui| {
            send_local = ui.button("An Shanway senden").clicked();
            send_relay = ui.button("An Shanway senden + Relay").clicked();
        });
        if send_local || send_relay {
            let prompt = self.shanway_message_input.trim().to_owned();
            if !prompt.is_empty() {
                let active_signal = self
                    .current_file
                    .as_ref()
                    .cloned()
                    .or_else(|| {
                        self.browser_probe
                            .as_ref()
                            .map(build_browser_processed_file)
                    })
                    .map(|file| build_processed_signal(&file));
                if let Some(signal) = active_signal.as_ref() {
                    self.mind_model
                        .learn_from_user_prompt(self.observer_id, signal, &prompt);
                }
                let shanway_input = self.current_shanway_input();
                let raw_reply = render_shanway_reply(shanway_input.as_ref(), &prompt);
                let reply = if let Some(signal) = active_signal.as_ref() {
                    let observer_delta = self
                        .mind_model
                        .calculate_observer_delta(signal, self.observer_id);
                    let adapted = ToMOutputAdapter::adapt_output(
                        &raw_reply,
                        &observer_delta,
                        self.mind_model.observer_model(self.observer_id),
                    );
                    self.mind_model.record_interaction(
                        self.observer_id,
                        signal.signal_hash,
                        adapted.depth_used,
                        map_text_signal_to_comprehension(&prompt),
                    );
                    if let Some(bridge_note) = adapted.bridge_note {
                        format!("{}\n[Observer Bridge] {}", adapted.content, bridge_note)
                    } else {
                        adapted.content
                    }
                } else {
                    raw_reply
                };
                let shanway_thread = self.state_store.private_thread(&username, "Shanway");
                shanway_thread.messages.push(ChatMessage {
                    author: username.clone(),
                    body: prompt.clone(),
                });
                shanway_thread.messages.push(ChatMessage {
                    author: "Shanway".to_owned(),
                    body: reply.clone(),
                });
                let _ = self.state_store.save();
                if send_relay {
                    self.queue_consent(
                        "Shanway-Dialog ins Relay geben",
                        "Prompt und strukturelle Shanway-Antwort werden verschluesselt in den Shanway-Raum gelegt. Default bleibt Nein.",
                        ConsentAction::ChatRelayPublishBatch {
                            envelopes: vec![
                                QueuedRelayEnvelope {
                                    room_kind: "shanway".to_owned(),
                                    room_name: "Shanway".to_owned(),
                                    author: username.clone(),
                                    body: prompt,
                                },
                                QueuedRelayEnvelope {
                                    room_kind: "shanway".to_owned(),
                                    room_name: "Shanway".to_owned(),
                                    author: "Shanway".to_owned(),
                                    body: reply,
                                },
                            ],
                        },
                    );
                }
                self.shanway_message_input.clear();
            }
        }
    }

    fn preview_existing_file(
        &mut self,
        path: &Path,
        ctx: &egui::Context,
    ) -> Result<ProcessedFile, String> {
        let bytes =
            fs::read(path).map_err(|err| format!("Datei konnte nicht gelesen werden: {err}"))?;
        let metadata = fs::metadata(path)
            .map_err(|err| format!("Metadaten konnten nicht gelesen werden: {err}"))?;
        let fingerprint_hash = sha256_hex(&bytes);
        let original_size = metadata.len();
        let delta_size = estimate_compressed_size(&bytes)?;
        let ratio = if original_size == 0 {
            0.0
        } else {
            delta_size as f32 / original_size as f32
        };
        let compression_gain_percent = ((1.0 - ratio).clamp(0.0, 1.0) * 10000.0).round() / 100.0;
        let entropy = shannon_entropy(&bytes);
        let preview = build_preview_image(path, &bytes);
        let symmetry = preview_symmetry(&preview);
        let drift = byte_drift(&bytes);
        let source_kind = detect_source_kind(path, &bytes);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unbekannt")
            .to_owned();
        let preview_note = format!(
            "{} | Entropie {:.2} bit | Symmetrie {:.1}% | Drift {:.2}",
            source_kind,
            entropy,
            symmetry * 100.0,
            drift
        );
        let anchor_summary = build_anchor_summary(entropy, symmetry, drift);
        let process_summary =
            build_process_summary(entropy, symmetry, compression_gain_percent, &source_kind);
        let excerpt = build_excerpt(&source_kind, &bytes);
        self.preview_texture = Some(ctx.load_texture(
            format!("preview::{file_name}"),
            preview,
            egui::TextureOptions::LINEAR,
        ));
        Ok(ProcessedFile {
            file_name,
            full_path: path.to_string_lossy().to_string(),
            fingerprint_hash,
            source_kind,
            original_size,
            delta_size,
            compression_gain_percent,
            entropy,
            symmetry,
            drift,
            anchor_summary,
            process_summary,
            preview_note,
            excerpt,
        })
    }

    fn ui_register_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(username) = self.current_username() else {
            return;
        };
        let entries = self.state_store.entries_for(&username);
        ui.label(RichText::new("Lokales Register").strong());
        ui.label("Ein Klick laedt die Datei kompakt in die Vorschau. Keine Vollbild-Uebernahme.");
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("register_grid")
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("ID");
                    ui.strong("Datei");
                    ui.strong("Typ");
                    ui.strong("Original");
                    ui.strong("Delta");
                    ui.strong("Gewinn");
                    ui.end_row();
                    for entry in entries {
                        let selected = self.selected_register_id == Some(entry.id);
                        if ui
                            .selectable_label(selected, entry.id.to_string())
                            .clicked()
                        {
                            self.load_register_entry(ctx, &entry);
                        }
                        if ui.selectable_label(selected, &entry.file_name).clicked() {
                            self.load_register_entry(ctx, &entry);
                        }
                        ui.label(&entry.source_kind);
                        ui.label(format!("{} B", entry.original_size));
                        ui.label(format!("{} B", entry.delta_size));
                        ui.label(format!("{:.2}%", entry.compression_gain_percent));
                        ui.end_row();
                    }
                });
        });
    }
}

impl eframe::App for AetherRustShell {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_bus_publish_requests();
        self.drain_bus_events();
        if self.current_user.is_none() {
            self.ui_auth(ctx);
            return;
        }
        self.handle_dropped_files(ctx);
        self.ui_left_panel(ctx);
        egui::TopBottomPanel::top("main_tabs_top").show(ctx, |ui| self.ui_top_tabs(ui));
        egui::CentralPanel::default().show(ctx, |ui| match self.top_tab {
            TopTab::Analyse => self.ui_analyse_tab(ui),
            TopTab::Struktur => self.ui_struktur_tab(ui),
            TopTab::Browser => self.ui_browser_tab(ui),
            TopTab::Chats => self.ui_chats_tab(ui),
            TopTab::Register => self.ui_register_tab(ui, ctx),
        });
        self.ui_consent_dialog(ctx);
    }
}

fn build_processed_signal(file: &ProcessedFile) -> ProcessedSignal {
    ProcessedSignal::from_summary(
        format!(
            "{} | {} | {}",
            file.file_name, file.anchor_summary, file.process_summary
        ),
        vec![domain_from_source_kind(&file.source_kind)],
    )
}

fn build_browser_processed_file(probe: &BrowserProbeResult) -> ProcessedFile {
    let file_name = if probe.title.trim().is_empty() {
        probe.final_url.clone()
    } else {
        probe.title.clone()
    };
    let summary = if probe.summary.trim().is_empty() {
        trimmed_at_boundary(&probe.text_sample, 240)
    } else {
        trimmed_at_boundary(&probe.summary, 240)
    };
    ProcessedFile {
        file_name,
        full_path: probe.final_url.clone(),
        fingerprint_hash: sha256_hex(probe.final_url.as_bytes()),
        source_kind: format!("Browser {}", probe.category),
        original_size: probe.content_length as u64,
        delta_size: (probe.content_length as f32 * probe.risk_score.clamp(0.0, 1.0)) as u64,
        compression_gain_percent: ((1.0 - probe.risk_score.clamp(0.0, 1.0)) * 100.0)
            .clamp(0.0, 100.0),
        entropy: probe.entropy,
        symmetry: probe.frontend_symmetry.clamp(0.0, 1.0),
        drift: (probe.risk_score * 255.0).clamp(0.0, 255.0),
        anchor_summary: probe.risk_reasons.join(" | "),
        process_summary: format!("{} | {}", probe.frontend_summary, probe.backend_summary),
        preview_note: summary.clone(),
        excerpt: summary,
    }
}

fn build_usage_profile(file: &ProcessedFile, current_hit_rate: f32) -> UsageProfile {
    UsageProfile {
        dominant_domains: vec![(domain_from_source_kind(&file.source_kind), 1.0)],
        active_signal_types: vec![signal_type_from_source_kind(&file.source_kind)],
        current_hit_rate,
    }
}

fn domain_from_source_kind(source_kind: &str) -> String {
    let normalized = source_kind.to_ascii_lowercase();
    if normalized.contains("text") || normalized.contains("code") || normalized.contains("pdf") {
        "language_german".to_owned()
    } else if normalized.contains("bild") {
        "image_editing".to_owned()
    } else if normalized.contains("audio") {
        "audio_production".to_owned()
    } else if normalized.contains("video") {
        "video_editing".to_owned()
    } else {
        "security".to_owned()
    }
}

fn signal_type_from_source_kind(source_kind: &str) -> SignalType {
    let normalized = source_kind.to_ascii_lowercase();
    if normalized.contains("pdf") {
        SignalType::Pdf
    } else if normalized.contains("html") || normalized.contains("browser") {
        SignalType::Html
    } else if normalized.contains("audio") {
        SignalType::AudioTranscript
    } else if normalized.contains("code") {
        SignalType::Code
    } else if normalized.contains("text") {
        SignalType::PlainText
    } else {
        SignalType::Unknown
    }
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

fn map_text_signal_to_comprehension(prompt: &str) -> ComprehensionSignal {
    match ComprehensionDetector::detect_text_signal(prompt) {
        crate::theory_of_mind::TextSignal::Confusion => ComprehensionSignal::NotUnderstood,
        crate::theory_of_mind::TextSignal::AlreadyFamiliar => ComprehensionSignal::AlreadyKnew,
        crate::theory_of_mind::TextSignal::Understood => ComprehensionSignal::Understood,
        crate::theory_of_mind::TextSignal::Neutral => ComprehensionSignal::Unknown,
    }
}

fn trimmed_at_boundary(source: &str, limit: usize) -> String {
    let normalized = source.trim();
    if normalized.is_empty() || limit == 0 {
        return String::new();
    }
    let mut output = String::new();
    for (index, ch) in normalized.chars().enumerate() {
        if index >= limit {
            let trimmed = output
                .trim_end_matches(|candidate: char| {
                    candidate.is_whitespace()
                        || matches!(candidate, ',' | '.' | ';' | ':' | '!' | '?')
                })
                .to_owned();
            return format!("{trimmed}...");
        }
        output.push(ch);
    }
    output
}

fn push_message_if_new(messages: &mut Vec<ChatMessage>, author: String, body: String) {
    let is_duplicate = messages
        .iter()
        .rev()
        .take(12)
        .any(|message| message.author == author && message.body == body);
    if !is_duplicate {
        messages.push(ChatMessage { author, body });
    }
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

fn build_excerpt(source_kind: &str, bytes: &[u8]) -> String {
    if source_kind == "Text / Code" || source_kind == "PDF" {
        if let Ok(text) = String::from_utf8(bytes.iter().copied().take(2400).collect()) {
            return text
                .replace('\r', "")
                .replace('\0', " ")
                .chars()
                .take(420)
                .collect();
        }
    }
    let hex: Vec<String> = bytes
        .iter()
        .take(64)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("Hex-Anriss: {}", hex.join(" "))
}

fn estimate_compressed_size(bytes: &[u8]) -> Result<u64, String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .map_err(|err| format!("Kompressionsprobe fehlgeschlagen: {err}"))?;
    let output = encoder
        .finish()
        .map_err(|err| format!("Kompressionsprobe konnte nicht abgeschlossen werden: {err}"))?;
    Ok(output.len() as u64)
}

fn shannon_entropy(bytes: &[u8]) -> f32 {
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

fn byte_drift(bytes: &[u8]) -> f32 {
    if bytes.len() < 2 {
        return 0.0;
    }
    let total: u64 = bytes
        .windows(2)
        .map(|window| (window[0] as i32 - window[1] as i32).unsigned_abs() as u64)
        .sum();
    total as f32 / bytes.len().saturating_sub(1) as f32
}

fn build_anchor_summary(entropy: f32, symmetry: f32, drift: f32) -> String {
    let noether = if symmetry >= 0.82 {
        "Noether: starke Invarianzfelder"
    } else if symmetry >= 0.62 {
        "Noether: teilweise erhaltene Invarianten"
    } else {
        "Noether: Symmetriebruch dominant"
    };
    let mandelbrot = if drift <= 36.0 {
        "Mandelbrot: wiederkehrende lokale Formen"
    } else {
        "Mandelbrot: stark zerstreute Byte-Landschaft"
    };
    let heisenberg = if entropy >= 6.0 {
        "Heisenberg: Beobachtergrenze hoch"
    } else {
        "Heisenberg: Beobachtergrenze kontrollierbar"
    };
    format!(
        "{noether} | {mandelbrot} | {heisenberg} | Entropie {:.2}",
        entropy
    )
}

fn build_process_summary(
    entropy: f32,
    symmetry: f32,
    compression_gain_percent: f32,
    source_kind: &str,
) -> String {
    format!(
        "Quelle: {source_kind}\nVerdichtung: {:.2}% Gewinn\nEntropiepfad: {:.2} bit\nSymmetriestabilitaet: {:.1}%",
        compression_gain_percent,
        entropy,
        symmetry * 100.0
    )
}

fn apply_aether_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(Color32::from_rgb(224, 234, 246));
    visuals.panel_fill = Color32::from_rgb(8, 12, 20);
    visuals.window_fill = Color32::from_rgb(10, 16, 26);
    visuals.faint_bg_color = Color32::from_rgb(16, 24, 36);
    visuals.extreme_bg_color = Color32::from_rgb(13, 20, 32);
    visuals.code_bg_color = Color32::from_rgb(10, 16, 26);
    visuals.selection.bg_fill = Color32::from_rgb(54, 114, 192);
    visuals.selection.stroke = Stroke::new(1.0, Color32::from_rgb(150, 228, 248));
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(14, 20, 30);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(204, 216, 232));
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(18, 26, 40);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(194, 208, 226));
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(30, 44, 64);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::from_rgb(234, 242, 250));
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(112, 208, 232));
    visuals.widgets.active.bg_fill = Color32::from_rgb(48, 96, 164);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, Color32::from_rgb(144, 226, 246));
    ctx.set_visuals(visuals.clone());

    let mut style = (*ctx.style()).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(10.0, 10.0);
    style.spacing.button_padding = Vec2::new(14.0, 8.0);
    style.spacing.window_margin = egui::Margin::same(12);
    style.spacing.indent = 18.0;
    ctx.set_style(style);
}

fn paint_aether_backdrop(painter: &egui::Painter, rect: Rect) {
    painter.rect_filled(rect, 0.0, Color32::from_rgb(7, 11, 18));
    painter.circle_filled(
        egui::pos2(
            rect.left() + rect.width() * 0.16,
            rect.top() + rect.height() * 0.18,
        ),
        rect.width() * 0.18,
        Color32::from_rgba_unmultiplied(38, 132, 168, 28),
    );
    painter.circle_filled(
        egui::pos2(
            rect.right() - rect.width() * 0.12,
            rect.top() + rect.height() * 0.24,
        ),
        rect.width() * 0.14,
        Color32::from_rgba_unmultiplied(248, 184, 88, 20),
    );
    painter.circle_filled(
        egui::pos2(rect.center().x, rect.bottom() - rect.height() * 0.12),
        rect.width() * 0.22,
        Color32::from_rgba_unmultiplied(90, 114, 208, 20),
    );
    for step in 0..12 {
        let x = lerp_f32(rect.left(), rect.right(), step as f32 / 11.0);
        painter.line_segment(
            [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(120, 146, 180, 10)),
        );
    }
}

fn render_interference_map(painter: egui::Painter, rect: Rect, metrics: VisualizationMetrics) {
    painter.rect_filled(rect, 12.0, Color32::from_rgb(9, 14, 24));
    let inner = rect.shrink2(Vec2::new(10.0, 10.0));
    for step in 0..10 {
        let x = lerp_f32(inner.left(), inner.right(), step as f32 / 9.0);
        painter.line_segment(
            [Pos2::new(x, inner.top()), Pos2::new(x, inner.bottom())],
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(72, 102, 136, 20)),
        );
    }
    for step in 0..7 {
        let y = lerp_f32(inner.top(), inner.bottom(), step as f32 / 6.0);
        painter.line_segment(
            [Pos2::new(inner.left(), y), Pos2::new(inner.right(), y)],
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(72, 102, 136, 16)),
        );
    }
    for line_idx in 0..4 {
        let mut points = Vec::new();
        let base_y = inner.center().y + (line_idx as f32 - 1.5) * 28.0;
        let amplitude = 10.0 + metrics.resonance * 24.0 + line_idx as f32 * 3.0;
        let phase = metrics.entropy_norm * std::f32::consts::TAU * (1.0 + line_idx as f32 * 0.12);
        let frequency = 1.1 + metrics.anchor_density * 2.8 + line_idx as f32 * 0.35;
        for step in 0..72 {
            let t = step as f32 / 71.0;
            let x = lerp_f32(inner.left(), inner.right(), t);
            let wave = (t * std::f32::consts::TAU * frequency + phase).sin() * amplitude;
            let drift = (t * std::f32::consts::TAU * 0.65 + metrics.drift_norm * 5.0).cos()
                * metrics.drift_norm
                * 12.0;
            points.push(Pos2::new(x, base_y + wave + drift));
        }
        let color = mix_color(
            Color32::from_rgb(42, 120, 152),
            Color32::from_rgb(130, 244, 255),
            (metrics.resonance * 0.75 + line_idx as f32 * 0.08).clamp(0.0, 1.0),
        );
        painter.add(egui::Shape::line(points, Stroke::new(1.6, color)));
    }
    for node_idx in 0..5 {
        let t = 0.12 + node_idx as f32 * 0.19;
        let x = lerp_f32(inner.left(), inner.right(), t);
        let y = inner.center().y
            + ((t * std::f32::consts::TAU * (1.4 + metrics.coverage) + metrics.resonance * 2.2)
                .sin()
                * 22.0);
        let radius = 3.0 + metrics.coherence * 5.5 + node_idx as f32 * 0.25;
        painter.circle_filled(
            Pos2::new(x, y),
            radius,
            Color32::from_rgba_unmultiplied(190, 250, 255, 220),
        );
        painter.circle_stroke(
            Pos2::new(x, y),
            radius + 4.0,
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(110, 210, 255, 60)),
        );
    }
    for hole_idx in 0..3 {
        let t = 0.18 + hole_idx as f32 * 0.28;
        let x = lerp_f32(inner.left(), inner.right(), t);
        let y = inner.bottom() - 42.0 - hole_idx as f32 * 24.0 + metrics.drift_norm * 18.0;
        let radius = 10.0 + metrics.drift_norm * 16.0 + hole_idx as f32 * 2.0;
        painter.circle_filled(
            Pos2::new(x, y),
            radius,
            Color32::from_rgba_unmultiplied(4, 6, 9, 180),
        );
        painter.circle_stroke(
            Pos2::new(x, y),
            radius + 3.0,
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 90, 64, 46)),
        );
    }
    painter.text(
        Pos2::new(inner.left() + 4.0, inner.top() + 2.0),
        Align2::LEFT_TOP,
        "in phase",
        FontId::proportional(11.0),
        Color32::from_rgb(150, 225, 235),
    );
    painter.text(
        Pos2::new(inner.right() - 4.0, inner.bottom() - 2.0),
        Align2::RIGHT_BOTTOM,
        "drift / loss",
        FontId::proportional(11.0),
        Color32::from_rgb(214, 114, 96),
    );
}

fn render_delta_heatmap(painter: egui::Painter, rect: Rect, metrics: VisualizationMetrics) {
    painter.rect_filled(rect, 12.0, Color32::from_rgb(11, 16, 26));
    let labels = ["CPU", "IO", "RAM", "VRAM", "Netz", "Scheduler"];
    let values = [
        (0.46 * metrics.drift_norm + 0.28 * metrics.entropy_norm + 0.26 * (1.0 - metrics.trust))
            .clamp(0.0, 1.0),
        (0.44 * metrics.residual_ratio
            + 0.32 * metrics.projection_gain
            + 0.24 * (1.0 - metrics.coverage))
            .clamp(0.0, 1.0),
        (0.40 * metrics.entropy_norm + 0.34 * metrics.drift_norm + 0.26 * metrics.godel_zone)
            .clamp(0.0, 1.0),
        (0.52 * (1.0 - metrics.hit_rate)
            + 0.28 * metrics.anchor_density
            + 0.20 * metrics.resonance)
            .clamp(0.0, 1.0),
        (0.56 * metrics.network_pressure + 0.24 * metrics.godel_zone + 0.20 * metrics.drift_norm)
            .clamp(0.0, 1.0),
        (0.36 * (1.0 - metrics.coherence)
            + 0.34 * metrics.projection_gain
            + 0.30 * metrics.resonance)
            .clamp(0.0, 1.0),
    ];
    let inner = rect.shrink2(Vec2::new(12.0, 12.0));
    let gap = 8.0;
    let cell_w = (inner.width() - gap * 2.0) / 3.0;
    let cell_h = (inner.height() - gap) / 2.0;
    for index in 0..labels.len() {
        let row = index / 3;
        let col = index % 3;
        let x = inner.left() + col as f32 * (cell_w + gap);
        let y = inner.top() + row as f32 * (cell_h + gap);
        let cell = Rect::from_min_size(Pos2::new(x, y), Vec2::new(cell_w, cell_h));
        let fill = heat_color(values[index]);
        painter.rect_filled(cell, 10.0, fill);
        painter.rect_filled(
            Rect::from_min_max(
                cell.min,
                Pos2::new(cell.max.x, cell.min.y + cell.height() * 0.26),
            ),
            10.0,
            Color32::from_rgba_unmultiplied(255, 255, 255, 18),
        );
        painter.text(
            Pos2::new(cell.left() + 10.0, cell.top() + 10.0),
            Align2::LEFT_TOP,
            labels[index],
            FontId::proportional(13.0),
            Color32::WHITE,
        );
        painter.text(
            cell.center(),
            Align2::CENTER_CENTER,
            format!("{:.0}%", values[index] * 100.0),
            FontId::proportional(22.0),
            Color32::from_rgb(246, 248, 250),
        );
        let state = if values[index] < 0.35 {
            "stabil"
        } else if values[index] < 0.68 {
            "drift"
        } else {
            "emergent"
        };
        painter.text(
            Pos2::new(cell.left() + 10.0, cell.bottom() - 10.0),
            Align2::LEFT_BOTTOM,
            state,
            FontId::proportional(11.0),
            Color32::from_rgba_unmultiplied(255, 255, 255, 210),
        );
    }
}

fn render_symmetry_break_radar(painter: egui::Painter, rect: Rect, metrics: VisualizationMetrics) {
    painter.rect_filled(rect, 12.0, Color32::from_rgb(10, 15, 24));
    let labels = ["IO", "CPU", "Memory", "Network", "Telemetry", "GPU"];
    let values = [
        (0.30 + 0.44 * metrics.coverage + 0.26 * (1.0 - metrics.residual_ratio)).clamp(0.0, 1.0),
        (0.24 + 0.36 * metrics.coherence + 0.40 * (1.0 - metrics.drift_norm)).clamp(0.0, 1.0),
        (0.28 + 0.40 * metrics.symmetry + 0.32 * (1.0 - metrics.entropy_norm)).clamp(0.0, 1.0),
        (0.20 + 0.58 * (1.0 - metrics.network_pressure) + 0.22 * metrics.trust).clamp(0.0, 1.0),
        (0.22 + 0.44 * (1.0 - metrics.godel_zone) + 0.34 * metrics.trust).clamp(0.0, 1.0),
        (0.24 + 0.42 * metrics.anchor_density + 0.34 * metrics.hit_rate).clamp(0.0, 1.0),
    ];
    let center = rect.center();
    let radius = rect.width().min(rect.height()) * 0.30;
    for ring in [0.25, 0.50, 0.75, 1.0] {
        let mut ring_points = Vec::new();
        for idx in 0..labels.len() {
            let angle = std::f32::consts::FRAC_PI_2
                - idx as f32 / labels.len() as f32 * std::f32::consts::TAU;
            ring_points.push(polar_point(center, radius * ring, angle));
        }
        ring_points.push(ring_points[0]);
        painter.add(egui::Shape::line(
            ring_points,
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(110, 136, 160, 36)),
        ));
    }
    let expected_radius = (0.56 + metrics.resonance * 0.14).clamp(0.0, 1.0);
    let mut expected_points = Vec::new();
    let mut actual_points = Vec::new();
    for idx in 0..labels.len() {
        let angle =
            std::f32::consts::FRAC_PI_2 - idx as f32 / labels.len() as f32 * std::f32::consts::TAU;
        let outer = polar_point(center, radius * 1.08, angle);
        painter.line_segment(
            [center, outer],
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(110, 136, 160, 34)),
        );
        painter.text(
            polar_point(center, radius * 1.24, angle),
            Align2::CENTER_CENTER,
            labels[idx],
            FontId::proportional(11.0),
            Color32::from_rgb(206, 216, 228),
        );
        expected_points.push(polar_point(center, radius * expected_radius, angle));
        actual_points.push(polar_point(center, radius * values[idx], angle));
    }
    expected_points.push(expected_points[0]);
    painter.add(egui::Shape::line(
        expected_points.clone(),
        Stroke::new(1.2, Color32::from_rgba_unmultiplied(150, 180, 220, 110)),
    ));
    painter.add(egui::Shape::convex_polygon(
        actual_points.clone(),
        Color32::from_rgba_unmultiplied(86, 214, 199, 26),
        Stroke::new(2.0, Color32::from_rgb(88, 224, 206)),
    ));
    for idx in 0..labels.len() {
        let gap = (expected_radius - values[idx]).abs();
        if gap > 0.12 {
            painter.line_segment(
                [expected_points[idx], actual_points[idx]],
                Stroke::new(1.2, Color32::from_rgba_unmultiplied(255, 102, 90, 110)),
            );
            painter.circle_stroke(
                actual_points[idx],
                4.0,
                Stroke::new(1.5, Color32::from_rgb(255, 120, 96)),
            );
        } else {
            painter.circle_filled(actual_points[idx], 3.0, Color32::from_rgb(198, 255, 240));
        }
    }
}

fn render_resonance_spectrum(painter: egui::Painter, rect: Rect, metrics: VisualizationMetrics) {
    painter.rect_filled(rect, 12.0, Color32::from_rgb(8, 13, 24));
    let inner = rect.shrink2(Vec2::new(14.0, 14.0));
    let baseline = inner.bottom() - 18.0;
    painter.line_segment(
        [
            Pos2::new(inner.left(), baseline),
            Pos2::new(inner.right(), baseline),
        ],
        Stroke::new(1.0, Color32::from_rgba_unmultiplied(150, 170, 196, 52)),
    );
    let bins = 18;
    let step_w = inner.width() / bins as f32;
    for idx in 0..bins {
        let t = idx as f32 / (bins.saturating_sub(1)) as f32;
        let constructive = ((t * std::f32::consts::TAU * (1.2 + metrics.anchor_density * 2.4)
            + metrics.resonance * std::f32::consts::TAU)
            .sin()
            .abs()
            * 0.54
            + metrics.resonance * 0.30
            + metrics.coverage * 0.16)
            .clamp(0.0, 1.0);
        let destructive = ((t * std::f32::consts::TAU * (1.8 + metrics.godel_zone * 2.0)
            + metrics.drift_norm * 3.8)
            .cos()
            .abs()
            * 0.24
            + metrics.residual_ratio * 0.10)
            .clamp(0.0, 1.0);
        let amplitude = (constructive - destructive * 0.72).clamp(0.05, 1.0);
        let x = inner.left() + step_w * idx as f32 + step_w * 0.18;
        let bar_w = step_w * 0.64;
        let bar_h = amplitude * (inner.height() - 26.0);
        let bar = Rect::from_min_max(
            Pos2::new(x, baseline - bar_h),
            Pos2::new(x + bar_w, baseline),
        );
        let fill = mix_color(
            Color32::from_rgb(42, 112, 182),
            Color32::from_rgb(255, 214, 92),
            amplitude,
        );
        let fill = mix_color(
            fill,
            Color32::from_rgb(255, 120, 82),
            metrics.godel_zone * 0.35,
        );
        painter.rect_filled(bar, 4.0, fill);
        if amplitude > 0.78 {
            painter.circle_filled(
                Pos2::new(bar.center().x, bar.top() - 4.0),
                3.5,
                Color32::from_rgb(255, 244, 192),
            );
        }
        if amplitude < 0.22 {
            painter.line_segment(
                [
                    Pos2::new(bar.left(), baseline - 8.0),
                    Pos2::new(bar.right(), baseline - 8.0),
                ],
                Stroke::new(1.2, Color32::from_rgba_unmultiplied(110, 150, 196, 120)),
            );
        }
    }
    painter.text(
        Pos2::new(inner.left(), inner.top()),
        Align2::LEFT_TOP,
        "constructive",
        FontId::proportional(11.0),
        Color32::from_rgb(255, 220, 122),
    );
    painter.text(
        Pos2::new(inner.right(), baseline + 10.0),
        Align2::RIGHT_TOP,
        "destructive valleys",
        FontId::proportional(11.0),
        Color32::from_rgb(120, 166, 214),
    );
}

fn heat_color(value: f32) -> Color32 {
    let value = value.clamp(0.0, 1.0);
    let cold = Color32::from_rgb(38, 104, 184);
    let warm = Color32::from_rgb(246, 208, 76);
    let hot = Color32::from_rgb(236, 86, 64);
    if value <= 0.5 {
        mix_color(cold, warm, value * 2.0)
    } else {
        mix_color(warm, hot, (value - 0.5) * 2.0)
    }
}

fn mix_color(from: Color32, to: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let r = lerp_f32(from.r() as f32, to.r() as f32, t).round() as u8;
    let g = lerp_f32(from.g() as f32, to.g() as f32, t).round() as u8;
    let b = lerp_f32(from.b() as f32, to.b() as f32, t).round() as u8;
    let a = lerp_f32(from.a() as f32, to.a() as f32, t).round() as u8;
    Color32::from_rgba_unmultiplied(r, g, b, a)
}

fn polar_point(center: Pos2, radius: f32, angle: f32) -> Pos2 {
    Pos2::new(
        center.x + radius * angle.cos(),
        center.y - radius * angle.sin(),
    )
}

fn lerp_f32(start: f32, end: f32, t: f32) -> f32 {
    start + (end - start) * t.clamp(0.0, 1.0)
}

fn load_local_vault_store() -> VaultStore {
    VaultStore::load_default().unwrap_or_default()
}

fn aef_output_path(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    let file_name = format!("{stem}.aef");
    PathBuf::from("data")
        .join("rust_shell")
        .join("aef")
        .join(file_name)
}

fn build_preview_image(path: &Path, bytes: &[u8]) -> ColorImage {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        extension.as_str(),
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tif" | "tiff" | "webp"
    ) {
        if let Ok(image) = image::load_from_memory(bytes) {
            let scaled = image.thumbnail(640, 360).to_rgba8();
            let size = [scaled.width() as usize, scaled.height() as usize];
            return ColorImage::from_rgba_unmultiplied(size, scaled.as_raw());
        }
    }
    let side = 128usize;
    let mut pixels = Vec::with_capacity(side * side);
    for index in 0..(side * side) {
        let value = bytes.get(index).copied().unwrap_or(0);
        pixels.push(Color32::from_rgb(value, value, value));
    }
    ColorImage::new([side, side], pixels)
}

fn color_image_rgba_bytes(image: &ColorImage) -> Vec<u8> {
    image
        .pixels
        .iter()
        .flat_map(|pixel| pixel.to_array())
        .collect()
}

fn placeholder_preview_image() -> ColorImage {
    let side = 128usize;
    let mut pixels = Vec::with_capacity(side * side);
    for y in 0..side {
        for x in 0..side {
            let value = if (x / 16 + y / 16) % 2 == 0 { 44 } else { 70 };
            pixels.push(Color32::from_rgb(value, value + 18, value + 28));
        }
    }
    ColorImage::new([side, side], pixels)
}

fn preview_symmetry(image: &ColorImage) -> f32 {
    let width = image.size[0];
    let height = image.size[1];
    if width < 2 || height == 0 {
        return 0.0;
    }
    let mut total_score = 0.0f32;
    let mut comparisons = 0usize;
    for y in 0..height {
        for x in 0..(width / 2) {
            let left = image.pixels[y * width + x];
            let right = image.pixels[y * width + (width - 1 - x)];
            let left_value = (left.r() as f32 + left.g() as f32 + left.b() as f32) / 3.0;
            let right_value = (right.r() as f32 + right.g() as f32 + right.b() as f32) / 3.0;
            total_score += 1.0 - ((left_value - right_value).abs() / 255.0).clamp(0.0, 1.0);
            comparisons += 1;
        }
    }
    if comparisons == 0 {
        0.0
    } else {
        total_score / comparisons as f32
    }
}
