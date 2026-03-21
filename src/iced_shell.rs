use crate::aef::{AefDecodeResult, AefDecoder, AefEncoder, EnginePipeline, VaultStore};
use crate::auth::{AuthStore, UserRecord};
use crate::browser::{
    BrowserInspector, BrowserProbePolicy, BrowserProbeResult, BrowserSearchContext,
};
use crate::browser_embed::{BrowserHostRect, EmbeddedBrowser};
use crate::ethics::{code_suspicion_score, structural_text_integrity};
use crate::key_vault::DataKey;
use crate::lab_boundary::{extract_stable_metrics, validate_response, LabResponse, LAB_SCHEMA_VERSION};
use crate::policy_executor::{default_analysis_rules, RuleEngine};
use crate::security::{SecurityAuditEvent, SecurityMonitor, SecuritySnapshot};
use crate::shanway::{render_reply as render_shanway_reply, ShanwayBrowserContext, ShanwayInput};
use crate::state::{ChatMessage, GroupRoom, PrivateThread, RegisterEntry, StateStore};
use iced::theme::Palette;
use iced::widget::{button, canvas, column, container, progress_bar, row, scrollable, text, text_input};
use iced::{
    application, event, mouse, time, window, Alignment, Background, Border, Color, Element,
    Length, Point, Rectangle, Settings, Subscription, Task, Theme,
};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use zeroize::Zeroize;

const BG_BASE: [u8; 3] = [0x0C, 0x0B, 0x12];
const BG_CARD: [u8; 3] = [0x14, 0x13, 0x1E];
const BG_CARD2: [u8; 3] = [0x1C, 0x1B, 0x2A];
const BORDER: [u8; 3] = [0x2E, 0x2C, 0x46];
const BORDER_ACT: [u8; 3] = [0xA0, 0x60, 0xFF];
const ACCENT: [u8; 3] = [0xA0, 0x60, 0xFF];
const ACCENT2: [u8; 3] = [0x00, 0xD4, 0xFF];
const TEXT_H: [u8; 3] = [0xF0, 0xEE, 0xFF];
const TEXT_M: [u8; 3] = [0x9E, 0x98, 0xC4];
const TEXT_D: [u8; 3] = [0x5C, 0x58, 0x82];
const WARN: [u8; 3] = [0xFF, 0xA0, 0x20];
const DANGER: [u8; 3] = [0xFF, 0x4C, 0x4C];

fn c(rgb: [u8; 3]) -> Color {
    Color::from_rgb8(rgb[0], rgb[1], rgb[2])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Home,
    Chat,
    Browser,
    YouTube,
    Data,
    Settings,
    Logs,
    Anchors,
    Imprint,
    StructureMap,
    ADE,
    Rekonstruktion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatContext {
    Private,
    Group,
    Shanway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeProfile {
    Auto,
    Balanced,
    LowPower,
    Legacy,
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
    DashboardSearchChanged(String),
    DashboardNavSelected(String),
    DashboardInfoToggle(String),
    SecurityRecheck,
    TutorialDismissed,
    AnchorGroupSelected(usize),
    ChatUserSearchChanged(String),
    PrivatePartnerSelected(String),
    PrivateMessageChanged(String),
    PrivateMessageSend,
    GroupMessageChanged(String),
    GroupMessageSend,
    ShanwayMessageChanged(String),
    ShanwayMessageSend,
    BrowserAddressChanged(String),
    BrowserSearchQueryChanged(String),
    BrowserLoadPressed,
    BrowserInspectPressed,
    BrowserSearchPressed,
    BrowserInspectCompleted(BrowserProbeResult),
    BrowserSearchCompleted(BrowserSearchContext),
    YouTubeAddressChanged(String),
    YouTubeLoadPressed,
    FileHovered(PathBuf),
    FileHoverCleared,
    FileDropped(PathBuf),
    FileAnalysisCompleted(Result<FileAnalysisResult, String>),
    ReconstructPressed(u64),
    ReconstructionCompleted(Result<(String, AefDecodeResult), String>),
    ExportPressed(u64),
    FlowSphereSnapshotSelected(usize),
    FlowSphereExportPressed,
    WindowResized(f32, f32),
    Tick,
}

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
    original_size: u64,
    delta_size: u64,
    compression_gain_percent: f32,
    anchor_summary: String,
    process_summary: String,
    preview_note: String,
}

#[derive(Debug, Clone)]
struct FileAnalysisResult {
    entry: RegisterEntry,
    snapshot: AnalysisSnapshot,
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
    login_username: String,
    login_password: String,
    status_line: String,
    active_tab: Tab,
    chat_context: ChatContext,
    show_tutorial: bool,
    selected_anchor_group: usize,
    chat_user_search: String,
    selected_private_partner: Option<String>,
    private_message_draft: String,
    group_message_draft: String,
    shanway_message_draft: String,
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
    window_width: f32,
    window_height: f32,
    tick_counter: u64,
    browser_sync_stride: u64,
    runtime_profile: RuntimeProfile,
    dashboard_search: String,
    dashboard_nav: String,
    dashboard_info_key: Option<String>,
    dashboard_info_open_tick: u64,
    // --- StructureMap / FlowSphere ---
    structure_map_nodes: Vec<Vec<f32>>,
    structure_map_compression: f32,
    structure_map_locked: bool,
    structure_map_anchor_hist: Vec<f32>,
    structure_map_mutation_hist: Vec<u32>,
    flow_sphere_snapshot_idx: usize,
    // --- YouTube ---
    youtube_address: String,
    // --- Rekonstruktion ---
    rekonstruktion_selected: Option<u64>,
    rekonstruktion_running: bool,
    rekonstruktion_result: Option<Result<(String, AefDecodeResult), String>>,
}

impl AetherIcedShell {
    fn bootstrap() -> Self {
        let mut shell = Self {
            auth_store: AuthStore::load_default(),
            state_store: StateStore::load_default(),
            security_monitor: SecurityMonitor::new(PathBuf::from(".")),
            current_user: None,
            data_key: None,
            data_key_fingerprint: String::new(),
            security_snapshot: SecuritySnapshot::default(),
            security_audit_events: Vec::new(),
            login_username: String::new(),
            login_password: String::new(),
            status_line: "Bitte lokal anmelden oder registrieren.".to_owned(),
            active_tab: Tab::Home,
            chat_context: ChatContext::Shanway,
            show_tutorial: false,
            selected_anchor_group: 0,
            chat_user_search: String::new(),
            selected_private_partner: None,
            private_message_draft: String::new(),
            group_message_draft: String::new(),
            shanway_message_draft: String::new(),
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
            window_width: 1560.0,
            window_height: 900.0,
            tick_counter: 0,
            browser_sync_stride: 3,
            runtime_profile: RuntimeProfile::Auto,
            dashboard_search: String::new(),
            dashboard_nav: "Overview".to_owned(),
            dashboard_info_key: None,
            dashboard_info_open_tick: 0,
            structure_map_nodes: Vec::new(),
            structure_map_compression: 0.0,
            structure_map_locked: false,
            structure_map_anchor_hist: Vec::new(),
            structure_map_mutation_hist: Vec::new(),
            flow_sphere_snapshot_idx: 0,
            youtube_address: "https://www.youtube.com/".to_owned(),
            rekonstruktion_selected: None,
            rekonstruktion_running: false,
            rekonstruktion_result: None,
        };
        shell.browser_sync_stride = shell.profile_browser_sync_stride();
        shell.refresh_security_snapshot(false, "startup");
        shell
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

    fn shanway_messages(&self) -> Vec<ChatMessage> {
        self.private_threads()
            .into_iter()
            .find(|thread| thread.partner_name == "Shanway")
            .map(|thread| thread.messages)
            .unwrap_or_default()
    }

    fn current_shanway_input(&self) -> Option<ShanwayInput> {
        let snapshot = self.last_analysis.as_ref()?;
        let original = snapshot.original_size.max(1) as f32;
        let delta = snapshot.delta_size as f32;
        let knowledge_ratio = (1.0 - (delta / original)).clamp(0.0, 1.0);
        let residual_ratio = (delta / original).clamp(0.0, 1.0);
        let e_lambda = (1.0 - knowledge_ratio).clamp(0.0, 1.0);
        let e_lambda_label = if e_lambda < 0.15 {
            "LATENT"
        } else if e_lambda < 0.35 {
            "EMERGING"
        } else if e_lambda < 0.60 {
            "ACTIVE"
        } else {
            "CRITICAL"
        };
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
                    .map(|context| context.summary.clone())
                    .unwrap_or_default(),
            });
        Some(ShanwayInput {
            file_name: snapshot.file_name.clone(),
            file_type: detect_file_type_from_name(&snapshot.file_name),
            entropy_mean: (1.0 - residual_ratio).clamp(0.0, 1.0) * 8.0,
            knowledge_ratio,
            symmetry_gini: (1.0 - knowledge_ratio).clamp(0.0, 1.0),
            delta_paths: 1,
            bayes_priors: "lokal kalibriert".to_owned(),
            residual_ratio,
            observer_mutual_info: knowledge_ratio,
            h_lambda: (1.0 - knowledge_ratio).clamp(0.0, 1.0),
            e_lambda,
            e_lambda_label: e_lambda_label.to_owned(),
            boundary: "LOCAL_ONLY".to_owned(),
            anchor_summary: snapshot.anchor_summary.clone(),
            process_summary: snapshot.process_summary.clone(),
            observer_context: None,
            pack_hints: Vec::new(),
            browser_context,
            public_ttd_status: Some("lokal deaktiviert".to_owned()),
        })
    }

    fn browser_embed_rect(&self) -> BrowserHostRect {
        if self.active_tab == Tab::Home
            && (self.dashboard_nav == "Network" || self.dashboard_nav == "Compute")
        {
            return BrowserHostRect {
                x: (self.window_width * 0.44) as i32,
                y: 178,
                width: (self.window_width * 0.52) as i32,
                height: (self.window_height - 210.0) as i32,
            }
            .normalized();
        }

        let right_column_x = 18.0 + 180.0 + 18.0;
        let main_width = (self.window_width - right_column_x - 18.0).max(900.0);
        let top_tabs_height = 58.0;
        let status_height = 30.0;
        let content_top = 18.0 + top_tabs_height + status_height + 12.0;
        let browser_inner_padding = 12.0;
        let control_column_width = 420.0;
        let split_gap = 18.0;
        BrowserHostRect {
            x: (right_column_x + browser_inner_padding + control_column_width + split_gap) as i32,
            y: (content_top + browser_inner_padding) as i32,
            width: (main_width - control_column_width - split_gap - browser_inner_padding * 2.0)
                as i32,
            height: (self.window_height - content_top - 24.0) as i32,
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

    fn tab_button(&self, tab: Tab, icon: &'static str, label: &'static str) -> Element<'_, Message> {
        let is_active = self.active_tab == tab;
        let accent = c(ACCENT);
        let text_active = c(TEXT_H);
        let text_idle = c(TEXT_D);

        container(
            button(
                column![
                    text(icon).size(16).color(if is_active { accent } else { text_idle }),
                    text(label).size(11).color(if is_active { text_active } else { text_idle }),
                ]
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
                color: if is_active { c(BORDER_ACT) } else { Color::TRANSPARENT },
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
        let left = container(
            column![
                text("AetherGuard").size(30).color(Color::from_rgb8(0xA0, 0x60, 0xFF)),
                text("Deterministic Security Kernel").size(34).color(c(TEXT_H)),
                text("Lokale Analyse, rekonstruierbare Entscheidungen und Privacy by Architecture.")
                    .size(14)
                    .color(c(TEXT_M)),
                text("Kein Cloud-Zwang. Keine Black Box. Keine versteckte Semantik.")
                    .size(13)
                    .color(c(TEXT_D)),
                container(
                    column![
                        text("Live Engine State").size(12).color(c(TEXT_M)),
                        text(format!("Tick {}", self.tick_counter)).size(14).color(c(TEXT_H)),
                        text(format!("Runtime {}", self.runtime_profile_label())).size(12).color(c(TEXT_D)),
                    ]
                    .spacing(4)
                )
                .padding(12)
                .style(accent_card_style),
            ]
            .spacing(12)
        )
        .padding(18)
        .style(panel_frame_style)
        .width(Length::FillPortion(3));

        let right = container(
            column![
                text("Sign in").size(24).color(c(TEXT_H)),
                text_input("Username", &self.login_username)
                    .on_input(Message::LoginUsernameChanged)
                    .padding([10, 12])
                    .size(16),
                text_input("Password", &self.login_password)
                    .on_input(Message::LoginPasswordChanged)
                    .secure(true)
                    .padding([10, 12])
                    .size(16),
                row![
                    button(text("Login"))
                        .padding([10, 18])
                        .on_press(Message::LoginPressed)
                        .style(primary_button_style),
                    button(text("Register"))
                        .padding([10, 18])
                        .on_press(Message::RegisterPressed)
                        .style(secondary_button_style),
                ]
                .spacing(10),
                container(text(&self.status_line).size(13).color(c(TEXT_M)))
                    .padding(10)
                    .style(panel_frame_style),
            ]
            .spacing(12)
        )
        .padding(18)
        .style(panel_frame_style)
        .width(Length::FillPortion(2));

        container(
            row![left, right]
                .spacing(12)
                .width(1180)
        )
        .padding(16)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x04, 0x08, 0x14))),
            ..Default::default()
        })
        .into()
    }

    fn view_sidebar(&self) -> Element<'_, Message> {
        let username = self
            .current_username()
            .unwrap_or_else(|| "aether_local".to_owned());
        let trust_ok = self.security_snapshot.trust_state.to_uppercase().contains("HIGH")
            || self.security_snapshot.trust_state.to_uppercase().contains("OK")
            || self.security_snapshot.trust_state.to_uppercase().contains("SECURE");
        let trust_color = if trust_ok {
            Color::from_rgb8(0x4C, 0xD9, 0x6E)
        } else {
            Color::from_rgb8(0xD9, 0xA0, 0x4C)
        };

        // Helper: sidebar section header
        let section_header = |label: &'static str| -> Element<'_, Message> {
            container(
                text(label).size(11).color(Color::from_rgb8(0x7E, 0x76, 0xA8)),
            )
            .padding([6, 10])
            .width(Length::Fill)
            .into()
        };

        // Helper: sidebar nav item
        let nav_item = |icon: &'static str, label: &'static str, tab: Tab| -> Element<'_, Message> {
            let active = self.active_tab == tab;
            let bg = if active {
                Color::from_rgb8(0x20, 0x18, 0x38)
            } else {
                Color::from_rgba8(0, 0, 0, 0.0f32)
            };
            let text_col = if active {
                Color::from_rgb8(0xF0, 0xEE, 0xFF)
            } else {
                Color::from_rgb8(0x9E, 0x96, 0xC0)
            };
            container(
                button(
                    row![
                        text(icon).size(14).color(text_col),
                        text(label).size(13).color(text_col),
                    ]
                    .spacing(8)
                    .align_y(iced::Alignment::Center),
                )
                .padding([7, 12])
                .width(Length::Fill)
                .on_press(Message::TabSelected(tab)),
            )
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(bg)),
                border: Border {
                    color: if active { Color::from_rgb8(0x1E, 0x90, 0xFF) } else { Color::TRANSPARENT },
                    width: if active { 1.0 } else { 0.0 },
                    radius: 6.0.into(),
                },
                ..Default::default()
            })
            .width(Length::Fill)
            .into()
        };

        container(
            column![
                // Logo
                container(
                    column![
                        text("\u{2b21}").size(30).color(Color::from_rgb8(0x1E, 0x90, 0xFF)),
                        text("AETHER").size(16).color(Color::from_rgb8(0xF0, 0xEE, 0xFF)),
                    ]
                    .spacing(2)
                    .align_x(Alignment::Center),
                )
                .padding([14, 10])
                .width(Length::Fill),

                // User status badge
                container(
                    row![
                        canvas::Canvas::new(DotScene { color: trust_color })
                            .width(Length::Fixed(10.0))
                            .height(Length::Fixed(10.0)),
                        text(username.chars().take(16).collect::<String>())
                            .size(12)
                            .color(Color::from_rgb8(0xCC, 0xC6, 0xF4)),
                    ]
                    .spacing(6)
                    .align_y(iced::Alignment::Center),
                )
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
                    border: Border {
                        color: Color::from_rgb8(0x28, 0x26, 0x42),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                })
                .padding([8, 12])
                .width(Length::Fill),

                // AGENTS
                section_header("AGENTS"),
                nav_item("\u{25a3}", "Data Collector", Tab::Data),
                nav_item("\u{25ce}", "Event Monitor", Tab::Logs),
                nav_item("\u{25a4}", "Task Scheduler", Tab::Anchors),

                // CATEGORIES
                section_header("CATEGORIES"),
                nav_item("\u{2295}", "Network", Tab::Browser),
                nav_item("\u{25b6}", "Compute", Tab::YouTube),
                nav_item("\u{25c6}", "Storage", Tab::StructureMap),

                // LOGS
                section_header("LOGS"),
                nav_item("\u{2699}", "System Logs", Tab::Settings),
                nav_item("\u{25d0}", "Alerts", Tab::Logs),

                // Bottom spacer + info
                iced::widget::Space::new(Length::Fill, Length::Fill),
                container(
                    column![
                        text(format!("\u{2699} {}", self.runtime_profile_label())).size(11)
                            .color(Color::from_rgb8(0x62, 0x5E, 0x90)),
                        text(if self.analysis_running { "\u{25b6} ANALYS. AKTIV" } else { "\u{25a0} BEREIT" })
                            .size(11)
                            .color(Color::from_rgb8(0x62, 0x5E, 0x90)),
                    ]
                    .spacing(4),
                )
                .padding([8, 10])
                .width(Length::Fill),

                // Settings + Power icons at bottom
                container(
                    row![
                        button(text("\u{2699}").size(16).color(Color::from_rgb8(0x84, 0x7C, 0xB2)))
                            .padding([6, 10])
                            .on_press(Message::TabSelected(Tab::Settings)),
                        button(text("\u{23fb}").size(16).color(Color::from_rgb8(0x84, 0x7C, 0xB2)))
                            .padding([6, 10])
                            .on_press(Message::TabSelected(Tab::Imprint)),
                    ]
                    .spacing(4),
                )
                .padding([8, 8])
                .width(Length::Fill),
            ]
            .spacing(2)
            .height(Length::Fill),
        )
        .style(|_theme: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x0D, 0x0C, 0x14))),
            border: Border {
                color: Color::from_rgb8(0x24, 0x22, 0x3A),
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .padding([8, 6])
        .width(Length::Fixed(200.0))
        .height(Length::Fill)
        .into()
    }

    fn view_tabs(&self) -> Element<'_, Message> {
        let logo = row![
            canvas::Canvas::new(AetherLogoScene)
                .width(Length::Fixed(32.0))
                .height(Length::Fixed(32.0)),
            text("AETHER")
                .size(14)
                .color(c(ACCENT)),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let tabs = row![
            self.tab_button(Tab::Home,           "\u{25c9}", "Overview"),
            self.tab_button(Tab::Chat,           "\u{25c8}", "Chat"),
            self.tab_button(Tab::Browser,        "\u{2295}", "Browser"),
            self.tab_button(Tab::YouTube,        "\u{25b6}", "YouTube"),
            self.tab_button(Tab::Data,           "\u{25a4}", "Data"),
            self.tab_button(Tab::Settings,       "\u{2699}", "Config"),
            self.tab_button(Tab::Logs,           "\u{25a3}", "Logs"),
            self.tab_button(Tab::Anchors,        "\u{25c6}", "Cluster"),
            self.tab_button(Tab::StructureMap,   "\u{25ce}", "FlowSphere"),
            self.tab_button(Tab::ADE,            "\u{25cd}", "ADE"),
            self.tab_button(Tab::Imprint,        "\u{2139}", "Info"),
            self.tab_button(Tab::Rekonstruktion, "\u{21ba}", "Rekon"),
        ]
        .spacing(0);

        let all_ok = self.security_snapshot.trust_state.to_uppercase().contains("HIGH")
            || self.security_snapshot.trust_state.to_uppercase().contains("OK");

        let status_border = if all_ok {
            c(ACCENT)
        } else {
            c(DANGER)
        };

        let status_content: Element<'_, Message> = row![
            canvas::Canvas::new(DotScene { color: if all_ok {
                c(ACCENT)
            } else {
                c(DANGER)
            }})
            .width(Length::Fixed(8.0)).height(Length::Fixed(8.0)),
            text(if all_ok { "Operational" } else { "Degraded" })
                .size(11).color(c(TEXT_M)),
        ].spacing(6).align_y(Alignment::Center).into();

        let nodes_content: Element<'_, Message> = row![
            text("\u{2b21}").size(11).color(c(ACCENT2)),
            text(format!("{} Nodes", self.anchor_clusters().len()))
                .size(11).color(c(TEXT_M)),
        ].spacing(6).align_y(Alignment::Center).into();

        let time_content: Element<'_, Message> = row![
            text("\u{25d4}").size(11).color(c(TEXT_D)),
            text(format!("{:02}:{:02} Live",
                (self.tick_counter / 60) % 24,
                self.tick_counter % 60))
                .size(11).color(c(TEXT_D)),
        ].spacing(6).align_y(Alignment::Center).into();

        let key_content: Element<'_, Message> = row![
            text("\u{1f511}").size(11).color(c(ACCENT)),
            text(if self.data_key_fingerprint.is_empty() {
                "KEY --".to_owned()
            } else {
                format!("KEY {}", self.data_key_fingerprint)
            })
            .size(11)
            .color(c(TEXT_M)),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .into();

        let badge_style_ok = move |_: &Theme| container::Style {
            background: None,
            border: Border { color: status_border, width: 1.0, radius: 20.0.into() },
            ..Default::default()
        };
        let badge_style_cyan = |_: &Theme| container::Style {
            background: None,
            border: Border { color: c(ACCENT2), width: 1.0, radius: 20.0.into() },
            ..Default::default()
        };
        let badge_style_dim = |_: &Theme| container::Style {
            background: None,
            border: Border { color: c(BORDER), width: 1.0, radius: 20.0.into() },
            ..Default::default()
        };

        container(
            row![
                logo,
                container(iced::widget::Space::new(1.0, 32.0))
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgb8(0x20, 0x1E, 0x30))),
                        ..Default::default()
                    })
                    .width(Length::Fixed(1.0)),
                tabs,
                iced::widget::Space::new(Length::Fill, Length::Shrink),
                row![
                    container(status_content).style(badge_style_ok).padding([4, 14]),
                    container(nodes_content).style(badge_style_cyan).padding([4, 14]),
                    container(time_content).style(badge_style_dim).padding([4, 14]),
                    container(key_content).style(badge_style_dim).padding([4, 14]),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            ]
            .spacing(16)
            .align_y(Alignment::Center),
        )
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(c(BG_BASE))),
            border: Border {
                color: c(BORDER),
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
        let entries = self.entries();
        let total_bytes: u64 = entries.iter().map(|e| e.original_size).sum();
        let cluster_count = self.anchor_clusters().len();

        // --- Simulate live metrics from tick_counter ---
        let t = self.tick_counter as f32;
        let cpu_pct   = (38.0 + 12.0 * (t * 0.11).sin() + 8.0 * (t * 0.23).cos()).clamp(5.0, 95.0);
        let mem_used  = 7.8 + 0.4 * (t * 0.07).sin();
        let net_mbps  = (220.0 + 40.0 * (t * 0.17).sin()).clamp(0.0, 999.0);
        let disk_mbps = (115.0 + 25.0 * (t * 0.13).cos()).clamp(0.0, 999.0);

        let latest_log = self.security_audit_events.first()
            .map(|e| e.summary.clone())
            .unwrap_or_else(|| "Keine Audit-Ereignisse.".to_owned());
        let latest_log2 = self.security_audit_events.get(1)
            .map(|e| e.summary.clone())
            .unwrap_or_else(|| self.analysis_status.clone());
        let latest_log3 = self.security_audit_events.get(2)
            .map(|e| e.summary.clone())
            .unwrap_or_else(|| "Hovered: ".to_owned() + &self.hovered_file_label);

        let analysis_value = if self.analysis_running {
            format!("{:.0}%", self.analysis_progress * 100.0)
        } else if let Some(a) = &self.last_analysis {
            format!("{:.2}% Gain", a.compression_gain_percent)
        } else { "Bereit".to_owned() };

        container(
            scrollable(
                column![
                    // ── Tutorial Banner ───────────────────────────────────────
                    {
                        let tutorial_banner: Element<'_, Message> = if self.show_tutorial {
                            container(
                                row![
                                    canvas::Canvas::new(ShanwayRobotScene { tick: self.tick_counter, size: 48.0 })
                                        .width(Length::Fixed(60.0))
                                        .height(Length::Fixed(70.0)),
                                    column![
                                        text("Willkommen bei Aether").size(16)
                                            .color(Color::from_rgb8(0x9A, 0x67, 0xFF)),
                                        text("Ziehe eine Datei ins Fenster \u{2192} Aether erstellt automatisch eine .aef-Datei mit Strukturanalyse.")
                                            .size(12).color(Color::from_rgb8(0x90, 0x88, 0xBC)),
                                        text("Data-Tab: Ergebnisse | Rekon-Tab: Originaldatei wiederherstellen | Intuitionsblase: Strukturvisualisierung")
                                            .size(11).color(Color::from_rgb8(0x4E, 0x4A, 0x76)),
                                    ]
                                    .spacing(4),
                                    iced::widget::Space::new(Length::Fill, Length::Shrink),
                                    button(text("\u{2715}").size(12).color(Color::from_rgb8(0x4E, 0x4A, 0x76)))
                                        .on_press(Message::TutorialDismissed)
                                        .style(|_: &Theme, _| button::Style {
                                            background: None,
                                            ..Default::default()
                                        })
                                        .padding([4, 8]),
                                ]
                                .spacing(12)
                                .align_y(Alignment::Center),
                            )
                            .style(|_: &Theme| container::Style {
                                background: Some(Background::Color(Color::from_rgba(0.59, 0.34, 0.96, 0.10))),
                                border: Border { color: Color::from_rgb8(0xA0, 0x70, 0xFF), width: 1.0, radius: 10.0.into() },
                                ..Default::default()
                            })
                            .padding([12, 16])
                            .width(Length::Fill)
                            .into()
                        } else {
                            container(iced::widget::Space::new(Length::Shrink, Length::Fixed(0.0)))
                                .into()
                        };
                        tutorial_banner
                    },
                    // ── Row 1: System Metrics (wie im Bild) ──────────────────
                    row![
                        sys_metric_card(
                            "CPU Usage",
                            format!("{:.0}%", cpu_pct),
                            cpu_pct / 100.0,
                            Color::from_rgb8(0x4C, 0xD9, 0x9C),
                        ),
                        sys_metric_card(
                            "Memory",
                            format!("{:.1} GB / 16 GB", mem_used),
                            (mem_used / 16.0) as f32,
                            Color::from_rgb8(0x4C, 0xB4, 0xD9),
                        ),
                        sys_metric_card(
                            "Network Traffic",
                            format!("{:.0} MB/s", net_mbps),
                            (net_mbps / 400.0) as f32,
                            Color::from_rgb8(0x7C, 0x9C, 0xE8),
                        ),
                        sys_metric_card(
                            "Disk I/O",
                            format!("{:.0} MB/s", disk_mbps),
                            (disk_mbps / 250.0) as f32,
                            Color::from_rgb8(0x9C, 0x7C, 0xE8),
                        ),
                    ]
                    .spacing(12),

                    // ── Row 2: Orchestration Map (Canvas) ───────────────────
                    container(
                        column![
                            text("Orchestration Map").size(16)
                                .color(Color::from_rgb8(0xCC, 0xC6, 0xF4)),
                            canvas::Canvas::new(OrchestrationScene {
                                tick: self.tick_counter,
                                cluster_count,
                                analysis_running: self.analysis_running,
                                trust_ok: self.security_snapshot.trust_state
                                    .to_uppercase().contains("OK")
                                    || self.security_snapshot.trust_state
                                    .to_uppercase().contains("HIGH"),
                            })
                            .width(Length::Fill)
                            .height(Length::Fixed(220.0)),
                        ]
                        .spacing(8),
                    )
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
                        border: Border { color: Color::from_rgb8(0x2A, 0x28, 0x44), width: 1.5, radius: 10.0.into() },
                        ..Default::default()
                    })
                    .padding(16)
                    .width(Length::Fill),

                    // ── Row 3: Recent Events + Active Alerts ─────────────────
                    row![
                        // Recent Events
                        container(
                            column![
                                text("Recent Events").size(15)
                                    .color(Color::from_rgb8(0xCC, 0xC6, 0xF4)),
                                event_row("04:21", &(self.tick_counter / 60 % 60).to_string(),
                                    &latest_log,  Color::from_rgb8(0xCC, 0xC6, 0xF4)),
                                event_row("04:18", "New", &latest_log2, Color::from_rgb8(0x4C, 0xD9, 0x9C)),
                                event_row("04:15", "Net", &latest_log3, Color::from_rgb8(0xC0, 0xA0, 0x60)),
                                event_row("04:10", "Bkp", &format!("{} Artefakte lokal", entries.len()),
                                    Color::from_rgb8(0x72, 0x9A, 0xD8)),
                                text(format!("Mode: {} | Analyse: {}",
                                    self.security_snapshot.mode, analysis_value))
                                    .size(11).color(Color::from_rgb8(0x62, 0x5E, 0x90)),
                            ]
                            .spacing(10)
                            .width(Length::Fill),
                        )
                        .style(|_: &Theme| container::Style {
                            background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
                            border: Border { color: Color::from_rgb8(0x2A, 0x28, 0x44), width: 1.5, radius: 10.0.into() },
                            ..Default::default()
                        })
                        .padding(18)
                        .width(Length::FillPortion(3)),

                        // Active Alerts
                        container(
                            column![
                                row![
                                    text("Active Alerts").size(15)
                                        .color(Color::from_rgb8(0xCC, 0xC6, 0xF4)),
                                    iced::widget::Space::new(Length::Fill, Length::Shrink),
                                    text("\u{25b2}").size(12)
                                        .color(Color::from_rgb8(0x62, 0x5E, 0x90)),
                                ]
                                .spacing(8),
                                alert_row(
                                    "\u{25cf}",
                                    c(DANGER),
                                    &format!("Service Timeout: {} nodes", cluster_count.max(1)),
                                    &format!("on {}", self.security_snapshot.mode),
                                ),
                                alert_row(
                                    "\u{26a0}",
                                    c(WARN),
                                    &format!("Disk: {} B lokal", total_bytes),
                                    "Low Space Warning",
                                ),
                                if self.analysis_running {
                                    alert_row(
                                        "\u{25b6}",
                                        Color::from_rgb8(0x4C, 0xD9, 0x9C),
                                        "Analyse läuft",
                                        &self.analysis_status,
                                    )
                                } else {
                                    container(text("")).width(Length::Fill).into()
                                },
                            ]
                            .spacing(10)
                            .width(Length::Fill),
                        )
                        .style(|_: &Theme| container::Style {
                            background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
                            border: Border { color: Color::from_rgb8(0x2A, 0x28, 0x44), width: 1.5, radius: 10.0.into() },
                            ..Default::default()
                        })
                        .padding(18)
                        .width(Length::FillPortion(2)),
                    ]
                    .spacing(12),

                    // ── Row 4: Analysefluss + Drop-Hinweis ──────────────────
                    container(
                        column![
                            row![
                                text("\u{25b6} Analysefluss").size(14)
                                    .color(Color::from_rgb8(0xCC, 0xC6, 0xF4)),
                                iced::widget::Space::new(Length::Fill, Length::Shrink),
                                text(format!("{:.0}%", self.analysis_progress * 100.0)).size(14)
                                    .color(Color::from_rgb8(0x4C, 0xD9, 0x9C)),
                            ]
                            .spacing(8),
                            progress_bar(0.0..=1.0, self.analysis_progress.clamp(0.0, 1.0))
                                .height(6),
                            text(&self.hovered_file_label).size(12)
                                .color(Color::from_rgb8(0x84, 0x7C, 0xB2)),
                        ]
                        .spacing(8)
                        .width(Length::Fill),
                    )
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
                        border: Border { color: Color::from_rgb8(0x70, 0x40, 0xCC), width: 1.5, radius: 10.0.into() },
                        ..Default::default()
                    })
                    .padding(16)
                    .width(Length::Fill),
                ]
                .spacing(14),
            )
            .height(Length::Fill),
        )
        .padding(16)
        .into()
    }

    fn view_home_aether_cyber(&self) -> Element<'_, Message> {
        let t = self.tick_counter as f32;
        let entries = self.entries();
        let risk_base = if self.security_snapshot.trust_state.to_ascii_uppercase().contains("HIGH") {
            0.34
        } else if self.security_snapshot.trust_state.to_ascii_uppercase().contains("OK") {
            0.48
        } else {
            0.71
        };
        let risk_score = ((risk_base + 0.08 * (t * 0.021).sin()).clamp(0.05, 0.98) * 1000.0) as u32;
        let noether_score = (0.62 + 0.25 * (t * 0.017).cos()).clamp(0.0, 1.0);
        let total_threats = (entries.len() as f32 * 1.9 + 14.0 + (t * 0.13).sin().abs() * 22.0) as u32;
        let video_risk = (12.0 + 8.0 * (t * 0.042).sin().abs()) as u32;
        let image_risk = (35.0 + 14.0 * (t * 0.033).sin().abs()) as u32;
        let docs_risk = (6.0 + 5.0 * (t * 0.051).sin().abs()) as u32;
        let folder_risk = (52.0 + 16.0 * (t * 0.024).sin().abs()) as u32;
        let pane_slide = ((self.tick_counter % 8) as f32 / 8.0).clamp(0.0, 1.0); // 120ms @ ~60fps
        let node_pulse = 1.0 + 0.03 * (t * 1.57).sin(); // 40ms pulse
        let data_flash = 0.45 + 0.55 * (t * 5.0).sin().abs(); // pulse intensity for border shimmer
        let graph_reveal = ((self.tick_counter % 6) as f32 / 6.0).clamp(0.0, 1.0); // 90ms reveal
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
        let filtered_threat_rows: Vec<_> = threat_rows
            .into_iter()
            .filter(|(_, device, virus, path, file_type)| {
                q.is_empty()
                    || device.to_ascii_lowercase().contains(&q)
                    || virus.to_ascii_lowercase().contains(&q)
                    || path.to_ascii_lowercase().contains(&q)
                    || file_type.to_ascii_lowercase().contains(&q)
            })
            .collect();
        let filtered_device_rows: Vec<_> = device_rows
            .into_iter()
            .filter(|(device, _)| q.is_empty() || device.to_ascii_lowercase().contains(&q))
            .collect();

        let sidebar = {
            let nav_item = |label: &str, section: &str, active: bool| {
                button(text(label).size(13).color(if active { c(TEXT_H) } else { c(TEXT_M) }))
                    .on_press(Message::DashboardNavSelected(section.to_owned()))
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

            container(
                column![
                    text("AetherGuard").size(24).color(Color::from_rgb8(0xA0, 0x60, 0xFF)),
                    text("General").size(12).color(c(TEXT_D)),
                    nav_item("Overview", "Overview", self.dashboard_nav == "Overview"),
                    nav_item("Issues", "Issues", self.dashboard_nav == "Issues"),
                    nav_item("Files", "Files", self.dashboard_nav == "Files"),
                    text("Reports").size(12).color(c(TEXT_D)),
                    nav_item("Reports", "Reports", self.dashboard_nav == "Reports"),
                    nav_item("Threat Details", "Threat Details", self.dashboard_nav == "Threat Details"),
                    nav_item("Threats", "Threats", self.dashboard_nav == "Threats"),
                    text("Engine").size(12).color(c(TEXT_D)),
                    nav_item("Chat", "Chat", self.dashboard_nav == "Chat"),
                    nav_item("Network", "Network", self.dashboard_nav == "Network"),
                    nav_item("Compute", "Compute", self.dashboard_nav == "Compute"),
                    nav_item("Storage", "Storage", self.dashboard_nav == "Storage"),
                    text("All Modules").size(12).color(c(TEXT_D)),
                    nav_item("Logs", "Logs", self.dashboard_nav == "Logs"),
                    nav_item("Data", "Data", self.dashboard_nav == "Data"),
                    nav_item("Anchors", "Anchors", self.dashboard_nav == "Anchors"),
                    nav_item("FlowSphere", "FlowSphere", self.dashboard_nav == "FlowSphere"),
                    nav_item("ADE", "ADE", self.dashboard_nav == "ADE"),
                    nav_item("Reconstruction", "Reconstruction", self.dashboard_nav == "Reconstruction"),
                    nav_item("Imprint", "Imprint", self.dashboard_nav == "Imprint"),
                    text("Settings").size(12).color(c(TEXT_D)),
                    nav_item("Performance", "Performance", self.dashboard_nav == "Performance"),
                    nav_item("Help & Support", "Help & Support", self.dashboard_nav == "Help & Support"),
                    nav_item("Settings", "Settings", self.dashboard_nav == "Settings"),
                ]
                .spacing(8)
            )
            .padding(14)
            .width(Length::Fixed(210.0))
            .style(|_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
                border: Border { color: Color::from_rgb8(0x30, 0x2E, 0x4E), width: 1.2, radius: 14.0.into() },
                ..Default::default()
            })
        };

        let topbar = row![
            column![
                text("Welcome! Aether Operator").size(24).color(c(TEXT_H)),
                text("Deterministic pane-graph security telemetry").size(13).color(c(TEXT_M)),
            ].spacing(3),
            iced::widget::Space::new(Length::Fill, Length::Shrink),
            container(
                row![
                    text("Search").size(12).color(c(TEXT_D)),
                    text_input("Search Here", &self.dashboard_search)
                        .on_input(Message::DashboardSearchChanged)
                        .padding([8, 12])
                        .size(13)
                        .width(Length::Fixed(340.0)),
                ]
                .spacing(10)
                .align_y(Alignment::Center)
            )
            .padding([4, 8])
            .style(|_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgb8(0x1A, 0x19, 0x28))),
                border: Border { color: Color::from_rgb8(0x3C, 0x38, 0x60), width: 1.1, radius: 24.0.into() },
                ..Default::default()
            }),
            button(text(format!("Performance {}", self.runtime_profile_label())).size(12).color(c(TEXT_H)))
                .on_press(Message::DashboardNavSelected("Performance".to_owned()))
                .padding([8, 12])
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(Color::from_rgba(0.59, 0.34, 0.96, 0.18))),
                    border: Border { color: Color::from_rgb8(0xA0, 0x70, 0xFF), width: 1.1, radius: 10.0.into() },
                    ..Default::default()
                }),
        ]
        .align_y(Alignment::Center)
        .spacing(12);

        let kpis = row![
            cyber_kpi_card("Total Threats", format!("{}%", total_threats), "Aether event stream", Color::from_rgb8(0xFF, 0x4D, 0xA4), "total_threats"),
            cyber_kpi_card("Video File Risk", format!("{}%", video_risk), "Live node binding", Color::from_rgb8(0xA6, 0x4D, 0xFF), "video_risk"),
            cyber_kpi_card("Image File Risk", format!("{}%", image_risk), "Deterministic state", Color::from_rgb8(0xFF, 0x53, 0x96), "image_risk"),
            cyber_kpi_card("Docs File Risk", format!("{}%", docs_risk), "Aether transition", Color::from_rgb8(0x3E, 0x7B, 0xFF), "docs_risk"),
            cyber_kpi_card("Folder File Risk", format!("{}%", folder_risk), "Overlay observer", Color::from_rgb8(0x18, 0x9E, 0xFF), "folder_risk"),
        ]
        .spacing(10);

        let threat_summary_panel = container(
            column![
                row![
                    text("Threat Summary").size(18).color(c(TEXT_H)),
                    info_icon_button("threat_summary"),
                    iced::widget::Space::new(Length::Fill, Length::Shrink),
                    text("Yearly").size(12).color(c(TEXT_M)),
                ].spacing(8).align_y(Alignment::Center),
                canvas::Canvas::new(ThreatTrendScene {
                    tick: self.tick_counter,
                    reveal: graph_reveal,
                })
                .height(Length::Fixed(210.0))
                .width(Length::Fill),
            ]
            .spacing(8)
        )
        .padding(14)
        .width(Length::FillPortion(3))
        .style(accent_card_style);

        let risk_panel = container(
            column![
                row![
                    text("Risk Score").size(18).color(c(TEXT_H)),
                    info_icon_button("risk_score"),
                ].spacing(8).align_y(Alignment::Center),
                canvas::Canvas::new(RiskGaugeScene {
                    score: risk_score,
                    pulse: node_pulse,
                    flash: data_flash,
                })
                .height(Length::Fixed(200.0))
                .width(Length::Fill),
            ]
            .spacing(10)
        )
        .padding(14)
        .width(Length::FillPortion(2))
        .style(accent_card_style);

        let donut_panel = container(
            column![
                row![
                    text("Threats By Virus").size(18).color(c(TEXT_H)),
                    info_icon_button("virus_pie"),
                ].spacing(8).align_y(Alignment::Center),
                canvas::Canvas::new(DonutScene {
                    values: [0.22, 0.18, 0.35, 0.25],
                    colors: [
                        Color::from_rgb8(0xB0, 0x4D, 0xFF),
                        Color::from_rgb8(0xFF, 0x55, 0xA0),
                        Color::from_rgb8(0x3B, 0x8E, 0xFF),
                        Color::from_rgb8(0x17, 0xC2, 0xFF),
                    ],
                    pulse: node_pulse,
                })
                .height(Length::Fixed(180.0))
                .width(Length::Fill),
            ]
            .spacing(8)
        )
        .padding(14)
        .width(Length::FillPortion(2))
        .style(standard_card_style);

        let pane_graph = container(
            column![
                row![
                    text("Aether Pane-Graph").size(16).color(c(TEXT_H)),
                    info_icon_button("pane_graph"),
                    iced::widget::Space::new(Length::Fill, Length::Shrink),
                    text("Background · Mid · Overlay").size(11).color(c(TEXT_D)),
                ].spacing(8).align_y(Alignment::Center),
                canvas::Canvas::new(CyberPaneGraphScene {
                    tick: self.tick_counter,
                    pulse: node_pulse,
                    slide: pane_slide,
                })
                .height(Length::Fixed(130.0))
                .width(Length::Fill),
            ]
            .spacing(8)
        )
        .padding(12)
        .style(standard_card_style);

        let table_panel = {
            let rows: Vec<Element<'_, Message>> = filtered_threat_rows
                .iter()
                .map(|(date, device, virus, path, file_type)| {
                    row![
                        text(date).size(12).color(c(TEXT_M)).width(Length::FillPortion(2)),
                        text(device).size(12).color(c(TEXT_H)).width(Length::FillPortion(3)),
                        text(virus).size(12).color(Color::from_rgb8(0xFF, 0x60, 0xA0)).width(Length::FillPortion(2)),
                        text(path).size(12).color(c(TEXT_D)).width(Length::FillPortion(4)),
                        text(file_type).size(12).color(c(TEXT_M)).width(Length::FillPortion(1)),
                        info_icon_button("threat_details"),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .into()
                })
                .collect();
            container(
                column![
                    row![
                        text("Threat Details").size(18).color(c(TEXT_H)),
                        info_icon_button("threat_details"),
                        iced::widget::Space::new(Length::Fill, Length::Shrink),
                        text("Daily").size(12).color(c(TEXT_M)),
                    ].spacing(8).align_y(Alignment::Center),
                    row![
                        text("Date").size(11).color(c(TEXT_D)).width(Length::FillPortion(2)),
                        text("Device ID").size(11).color(c(TEXT_D)).width(Length::FillPortion(3)),
                        text("Virus name").size(11).color(c(TEXT_D)).width(Length::FillPortion(2)),
                        text("File Path").size(11).color(c(TEXT_D)).width(Length::FillPortion(4)),
                        text("Type").size(11).color(c(TEXT_D)).width(Length::FillPortion(1)),
                        text("Info").size(11).color(c(TEXT_D)),
                    ]
                    .spacing(8),
                    column(rows).spacing(7),
                ]
                .spacing(8)
            )
            .padding(14)
            .width(Length::FillPortion(3))
            .style(standard_card_style)
        };

        let device_panel = {
            let rows: Vec<Element<'_, Message>> = filtered_device_rows
                .iter()
                .map(|(device, level)| {
                    row![
                        text(device).size(12).color(c(TEXT_H)).width(Length::FillPortion(3)),
                        canvas::Canvas::new(DonutScene {
                            values: [*level, 1.0 - *level, 0.0, 0.0],
                            colors: [Color::from_rgb8(0xFF, 0x9A, 0x3D), Color::from_rgb8(0x1C, 0x1B, 0x2A), Color::TRANSPARENT, Color::TRANSPARENT],
                            pulse: 1.0,
                        })
                        .width(Length::Fixed(56.0))
                        .height(Length::Fixed(56.0))
                        .into(),
                        info_icon_button("device_list"),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .into()
                })
                .collect();
            container(
                column![
                    row![
                        text("Threat by device").size(18).color(c(TEXT_H)),
                        info_icon_button("device_list"),
                    ].spacing(8).align_y(Alignment::Center),
                    column(rows).spacing(8),
                ]
                .spacing(8)
            )
            .padding(14)
            .width(Length::FillPortion(2))
            .style(standard_card_style)
        };

        let info_overlay: Element<'_, Message> = if let Some(key) = &self.dashboard_info_key {
            let alpha = (0.20 + 0.80 * info_reveal).clamp(0.0, 1.0);
            container(
                column![
                    row![
                        text(format!("Info: {key}")).size(14).color(c(TEXT_H)),
                        iced::widget::Space::new(Length::Fill, Length::Shrink),
                        button(text("x").size(12)).on_press(Message::DashboardInfoToggle(key.clone())).padding([2, 8]),
                    ].align_y(Alignment::Center),
                    text(dashboard_info_text(key)).size(12).color(c(TEXT_M)),
                ]
                .spacing(8)
            )
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
            column![
                pane_graph,
                kpis,
                row![risk_panel, threat_summary_panel].spacing(10),
                row![table_panel, donut_panel, device_panel].spacing(10),
            ]
            .spacing(10)
            .into()
        } else {
            let embedded: Element<'_, Message> = match self.dashboard_nav.as_str() {
                "Issues" => self.view_logs(),
                "Files" => self.view_data(),
                "Reports" => self.view_anchors(),
                "Threat Details" => self.view_ade(),
                "Threats" => self.view_flow_sphere(),
                "Chat" => self.view_chat(),
                "Network" => self.view_browser(),
                "Compute" => self.view_youtube(),
                "Storage" => self.view_rekonstruktion(),
                "Logs" => self.view_logs(),
                "Data" => self.view_data(),
                "Anchors" => self.view_anchors(),
                "FlowSphere" => self.view_flow_sphere(),
                "ADE" => self.view_ade(),
                "Reconstruction" => self.view_rekonstruktion(),
                "Imprint" => self.view_imprint(),
                "Performance" => self.view_dashboard_performance(),
                "Help & Support" => self.view_imprint(),
                "Settings" => self.view_settings(),
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
            column![
                topbar,
                dashboard_body,
                info_overlay,
            ]
            .spacing(10)
        )
        .style(standard_card_style)
        .padding(10)
        .width(Length::Fill);

        let background_layer = container(iced::widget::Space::new(Length::Fill, Length::Fill))
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgb8(0x0C, 0x0B, 0x12))),
                border: Border {
                    color: Color::from_rgba(0.61, 0.39, 1.0, 0.22 + 0.28 * data_flash),
                    width: 1.0 + 0.8 * node_pulse,
                    radius: 14.0.into(),
                },
                ..Default::default()
            });

        let overlay_layer = container(
            row![
                text(format!("Noether {:.3}", noether_score)).size(11).color(c(TEXT_H)),
                info_icon_button("noether_score"),
                text(format!("Risk {}", risk_score)).size(11).color(Color::from_rgb8(0xFF, 0xC0, 0x66)),
                text(format!("Aether Event Model | Nav: {}", self.dashboard_nav)).size(11).color(c(TEXT_D)),
                text(format!(
                    "Runtime {} | Tick {}ms | Sync {} | Poll {}",
                    self.runtime_profile_label(),
                    self.tick_interval_ms(),
                    self.browser_sync_stride,
                    self.profile_browser_poll_batch()
                ))
                .size(11)
                .color(c(TEXT_M)),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
        )
        .padding([6, 10])
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.03, 0.09, 0.20, 0.65 * pane_slide + 0.25))),
            border: Border { color: Color::from_rgb8(0x9A, 0x67, 0xFF), width: 1.0, radius: 8.0.into() },
            ..Default::default()
        });

        container(
            row![
                sidebar,
                container(
                    column![background_layer, mid_layer, overlay_layer]
                        .spacing(8)
                )
                .width(Length::Fill),
            ]
            .spacing(10)
            .height(Length::Fill)
        )
        .padding(10)
        .height(Length::Fill)
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

        container(
            column![
                row![
                    text("Performance Optimization").size(22).color(c(TEXT_H)),
                    info_icon_button("performance"),
                    iced::widget::Space::new(Length::Fill, Length::Shrink),
                    text(format!("Current: {}", self.runtime_profile_label())).size(12).color(c(TEXT_M)),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
                text("Deterministic runtime profiles for latency, throughput and low-resource stability.")
                    .size(13)
                    .color(c(TEXT_M)),
                row![
                    profile_button("AUTO", RuntimeProfile::Auto, profile == RuntimeProfile::Auto),
                    profile_button("BALANCED", RuntimeProfile::Balanced, profile == RuntimeProfile::Balanced),
                    profile_button("LOW-POWER", RuntimeProfile::LowPower, profile == RuntimeProfile::LowPower),
                    profile_button("LEGACY", RuntimeProfile::Legacy, profile == RuntimeProfile::Legacy),
                ]
                .spacing(10),
                row![
                    info_card("Tick-Intervall", &format!("{} ms", self.tick_interval_ms())),
                    info_card("Browser-Sync", &format!("jede {} Ticks", self.browser_sync_stride)),
                    info_card("Poll-Batch", &format!("{} Events", self.profile_browser_poll_batch())),
                    info_card("Browser-Modus", browser_mode),
                ]
                .spacing(10),
                row![
                    info_card("Analyse-Status", &self.analysis_status),
                ]
                .spacing(10),
                container(
                    text("Hinweis: Diese Profile beeinflussen Scheduler-Takt, Browser-Sync-Frequenz und Lastcharakteristik deterministisch.")
                        .size(12)
                        .color(c(TEXT_D))
                )
                .padding(10)
                .style(standard_card_style),
            ]
            .spacing(12)
        )
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
            ChatContext::Shanway => {
                let avatar = container(
                    canvas::Canvas::new(ShanwayRobotScene {
                        tick: self.tick_counter,
                        size: 80.0,
                    })
                    .width(Length::Fixed(90.0))
                    .height(Length::Fixed(110.0)),
                )
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x15, 0x14, 0x22))),
                    border: Border { color: Color::from_rgb8(0x9A, 0x67, 0xFF), width: 1.1, radius: 10.0.into() },
                    ..Default::default()
                })
                .padding(8);

                row![avatar, self.view_shanway_chat()]
                    .spacing(12)
                    .into()
            }
        };
        container(
            column![
                row![
                    self.context_button(ChatContext::Private, "Privat"),
                    self.context_button(ChatContext::Group, "Gruppen"),
                    self.context_button(ChatContext::Shanway, "Shanway"),
                    tutorial_button,
                ]
                .spacing(10),
                panel,
            ]
            .spacing(16),
        )
        .padding(12)
        .into()
    }

    fn view_browser(&self) -> Element<'_, Message> {
        let url_bar = container(
            row![
                container(
                    text("\u{1f50d}").size(14).color(Color::from_rgb8(0x4E, 0x4A, 0x76))
                ).padding([0, 8]),
                text_input("https://duckduckgo.com", &self.browser_address)
                    .on_input(Message::BrowserAddressChanged)
                    .on_submit(Message::BrowserLoadPressed)
                    .size(13)
                    .padding([8, 12])
                    .width(Length::Fill),
                button(
                    text("\u{2192}").size(14).color(Color::from_rgb8(0xF6, 0xED, 0xFF))
                )
                .padding([8, 14])
                .on_press(Message::BrowserLoadPressed)
                .style(|_: &Theme, _| button::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x96, 0x57, 0xF7))),
                    text_color: Color::from_rgb8(0xF6, 0xED, 0xFF),
                    border: Border { radius: 6.0.into(), ..Default::default() },
                    ..Default::default()
                }),
            ]
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
            row![
                scrollable(
                    column![
                        text("Browser").size(20).color(Color::from_rgb8(0xEE, 0xEA, 0xFF)),
                        url_bar,
                        row![
                            button(text("Seite pruefen").size(13))
                                .padding([8, 14])
                                .on_press(Message::BrowserInspectPressed)
                                .style(secondary_button_style),
                        ]
                        .spacing(10),
                        text_input("Suchbegriff oder Frage", &self.browser_search_query)
                            .on_input(Message::BrowserSearchQueryChanged)
                            .padding(10)
                            .size(14),
                        button(text("DuckDuckGo suchen"))
                            .padding([10, 16])
                            .on_press(Message::BrowserSearchPressed)
                            .style(primary_button_style),
                        info_card("Browser-Status", &self.browser_note),
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
                        },
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
                        },
                    ]
                    .spacing(14)
                )
                .width(Length::Fixed(420.0))
                .style(panel_frame_style)
                .padding(14),
                container(
                    column![
                        text("Eingebettete Browserflaeche").size(18).color(Color::from_rgb8(0xEE, 0xEA, 0xFF)),
                        text("DuckDuckGo und geladene Seiten erscheinen hier direkt im Hauptprogramm.")
                            .size(13).color(Color::from_rgb8(0x90, 0x88, 0xBC)),
                        container(text(" "))
                            .height(Length::Fill)
                            .width(Length::Fill),
                    ]
                    .spacing(10)
                )
                .padding(16)
                .style(panel_frame_style)
                .width(Length::Fill)
                .height(Length::Fill),
            ]
            .spacing(18)
            .height(Length::Fill),
        )
        .padding(12)
        .into()
    }

    fn view_data(&self) -> Element<'_, Message> {
        let mut items = column![
            text("Data").size(24),
            text("Dateien, Analysen, Deltas und Transformationen bleiben intern organisiert.")
                .size(16),
            column![
                row![
                    row![text("Entropie").size(12).color(c(TEXT_M)), info_badge("Entropie beschreibt die Restunsicherheit eines Artefakts.")].spacing(6),
                    row![text("Symmetrie").size(12).color(c(TEXT_M)), info_badge("Symmetrie markiert wiederkehrende Struktur und Invarianz.")].spacing(6),
                    row![text("Drift").size(12).color(c(TEXT_M)), info_badge("Drift misst lokale Byte-Aenderung zwischen benachbarten Bereichen.")].spacing(6),
                ]
                .spacing(12),
                row![
                    row![text("Gain").size(12).color(c(TEXT_M)), info_badge("Gain beschreibt den Kompressionsgewinn gegen das Original.")].spacing(6),
                    row![text("E-Lambda").size(12).color(c(TEXT_M)), info_badge("E-Lambda ist der interne Kohaerenzindikator der AEF-Pipeline.")].spacing(6),
                    row![text("Trust").size(12).color(c(TEXT_M)), info_badge("Trust kombiniert Filter, Kohaerenz und Lossless-Bestaetigung.")].spacing(6),
                ]
                .spacing(12),
            ]
            .spacing(8),
            analysis_card(
                self.analysis_progress,
                &self.analysis_status,
                &self.hovered_file_label,
                &self
                    .last_analysis
                    .as_ref()
                    .map(|analysis| format!(
                        "{}\n{}\n{}",
                        analysis.preview_note, analysis.anchor_summary, analysis.process_summary
                    ))
                    .unwrap_or_else(|| {
                        "Kompressionsgewinn, Delta und Anker erscheinen nach dem ersten Drop."
                            .to_owned()
                    }),
            ),
        ]
        .spacing(14);
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

    fn view_private_chat(&self) -> Element<'_, Message> {
        let selected_partner = self.active_private_partner();
        let mut partners = column![text_input("Nutzer suchen", &self.chat_user_search)
            .on_input(Message::ChatUserSearchChanged)
            .padding(10)
            .size(16)]
        .spacing(10);

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
            let mut content = column![
                text(format!("Privater Kanal | {partner}")).size(20),
                text("Suche nach Nutzernamen oeffnet lokale Threads. Inhalte bleiben im privaten Bereich.")
                    .size(15),
            ]
            .spacing(10);
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

        container(
            row![
                container(scrollable(partners).height(Length::Fill))
                    .padding(16)
                    .style(panel_frame_style)
                    .width(Length::FillPortion(1)),
                container(conversation).style(panel_frame_style).width(Length::FillPortion(2)),
            ]
            .spacing(14),
        )
        .height(Length::Fill)
        .into()
    }

    fn view_group_chat(&self) -> Element<'_, Message> {
        let rooms = self.group_rooms();
        let mut content = column![
            text("Gruppen").size(20),
            text("Gruppen bleiben lokal organisiert. Der Standardraum dient als gemeinsamer lokaler Arbeitskontext.")
                .size(15),
        ]
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

    fn view_shanway_chat(&self) -> Element<'_, Message> {
        let messages = self.shanway_messages();
        let mut content = column![
            text("Shanway").size(24),
            text("Ruhig, klar und professionell.").size(16),
        ]
        .spacing(12);
        let paragraph = if self.show_tutorial {
            "Willkommen. Aether ist ein vollstaendig lokales System fuer Strukturanalyse, sichere Verarbeitung und nachvollziehbare Organisation. DNA-Daten sind lokale Analysepakete: Sie beschreiben Merkmale einer Quelle, nicht deine Rohdaten. Anker sind stabile Strukturpunkte, mit denen Dateien, Prozesse und Artefakte in Cluster eingeordnet werden. Deltas, Restanteile und Zugangsdaten bleiben auf deinem Geraet; es gibt keine zentrale Wiederherstellung. Aether existiert, um Technik und Wissen ohne Cloud-Zwang verstaendlich und praktisch zugaenglich zu machen. Wenn du ein Artefakt in das Fenster ziehst, startet eine isolierte Strukturanalyse ohne Ausfuehrung."
        } else {
            "Ich erklaere den lokalen Zustand verstaendlich und ohne Effekte. Dateien werden isoliert verarbeitet, private Kontexte blockiert und die Analyse endet nach Merkmalsprofil, Anchor-Signalen und Cluster-Zuordnung."
        };
        content = content.push(info_card("Einfuehrung", paragraph));
        if messages.is_empty() {
            content = content.push(info_card(
                "Dialogstart",
                "Du kannst Shanway direkt fragen, wie Aether arbeitet, was DNA-Daten sind, wie Anker verwendet werden oder wie deine Daten lokal geschuetzt bleiben.",
            ));
        } else {
            for message in messages.iter().take(40) {
                content = content.push(info_card(&message.author, &message.body));
            }
        }
        content = content.push(
            text_input("Frage an Shanway", &self.shanway_message_draft)
                .on_input(Message::ShanwayMessageChanged)
                .padding(10)
                .size(16),
        );
        content = content.push(
            button(text("An Shanway senden"))
                .padding([10, 16])
                .on_press(Message::ShanwayMessageSend)
                .style(primary_button_style),
        );
        container(scrollable(content).height(Length::Fill))
            .padding(12)
            .style(panel_frame_style)
            .into()
    }

    fn view_settings(&self) -> Element<'_, Message> {
        let mode = self.security_mode();
        let profile = self.runtime_profile;
        container(
            scrollable(
                column![
                    text("Einstellungen").size(24),
                    row![
                        info_card("OS-Layer", "Sandbox: strikt\nPrivacy-Boundary: hard block\nIntegrationsgrad: lokal"),
                        info_card("Telemetrie", "Standard: nur lokal\nOptionen: aus, gedrosselt, sicherheitsrelevant"),
                        info_card("Agenten", "Lokale Agenten koennen aktiviert, begrenzt und mit Sicherheitsprofilen versehen werden."),
                    ]
                    .spacing(14),
                    text("Security-Modus").size(20),
                    row![
                        button(text(if mode == "local" { "LOCAL [aktiv]" } else { "LOCAL" }))
                            .padding([10, 18])
                            .on_press(Message::SecurityModeSelected("local".to_owned()))
                            .style(if mode == "local" { primary_button_style } else { secondary_button_style }),
                        button(text(if mode == "dev" { "DEV [aktiv]" } else { "DEV" }))
                            .padding([10, 18])
                            .on_press(Message::SecurityModeSelected("dev".to_owned()))
                            .style(if mode == "dev" { primary_button_style } else { secondary_button_style }),
                        button(text("Recheck"))
                            .padding([10, 18])
                            .on_press(Message::SecurityRecheck)
                            .style(secondary_button_style),
                    ]
                    .spacing(10),
                    text("Runtime-Profil (Hardware-Inklusion)").size(20),
                    text("AUTO passt dynamisch an. LEGACY priorisiert niedrige Dauerlast fuer aeltere Systeme.")
                        .size(14),
                    row![
                        button(text(if profile == RuntimeProfile::Auto {
                            "AUTO [aktiv]"
                        } else {
                            "AUTO"
                        }))
                        .padding([10, 16])
                        .on_press(Message::RuntimeProfileSelected(RuntimeProfile::Auto))
                        .style(if profile == RuntimeProfile::Auto { primary_button_style } else { secondary_button_style }),
                        button(text(if profile == RuntimeProfile::Balanced {
                            "BALANCED [aktiv]"
                        } else {
                            "BALANCED"
                        }))
                        .padding([10, 16])
                        .on_press(Message::RuntimeProfileSelected(RuntimeProfile::Balanced))
                        .style(if profile == RuntimeProfile::Balanced { primary_button_style } else { secondary_button_style }),
                        button(text(if profile == RuntimeProfile::LowPower {
                            "LOW-POWER [aktiv]"
                        } else {
                            "LOW-POWER"
                        }))
                        .padding([10, 16])
                        .on_press(Message::RuntimeProfileSelected(RuntimeProfile::LowPower))
                        .style(if profile == RuntimeProfile::LowPower { primary_button_style } else { secondary_button_style }),
                        button(text(if profile == RuntimeProfile::Legacy {
                            "LEGACY [aktiv]"
                        } else {
                            "LEGACY"
                        }))
                        .padding([10, 16])
                        .on_press(Message::RuntimeProfileSelected(RuntimeProfile::Legacy))
                        .style(if profile == RuntimeProfile::Legacy { primary_button_style } else { secondary_button_style }),
                    ]
                    .spacing(8),
                    info_card(
                        "Aktive Runtime-Parameter",
                        &format!(
                            "Profil: {}\nTick-Intervall: {} ms\nBrowser-Sync: alle {} Ticks\nBrowser-Event-Batch: {}",
                            self.runtime_profile_label(),
                            self.tick_interval_ms(),
                            self.browser_sync_stride,
                            self.profile_browser_poll_batch()
                        ),
                    ),
                ]
                .spacing(16),
            )
            .height(Length::Fill),
        )
        .padding(12)
        .style(panel_frame_style)
        .into()
    }

    fn view_logs(&self) -> Element<'_, Message> {
        let mut items = column![
            text("\u{25a3} LOGS \u{2014} Audit & Security").size(22),
            text("Lokale technische Meldungen fuer Audit und Security.").size(13),
        ]
        .spacing(12);
        if self.security_audit_events.is_empty() {
            items = items.push(
                container(
                    column![
                        text("\u{25cb} Noch keine Logs").size(16),
                        text("Nach Anmeldung oder Security-Recheck erscheinen hier Ereignisse.").size(14),
                    ]
                    .spacing(6),
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
                .width(Length::Fill),
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
                        column![
                            row![
                                text(badge).size(13),
                                text(format!("  {} | {}", reason, trust_state)).size(14),
                            ]
                            .spacing(6),
                            text(summary).size(13),
                            text(format!("Mode: {} | Maze: {}", mode, maze)).size(12),
                        ]
                        .spacing(4)
                        .width(Length::Fill),
                    )
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
                    .width(Length::Fill),
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
        let selected = clusters
            .get(self.selected_anchor_group)
            .cloned()
            .or_else(|| clusters.first().cloned())
            .unwrap();
        let mut list = column![
            text("\u{25c6} CLUSTER \u{2014} Anchor-Gruppen").size(22),
            text("Kategorien entstehen datengetrieben aus Strukturmerkmalen.").size(13),
        ]
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
                        column![
                            text(format!("\u{25c6} {}", title)).size(15),
                            text(descriptor).size(12),
                            text(format!("{} [{}]", bar, item_count)).size(12),
                        ]
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
            row![
                container(scrollable(list).height(Length::Fill))
                    .padding(12)
                    .style(panel_frame_style)
                    .width(Length::FillPortion(1)),
                container(
                    column![
                        text(format!("\u{25c6} {}", selected.title)).size(22),
                        text(selected.descriptor.clone()).size(15),
                        text(format!("Artefakte: {}", selected.item_count)).size(14),
                        progress_bar(0.0..=1.0, detail_fill),
                        text(make_sparkline(detail_fill)).size(13),
                        text(format!("Groesse: {} B", selected.total_bytes)).size(14),
                        text(selected.sample_note.clone()).size(13),
                        button(text("Download anfragen")).padding([10, 18]).style(secondary_button_style),
                    ]
                    .spacing(10),
                )
                .style(accent_card_style)
                .padding(22)
                .width(Length::FillPortion(2)),
            ]
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
                column![
                    text("Impressum").size(24),
                    info_card(
                        "Status",
                        "Kurz: Die Logik ist schon richtig gebaut. Die volle selbstverstaerkende Skalierung ist vorbereitet, aber noch nicht komplett end-to-end operationalisiert.",
                    ),
                    info_card("Symbionten", &format!("Aktuell registrierte Symbionten: {symbiont_count}")),
                    info_card("Zweck", "Aether macht lokale Analyse, Technik und Wissen ohne Cloud-Zwang verstaendlich und nutzbar."),
                    info_card("Datenschutz", "Account, Deltas und Restanteile bleiben auf dem Geraet. Keine zentrale Wiederherstellung."),
                    info_card("Formeln", "P(n) = base + (1-base) * ln(1+n) / ln(1+Nmax)\nC(t) = vault_hits / total_chunks"),
                    info_card("Systembild", "Aether arbeitet eher wie eine Leitstelle als wie ein Agent: lokale Signale werden geordnet, priorisiert und in stabile Entscheidungen ueberfuehrt."),
                ]
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

        let header = row![
            text("Rekonstruktion").size(22).color(Color::from_rgb8(0xD0, 0xE8, 0xF8)),
            text(" \u{2014} lokale AEF-Artefakte wiederherstellen").size(14)
                .color(Color::from_rgb8(0x60, 0x88, 0xA8)),
        ]
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
                            row![
                                text("\u{25a4}").size(14).color(Color::from_rgb8(0x80, 0xBC, 0xE8)),
                                column![
                                    text(entry.file_name).size(14).color(Color::from_rgb8(0xD0, 0xE8, 0xF8)),
                                    text(format!(
                                        "{} KB  \u{2192}  {:.1}% Gewinn",
                                        size_kb,
                                        gain
                                    ))
                                    .size(12)
                                    .color(gain_color),
                                ]
                                .spacing(2),
                            ]
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
            scrollable(column(rows).spacing(4))
                .height(Length::Fixed(320.0))
                .into()
        };

        // Status / result panel
        let status_panel: Element<'_, Message> = if self.rekonstruktion_running {
            container(
                row![
                    text("\u{21ba}").size(18).color(Color::from_rgb8(0x80, 0xBC, 0xE8)),
                    text("Rekonstruktion laeuft …").size(14)
                        .color(Color::from_rgb8(0x80, 0xBC, 0xE8)),
                ]
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
                        column![
                            text(format!("Datei: {file_name}")).size(14).color(Color::from_rgb8(0xD0, 0xE8, 0xF8)),
                            row![
                                text(hash_icon).size(14).color(hash_color),
                                text("Hash verifiziert").size(13).color(Color::from_rgb8(0x90, 0xB8, 0xD8)),
                            ].spacing(6),
                            row![
                                text(complete_icon).size(14).color(complete_color),
                                text("Rekonstruktion vollstaendig").size(13).color(Color::from_rgb8(0x90, 0xB8, 0xD8)),
                            ].spacing(6),
                            text(format!("Kohaerenz: {:.3}", aef_result.coherence_index)).size(13)
                                .color(Color::from_rgb8(0x80, 0xA8, 0xC8)),
                            text(format!("Fehlende Vault-Refs: {}", aef_result.missing_vault_refs.len())).size(13)
                                .color(Color::from_rgb8(0x80, 0xA8, 0xC8)),
                            export_btn,
                        ]
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
        let surf_bg    = Color::from_rgb8(0x03, 0x09, 0x12);
        let panel_bg   = Color::from_rgb8(0x05, 0x0F, 0x1C);

        // Derived metrics from live data
        let entropy = (self.structure_map_compression / 100.0).clamp(0.0, 1.0);
        let stability = if self.structure_map_locked { 1.0f32 } else { entropy * 0.82 };
        let anchor_count = self.structure_map_nodes.last().map_or(4, |v| v.len());
        let info_growth = entropy;

        let attractor_lons = [0.0f32, TAU / 6.0, TAU / 3.0, TAU / 2.0, 2.0 * TAU / 3.0, 5.0 * TAU / 6.0];

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
                        text("h\u{209c} INSPECTOR").size(11).color(cyan),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("ENTROPIE").size(10).color(dim),
                        text(format!("{:.4} bit", entropy * 7.83)).size(16).color(Color::from_rgb8(0xAF, 0x86, 0xFF)),
                        progress_bar(0.0..=1.0, entropy).height(5),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("ATTRAKTOR-PARAM").size(10).color(dim),
                        text(format!("{} stabile Knoten", anchor_count)).size(14).color(Color::WHITE),
                        text(format!("\u{03c4}/4  \u{00d7}  {}", anchor_count)).size(11).color(dim),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("DELTA-STATISTIK").size(10).color(dim),
                        text(format!("\u{0394} {:.3}", delta_phases[0].sin().abs())).size(14).color(Color::from_rgb8(0xFF, 0xD7, 0x00)),
                        text(format!("\u{03c3} {:.3}", delta_phases[1].sin().abs())).size(12).color(Color::from_rgb8(0xFF, 0xA5, 0x00)),
                        text(anchor_spark).size(10).color(Color::from_rgb8(0x9B, 0xD4, 0xFF)),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("I(h\u{209c})").size(10).color(dim),
                        text(format!("{:.4}", i_ht)).size(18).color(Color::from_rgb8(0xC0, 0xF0, 0xFF)),
                        text(make_sparkline(i_ht)).size(9).color(Color::from_rgb8(0x7B, 0x8F, 0xB3)),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("STABILIT\u{c4}T").size(10).color(dim),
                        text(format!("{:.1}%", stability * 100.0)).size(16).color(
                            if stability > 0.8 { Color::from_rgb8(0x4C, 0xD9, 0x6E) }
                            else if stability > 0.5 { Color::from_rgb8(0xFF, 0xD7, 0x00) }
                            else { Color::from_rgb8(0xD9, 0x50, 0x50) }
                        ),
                        progress_bar(0.0..=1.0, stability).height(5),
                        text(if self.structure_map_locked { "\u{25cf} KONVERGIERT" } else { "\u{25cc} Laufend..." })
                            .size(10)
                            .color(if self.structure_map_locked { Color::from_rgb8(0x4C, 0xD9, 0x6E) } else { dim }),
                        text("\u{2500}".repeat(22)).size(8).color(dim),
                        text("MUTATIONS-HIST").size(10).color(dim),
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
            column![
                text("TEMPORAL LAYER  \u{2500}  Session-Verlauf").size(10).color(dim),
                row(timeline).spacing(2),
            ]
            .spacing(4)
            .padding([6, 10]),
        )
        .width(Length::Fill)
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x03, 0x07, 0x0F))),
            border: Border { color: Color::from_rgb8(0x0A, 0x20, 0x30), width: 1.0, radius: 0.0.into() },
            ..Default::default()
        });

        // Flow Sphere Canvas
        let sphere_scene = FlowSphereScene {
            tick: self.tick_counter,
            entropy,
            stability,
            delta_phases,
            attractor_lons,
            info_growth,
        };

        let sphere_canvas = canvas::Canvas::new(sphere_scene)
            .width(Length::Fill)
            .height(Length::Fill);

        // Main layout
        let header = row![
            text("\u{25ce} AETHER FLOW SPHERE").size(13).color(cyan),
            text("  \u{00b7}  Strukturraum \u{1d4ae}  \u{00b7}  Attraktor-Dynamik  \u{00b7}  Delta-Konvergenz  \u{00b7}  h\u{209c} Observer").size(10).color(dim),
        ].spacing(0);

        container(
            column![
                header,
                row![
                    sphere_canvas,
                    ht_panel,
                ]
                .spacing(0)
                .height(Length::Fill),
                timeline_row,
            ]
            .spacing(8)
            .height(Length::Fill),
        )
        .padding(10)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(surf_bg)),
            ..Default::default()
        })
        .into()
    }

    fn view_ade(&self) -> Element<'_, Message> {
        let cyan    = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let yellow  = Color::from_rgb8(0xFF, 0xD7, 0x00);
        let red     = Color::from_rgb8(0xD9, 0x50, 0x50);
        let green   = Color::from_rgb8(0x4C, 0xD9, 0x6E);
        let dim     = Color::from_rgb8(0x50, 0x6A, 0x7A);
        let panel_s = Color::from_rgb8(0x05, 0x10, 0x1C);

        let entropy = (self.structure_map_compression / 100.0).clamp(0.0, 1.0);
        let lossless_ok = self.structure_map_locked;

        // Residuum viewer — sparkline from anchor history
        let residuum_spark: String = {
            let h = &self.structure_map_anchor_hist;
            let max = h.iter().cloned().fold(0.1f32, f32::max);
            h.iter().map(|&v| {
                let p = 1.0 - (v / max).clamp(0.0, 1.0); // residuum = inverse of anchoring
                if p > 0.75 { '\u{2588}' } else if p > 0.50 { '\u{2593}' }
                else if p > 0.25 { '\u{2592}' } else { '\u{2591}' }
            }).collect()
        };

        // Delta convergence series
        let conv_vals: Vec<f32> = self.structure_map_anchor_hist.iter()
            .scan(0.5f32, |acc, &v| {
                *acc = (*acc * 0.85 + v * 0.015).clamp(0.0, 1.0);
                Some(*acc)
            })
            .collect();
        let conv_spark: String = conv_vals.iter().map(|&v| {
            if v > 0.75 { '\u{2588}' } else if v > 0.50 { '\u{2593}' }
            else if v > 0.25 { '\u{2592}' } else { '\u{2591}' }
        }).collect();
        let final_conv = conv_vals.last().copied().unwrap_or(0.0);

        // Mutation histogram
        let mut_spark: String = self.structure_map_mutation_hist.iter().map(|&v| {
            if v >= 12 { '\u{2588}' } else if v >= 8 { '\u{2593}' }
            else if v >= 4 { '\u{2592}' } else { '\u{2591}' }
        }).collect();
        let seed_val = self.tick_counter.wrapping_mul(7919).wrapping_add(3);
        let seed_stability = 1.0 - (self.structure_map_mutation_hist.iter()
            .map(|&v| v as f32)
            .sum::<f32>()
            / (self.structure_map_mutation_hist.len().max(1) as f32 * 12.0)).clamp(0.0, 1.0);

        let panel_s_clone = panel_s;
        let _ = panel_s_clone; // used via move in subpanels below

        // Reconstruction preview: show last AEF file if available
        let recon_hint = self.structure_map_nodes.last()
            .map(|v| format!("Anker: {}  |  Tick: {}", v.len(), self.tick_counter))
            .unwrap_or_else(|| "Keine Daten – FlowSphere starten.".to_owned());

        let residuum_body = column![
            text("RESIDUUM-VIEWER").size(10).color(dim),
            text(residuum_spark.clone()).size(12).color(Color::from_rgb8(0xFF, 0xA5, 0x00)),
            text(format!("Residuum: {:.3}", 1.0 - entropy)).size(14).color(yellow),
            progress_bar(0.0..=1.0, 1.0 - entropy).height(6),
        ].spacing(6).into();

        let conv_body = column![
            text("DELTA-KONVERGENZ-GRAPH").size(10).color(dim),
            text(conv_spark.clone()).size(12).color(Color::from_rgb8(0x9B, 0xD4, 0xFF)),
            text(format!("\u{0394} \u{2192} {:.4}", final_conv)).size(14).color(cyan),
            progress_bar(0.0..=1.0, final_conv).height(6),
            text(format!("Reduktion: {:.1}%", (1.0 - final_conv).clamp(0.0, 1.0) * 100.0))
                .size(12).color(dim),
        ].spacing(6).into();

        let seed_body = column![
            text("SEED-STABILIT\u{c4}T").size(10).color(dim),
            text(format!("Seed: {:016X}", seed_val)).size(11).color(dim),
            text(format!("{:.2}%", seed_stability * 100.0)).size(18)
                .color(if seed_stability > 0.7 { green } else { yellow }),
            text(mut_spark.clone()).size(11).color(Color::from_rgb8(0xFF, 0xA5, 0x00)),
        ].spacing(6).into();

        let recon_body = column![
            text("RECONSTRUCTION-PREVIEW").size(10).color(dim),
            text(recon_hint).size(12).color(Color::from_rgb8(0xC0, 0xE0, 0xFF)),
            text(format!("Entropie: {:.4} bit", entropy * 7.83)).size(12).color(dim),
            text(format!("Kompression: {:.1}%", self.structure_map_compression))
                .size(14).color(Color::from_rgb8(0xE0, 0xF7, 0xFF)),
        ].spacing(6).into();

        let lossless_color = if lossless_ok { green } else { dim };
        let lossless_body: Element<'_, Message> = column![
            row![
                canvas::Canvas::new(DotScene { color: if lossless_ok { green } else { red } })
                    .width(Length::Fixed(14.0))
                    .height(Length::Fixed(14.0)),
                text(if lossless_ok { "LOSSLESS \u{2714} BEST\u{c4}TIGT" } else { "LOSSLESS \u{2715} NOCH NICHT KONVERGIERT" })
                    .size(13).color(lossless_color),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            progress_bar(0.0..=100.0, self.structure_map_compression).height(8),
            text(format!("{:.1}% Delta-Auflösung", self.structure_map_compression))
                .size(11).color(dim),
        ].spacing(8).into();

        let right_panel = container(
            scrollable(
                column![
                    text("ADE \u{00b7} ENGINE-STATUS").size(11).color(cyan),
                    text("\u{2500}".repeat(20)).size(8).color(dim),
                    text(format!("Tick:  {}", self.tick_counter)).size(11).color(dim),
                    text(format!("Layer: {}", self.structure_map_nodes.len())).size(11).color(dim),
                    text(format!("Nodes: {}", self.structure_map_nodes.iter().map(|v| v.len()).sum::<usize>())).size(11).color(dim),
                    text("\u{2500}".repeat(20)).size(8).color(dim),
                    text("ATTRAKTOR-PHASEN").size(10).color(dim),
                    text(format!("\u{03c6}\u{2080}: {:.3}", 0.0f32)).size(11).color(Color::from_rgb8(0x9B, 0xD4, 0xFF)),
                    text(format!("\u{03c6}\u{2081}: {:.3}", std::f32::consts::FRAC_PI_2)).size(11).color(Color::from_rgb8(0x9B, 0xD4, 0xFF)),
                    text(format!("\u{03c6}\u{2082}: {:.3}", std::f32::consts::PI)).size(11).color(Color::from_rgb8(0x9B, 0xD4, 0xFF)),
                    text(format!("\u{03c6}\u{2083}: {:.3}", std::f32::consts::PI * 1.5)).size(11).color(Color::from_rgb8(0x9B, 0xD4, 0xFF)),
                    text("\u{2500}".repeat(20)).size(8).color(dim),
                    text("OCKHAM-RATIO").size(10).color(dim),
                    text(format!("{:.3}", 0.35 + 0.18 * (self.tick_counter as f32 * 0.42).sin()))
                        .size(16).color(yellow),
                ]
                .spacing(5)
                .padding(10),
            )
            .height(Length::Fill),
        )
        .width(Length::Fixed(200.0))
        .height(Length::Fill)
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(panel_s)),
            border: Border { color: Color::from_rgb8(0x0A, 0x28, 0x38), width: 1.0, radius: 0.0.into() },
            ..Default::default()
        });

        let main_content = scrollable(
            column![
                ade_subpanel("RESIDUUM-VIEWER", residuum_body, panel_s),
                ade_subpanel("\u{0394} DELTA-KONVERGENZ", conv_body, panel_s),
                ade_subpanel("SEED-STABILIT\u{c4}T", seed_body, panel_s),
                ade_subpanel("RECONSTRUCTION-PREVIEW", recon_body, panel_s),
                ade_subpanel("LOSSLESS-CHECK", lossless_body, panel_s),
            ]
            .spacing(12)
            .padding([0.0f32, 8.0]),
        );

        container(
            column![
                row![
                    text("ADE \u{00b7} AETHER DELTA ENGINE").size(13).color(cyan),
                    text("  \u{00b7}  Residuum  \u{00b7}  Konvergenz  \u{00b7}  Seed  \u{00b7}  Lossless-Check").size(10).color(dim),
                ].spacing(0),
                row![
                    main_content,
                    right_panel,
                ]
                .spacing(8)
                .height(Length::Fill),
            ]
            .spacing(8)
            .height(Length::Fill),
        )
        .padding(10)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x02, 0x06, 0x10))),
            ..Default::default()
        })
        .into()
    }

    fn view_shell(&self) -> Element<'_, Message> {
        if self.active_tab == Tab::Home {
            return self.view_home();
        }

        let main = match self.active_tab {
            Tab::Home => self.view_home(),
            Tab::Chat => self.view_chat(),
            Tab::Browser => self.view_browser(),
            Tab::YouTube => self.view_youtube(),
            Tab::Data => self.view_data(),
            Tab::Settings => self.view_settings(),
            Tab::Logs => self.view_logs(),
            Tab::Anchors => self.view_anchors(),
            Tab::StructureMap => self.view_flow_sphere(),
            Tab::ADE => self.view_ade(),
            Tab::Imprint => self.view_imprint(),
            Tab::Rekonstruktion => self.view_rekonstruktion(),
        };

        let nav_item = |label: &str, tab: Tab, active_tab: Tab| {
            let active = tab == active_tab;
            button(text(label).size(13).color(if active { c(TEXT_H) } else { c(TEXT_M) }))
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

        let shell_sidebar = container(
            column![
                text("Aether").size(24).color(Color::from_rgb8(0xA0, 0x6A, 0xFF)),
                text("Core").size(12).color(c(TEXT_D)),
                nav_item("Overview", Tab::Home, self.active_tab),
                nav_item("Chat", Tab::Chat, self.active_tab),
                nav_item("Network", Tab::Browser, self.active_tab),
                nav_item("Compute", Tab::YouTube, self.active_tab),
                nav_item("Files", Tab::Data, self.active_tab),
                text("Analysis").size(12).color(c(TEXT_D)),
                nav_item("Threats", Tab::StructureMap, self.active_tab),
                nav_item("Threat Details", Tab::ADE, self.active_tab),
                nav_item("Reports", Tab::Anchors, self.active_tab),
                nav_item("Logs", Tab::Logs, self.active_tab),
                text("System").size(12).color(c(TEXT_D)),
                nav_item("Settings", Tab::Settings, self.active_tab),
                nav_item("Info", Tab::Imprint, self.active_tab),
                nav_item("Reconstruction", Tab::Rekonstruktion, self.active_tab),
            ]
            .spacing(8)
        )
        .padding(14)
        .width(Length::Fixed(220.0))
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x10, 0x10, 0x1A))),
            border: Border { color: Color::from_rgb8(0x30, 0x2E, 0x50), width: 1.2, radius: 12.0.into() },
            ..Default::default()
        });

        let shell_header = container(
            row![
                column![
                    text(match self.active_tab {
                        Tab::Home => "Overview",
                        Tab::Chat => "Chat",
                        Tab::Browser => "Network",
                        Tab::YouTube => "Compute",
                        Tab::Data => "Files",
                        Tab::Settings => "Settings",
                        Tab::Logs => "Logs",
                        Tab::Anchors => "Reports",
                        Tab::StructureMap => "Threats",
                        Tab::ADE => "Threat Details",
                        Tab::Imprint => "Info",
                        Tab::Rekonstruktion => "Reconstruction",
                    }).size(24).color(c(TEXT_H)),
                    text(&self.status_line).size(12).color(c(TEXT_M)),
                ]
                .spacing(3),
                iced::widget::Space::new(Length::Fill, Length::Shrink),
                button(text(format!("Performance {}", self.runtime_profile_label())).size(12).color(c(TEXT_H)))
                    .on_press(Message::TabSelected(Tab::Settings))
                    .padding([8, 12])
                    .style(|_: &Theme, _| button::Style {
                        background: Some(Background::Color(Color::from_rgba(0.59, 0.34, 0.96, 0.18))),
                        border: Border { color: Color::from_rgb8(0xA0, 0x70, 0xFF), width: 1.1, radius: 10.0.into() },
                        ..Default::default()
                    }),
            ]
            .align_y(Alignment::Center)
            .spacing(12)
        )
        .padding([10, 14])
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x13, 0x1F, 0x39))),
            border: Border { color: Color::from_rgb8(0x3C, 0x38, 0x60), width: 1.1, radius: 12.0.into() },
            ..Default::default()
        });

        container(
            row![
                shell_sidebar,
                column![
                    shell_header,
                    container(main)
                        .padding(6)
                        .style(standard_card_style)
                        .width(Length::Fill)
                        .height(Length::Fill),
                ]
                .spacing(10)
                .width(Length::Fill),
            ]
            .spacing(10),
        )
        .padding(10)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x04, 0x08, 0x14))),
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

    fn send_shanway_message(&mut self) {
        let Some(username) = self.current_username() else {
            self.status_line = "Shanway erfordert eine Anmeldung.".to_owned();
            return;
        };
        let prompt = self.shanway_message_draft.trim().to_owned();
        if prompt.is_empty() {
            self.status_line = "Bitte zuerst eine Frage eingeben.".to_owned();
            return;
        }
        let reply = render_shanway_reply(self.current_shanway_input().as_ref(), &prompt);
        if let Err(err) = self
            .state_store
            .add_private_message(&username, "Shanway", &username, &prompt)
        {
            self.status_line = err;
            return;
        }
        if let Err(err) = self
            .state_store
            .add_private_message(&username, "Shanway", "Shanway", &reply)
        {
            self.status_line = err;
            return;
        }
        self.shanway_message_draft.clear();
        self.status_line = "Shanway hat lokal geantwortet.".to_owned();
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

    fn browser_surface_mode(&self) -> Option<Tab> {
        match self.active_tab {
            Tab::Browser => Some(Tab::Browser),
            Tab::YouTube => Some(Tab::YouTube),
            Tab::Home => match self.dashboard_nav.as_str() {
                "Network" => Some(Tab::Browser),
                "Compute" => Some(Tab::YouTube),
                _ => None,
            },
            _ => None,
        }
    }

    fn profile_tick_interval_ms(&self) -> u64 {
        let browser_like = self.browser_surface_mode().is_some();
        match self.runtime_profile {
            RuntimeProfile::Auto => {
                if browser_like {
                    220
                } else if self.analysis_running {
                    320
                } else {
                    900
                }
            }
            RuntimeProfile::Balanced => {
                if browser_like {
                    260
                } else {
                    650
                }
            }
            RuntimeProfile::LowPower => {
                if browser_like {
                    420
                } else {
                    1150
                }
            }
            RuntimeProfile::Legacy => {
                if browser_like {
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
                        self.chat_context = ChatContext::Shanway;
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
                            self.chat_context = ChatContext::Shanway;
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
            Message::DashboardSearchChanged(value) => self.dashboard_search = value,
            Message::DashboardNavSelected(value) => {
                self.dashboard_nav = value;
                self.dashboard_info_key = None;
                self.dashboard_info_open_tick = self.tick_counter;
                if self.active_tab == Tab::Home {
                    if self.dashboard_nav == "Network" {
                        self.browser_address = "https://duckduckgo.com/".to_owned();
                        match self.browser_embed.navigate(&self.browser_address) {
                            Ok(()) => {
                                self.sync_browser_embed();
                                self.browser_note = "DuckDuckGo wurde im Dashboard geladen.".to_owned();
                                self.status_line = self.browser_note.clone();
                            }
                            Err(err) => {
                                self.browser_note =
                                    format!("DuckDuckGo konnte im Dashboard nicht geladen werden: {err}");
                                self.status_line = self.browser_note.clone();
                            }
                        }
                    } else if self.dashboard_nav == "Compute" {
                        self.youtube_address = "https://www.youtube.com/".to_owned();
                        let url = self.youtube_address.clone();
                        match self.browser_embed.navigate(&url) {
                            Ok(()) => {
                                self.sync_browser_embed();
                                self.browser_note = "YouTube wurde im Dashboard geladen.".to_owned();
                                self.status_line = self.browser_note.clone();
                            }
                            Err(err) => {
                                self.browser_note =
                                    format!("YouTube konnte im Dashboard nicht geladen werden: {err}");
                                self.status_line = self.browser_note.clone();
                            }
                        }
                    } else {
                        self.browser_embed.hide();
                    }
                }
            }
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
            Message::ShanwayMessageChanged(value) => self.shanway_message_draft = value,
            Message::ShanwayMessageSend => self.send_shanway_message(),
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
                        self.browser_note =
                            format!("Video konnte nicht geladen werden: {err}");
                        self.status_line = self.browser_note.clone();
                    }
                }
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
            Message::FileDropped(path) => {
                let Some(username) = self.current_username() else {
                    self.status_line =
                        "Bitte zuerst lokal anmelden, bevor du Artefakte analysierst.".to_owned();
                    return Task::none();
                };
                self.analysis_running = true;
                self.analysis_progress = 0.18;
                self.analysis_status = format!(
                    "Artefakt erkannt. Strukturanalyse gestartet: {}",
                    path.display()
                );
                self.hovered_file_label = format!("Drop uebernommen: {}", path.display());
                self.status_line = self.analysis_status.clone();
                self.active_tab = Tab::Data;
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
                            self.analysis_progress = 1.0;
                            self.analysis_status = format!(
                                "AEF erstellt: {} | {:.1}% Gewinn | {}",
                                result.snapshot.file_name,
                                result.snapshot.compression_gain_percent,
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
            Message::Tick => {
                self.tick_counter = self.tick_counter.wrapping_add(1);
                if self.active_tab == Tab::StructureMap || self.active_tab == Tab::ADE {
                    self.step_structure_map();
                    return Task::none();
                }
                if self.browser_surface_mode().is_none() {
                    return Task::none();
                }
                if self.tick_counter % self.browser_sync_stride == 0 {
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
            }
            Message::SecurityRecheck => {
                self.refresh_security_snapshot(true, "manual_recheck");
                self.status_line = "Security-Recheck abgeschlossen.".to_owned();
            }
            Message::TutorialDismissed => {
                self.show_tutorial = false;
                self.status_line = "Shanway-Tutorial ausgeblendet.".to_owned();
            }
            Message::AnchorGroupSelected(index) => self.selected_anchor_group = index,
        }
        Task::none()
    }

    fn root_view(&self) -> Element<'_, Message> {
        if self.current_user.is_none() {
            self.view_auth()
        } else {
            self.view_shell()
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
    application(app_title, app_update, app_view)
        .theme(app_theme)
        .subscription(app_subscription)
        .settings(Settings {
            antialiasing: true,
            ..Settings::default()
        })
        .window(window::Settings {
            size: iced::Size::new(1560.0, 900.0),
            min_size: Some(iced::Size::new(1260.0, 760.0)),
            ..window::Settings::default()
        })
        .run_with(|| (AetherIcedShell::bootstrap(), Task::none()))
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
}

impl canvas::Program<Message> for FlowSphereScene {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        use std::f32::consts::{PI, TAU};

        let mut frame = canvas::Frame::new(renderer, bounds.size());

        // Deep-space background
        frame.fill_rectangle(
            Point::new(0.0, 0.0),
            bounds.size(),
            Color::from_rgb8(0x01, 0x02, 0x06),
        );

        let cx = bounds.width * 0.5;
        let cy = bounds.height * 0.5;
        let base_r = cx.min(cy) * 0.70;
        let r = base_r + (self.info_growth * 32.0).min(32.0);

        let t = self.tick as f32;
        let rot_y = t * 0.006;
        let d = 3.2f32;

        let project = |lat: f32, lon: f32| -> (Point, f32) {
            let x3 = lat.cos() * lon.cos();
            let y3 = lat.sin();
            let z3 = lat.cos() * lon.sin();
            let xr = x3 * rot_y.cos() + z3 * rot_y.sin();
            let yr = y3;
            let zr = -x3 * rot_y.sin() + z3 * rot_y.cos();
            let scale = d / (d - zr * 0.28);
            (Point::new(cx + xr * r * scale, cy - yr * r * scale), zr)
        };

        // ── Deep nebula glow + dark sphere fill ─────────────────────────────────────
        {
            let nb_a = 0.09 + 0.03 * (t * 0.019).sin().abs();
            frame.fill(&canvas::Path::circle(Point::new(cx, cy), r * 0.62), Color::from_rgba(0.38, 0.18, 0.72, nb_a));
            let co_a = 0.045 + 0.02 * (t * 0.031).cos().abs();
            frame.fill(&canvas::Path::circle(Point::new(cx, cy), r * 0.28), Color::from_rgba(0.05, 0.40, 0.85, co_a));
            frame.fill(&canvas::Path::circle(Point::new(cx, cy), r), Color::from_rgb8(0x01, 0x08, 0x12));
        }

        const N_LAT: usize = 20;   // latitude rings
        const N_LON: usize = 38;   // longitude meridians
        const SEGS: usize = 80;    // segments per latitude circle

        // ── Latitude rings — vivid teal/cyan with tick-driven shimmer ───────────
        for li in 0..=N_LAT {
            let lat_base = -PI * 0.5 + PI * (li as f32) / (N_LAT as f32);
            let perturb = self.entropy * 0.08
                * (lat_base * 4.0 + t * 0.018).sin()
                * (1.0 - self.stability * 0.5);
            let lat = lat_base + perturb;
            let lat_frac = (li as f32) / (N_LAT as f32);
            let shimmer = 0.5 + 0.5 * (t * 0.038 + lat_base * 6.0).sin();
            let mut prev: Option<(Point, f32)> = None;
            for seg in 0..=SEGS {
                let lon = TAU * (seg as f32) / (SEGS as f32);
                let (pt, z) = project(lat, lon);
                if let Some((pp, pz)) = prev {
                    let avg_z = (z + pz) * 0.5;
                    if avg_z > -0.92 {
                        let br = ((avg_z + 1.0) * 0.5).powf(0.6).clamp(0.05, 1.0);
                        let eq_b = (1.0 - (lat_frac - 0.5).abs() * 1.0).max(0.1);
                        let sh_b = 1.0 + 0.42 * shimmer * br;
                        let alpha = (0.20 + 0.44 * br * eq_b * sh_b).clamp(0.04, 0.75);
                        let w = 0.55 + 0.68 * br * sh_b;
                        let r_c = 0.04 + 0.15 * (1.0 - (lat_frac - 0.5).abs() * 2.0).max(0.0);
                        let c = Color::from_rgba(r_c * br, 0.72 * br, 0.96 * br, alpha);
                        let seg_path = canvas::Path::new(|p| { p.move_to(pp); p.line_to(pt); });
                        frame.stroke(&seg_path, canvas::Stroke {
                            style: canvas::Style::Solid(c),
                            width: w,
                            ..canvas::Stroke::default()
                        });
                    }
                }
                prev = Some((pt, z));
            }
        }

        // ── Longitude meridians — alternating teal / violet ───────────────
        for li in 0..N_LON {
            let lon_base = TAU * (li as f32) / (N_LON as f32);
            let lon_perturb = self.entropy * 0.05
                * (lon_base * 3.0 + t * 0.012).cos()
                * (1.0 - self.stability * 0.6);
            let lon = lon_base + lon_perturb;
            let violet = li % 5 == 2;
            const LON_SEGS: usize = 56;
            let mut prev: Option<(Point, f32)> = None;
            for seg in 0..=LON_SEGS {
                let lat = -PI * 0.5 + PI * (seg as f32) / (LON_SEGS as f32);
                let (pt, z) = project(lat, lon);
                if let Some((pp, pz)) = prev {
                    let avg_z = (z + pz) * 0.5;
                    if avg_z > -0.92 {
                        let br = ((avg_z + 1.0) * 0.5).powf(0.85).clamp(0.04, 1.0);
                        let alpha = (0.10 + 0.28 * br).clamp(0.03, 0.46);
                        let c = if violet {
                            Color::from_rgba(0.30 * br, 0.12 * br, 0.82 * br, alpha * 1.6)
                        } else {
                            Color::from_rgba(0.04, 0.50 * br, 0.76 * br, alpha)
                        };
                        let seg_path = canvas::Path::new(|p| { p.move_to(pp); p.line_to(pt); });
                        frame.stroke(&seg_path, canvas::Stroke {
                            style: canvas::Style::Solid(c),
                            width: if violet { 0.70 } else { 0.48 },
                            ..canvas::Stroke::default()
                        });
                    }
                }
                prev = Some((pt, z));
            }
        }

        // ── Polar caps — glowing north/south ─────────────────────────────
        for (pole_idx, &pole_lat) in [PI * 0.48f32, -PI * 0.48f32].iter().enumerate() {
            let pulse = 0.75 + 0.25 * (t * 0.052 + pole_idx as f32 * PI).sin();
            let (pole_pt, pole_z) = project(pole_lat, rot_y);
            if pole_z > -0.55 {
                let br = ((pole_z + 1.0) * 0.5).clamp(0.0, 1.0);
                frame.fill(&canvas::Path::circle(pole_pt, 24.0 * pulse), Color::from_rgba(0.0,  0.75, 0.92, 0.055 * br));
                frame.fill(&canvas::Path::circle(pole_pt, 12.0 * pulse), Color::from_rgba(0.18, 0.90, 1.0,  0.16  * br));
                frame.fill(&canvas::Path::circle(pole_pt,  5.5 * pulse), Color::from_rgba(0.65, 0.97, 1.0,  0.62  * br));
            }
        }

        // ── Delta arc events — 5 arcs, wide glow + sharp core ─────────────
        for (arc_idx, &phase) in self.delta_phases.iter().enumerate() {
            let anim_lon = (t * 0.025 + phase * 0.5).rem_euclid(TAU);
            let lat_center = (phase * 0.35 - 0.55).clamp(-PI * 0.45, PI * 0.45);
            let arc_span = PI * 0.44;
            let hot = arc_idx % 2 == 1;
            const ARC_SEGS: usize = 40;
            for pass in 0..2usize {
                let mut prev: Option<(Point, f32)> = None;
                for seg in 0..=ARC_SEGS {
                    let progress = seg as f32 / ARC_SEGS as f32;
                    let lon = (anim_lon + arc_span * progress).rem_euclid(TAU);
                    let lat = lat_center + 0.30 * (progress * PI).sin();
                    let (pt, z) = project(lat, lon);
                    if let Some((pp, pz)) = prev {
                        let avg_z = (z + pz) * 0.5;
                        if avg_z > -0.30 {
                            let br = ((avg_z + 1.0) * 0.5).clamp(0.0, 1.0);
                            let intensity = (1.0 - (progress - 0.5).abs() * 2.0).max(0.0).powf(0.5);
                            let seg_path = canvas::Path::new(|p| { p.move_to(pp); p.line_to(pt); });
                            if pass == 0 {
                                let alpha = 0.22 * intensity * br;
                                let (rc, gc, bc) = if hot { (0.95, 0.30, 0.62) } else { (0.98, 0.88, 0.06) };
                                frame.stroke(&seg_path, canvas::Stroke {
                                    style: canvas::Style::Solid(Color::from_rgba(rc, gc, bc, alpha)),
                                    width: 6.5 * intensity + 1.0,
                                    ..canvas::Stroke::default()
                                });
                            } else {
                                let alpha = (0.82 + 0.18 * br) * intensity;
                                let (rc, gc, bc) = if hot { (1.0, 0.62, 0.82) } else { (1.0, 0.98, 0.38) };
                                frame.stroke(&seg_path, canvas::Stroke {
                                    style: canvas::Style::Solid(Color::from_rgba(rc, gc, bc, alpha)),
                                    width: 1.5 * intensity + 0.4,
                                    ..canvas::Stroke::default()
                                });
                            }
                        }
                    }
                    prev = Some((pt, z));
                }
            }
        }

        // ── Surface data-points (golden spiral, 24 nodes) ────────────────
        {
            const N_SP: usize = 24;
            let golden_angle = 2.399963f32;
            for i in 0..N_SP {
                let lat = ((1.0 - 2.0 * (i as f32 + 0.5) / N_SP as f32).clamp(-1.0, 1.0)).asin()
                    .clamp(-PI * 0.46, PI * 0.46);
                let lon = (i as f32 * golden_angle + rot_y * 0.7).rem_euclid(TAU);
                let (pt, z) = project(lat, lon);
                if z > 0.0 {
                    let br = ((z + 1.0) * 0.5).clamp(0.3, 1.0);
                    let blink = 0.6 + 0.4 * (t * 0.07 + i as f32 * 0.93).sin().abs();
                    let alpha = 0.65 * br * blink;
                    let hp = (i as f32 * 0.43 + t * 0.008).rem_euclid(TAU);
                    let rc = 0.38 + 0.55 * hp.sin().abs();
                    let gc = 0.72 + 0.25 * (hp + 2.1).cos().abs();
                    let bc = 0.88 + 0.12 * (hp + 4.2).sin().abs();
                    frame.fill(&canvas::Path::circle(pt, 2.8 * blink), Color::from_rgba(rc, gc, bc, alpha));
                }
            }
        }

        // ── Attractor nodes — 6 nodes, halos, neural arcs, pulse rings ───
        let mut apts: Vec<(Point, f32, f32)> = Vec::with_capacity(6);
        for (idx, &lon) in self.attractor_lons.iter().enumerate() {
            let lat = match idx % 3 { 0 => 0.30f32, 1 => -0.22f32, _ => 0.0f32 };
            let (pt, z) = project(lat, (lon + rot_y).rem_euclid(TAU));
            let pulse = 1.0 + 0.22 * (t * 0.045 + idx as f32 * std::f32::consts::FRAC_PI_2).sin();
            apts.push((pt, z, pulse));
        }

        // Neural arcs between selected pairs
        let pairs: [(usize, usize); 7] = [(0,1),(1,2),(2,3),(3,4),(4,5),(0,3),(2,5)];
        for (a, b) in pairs {
            let (pa, za, _) = apts[a];
            let (pb, zb, _) = apts[b];
            if za > -0.1 && zb > -0.1 {
                let br = (((za + zb) * 0.5 + 1.0) * 0.5).clamp(0.0, 1.0);
                let ap = (t * 0.033 + a as f32 * 1.1).rem_euclid(TAU);
                let alpha = (0.08 + 0.16 * ap.sin().abs()) * br;
                let arc_path = canvas::Path::new(|p| { p.move_to(pa); p.line_to(pb); });
                frame.stroke(&arc_path, canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(0.18, 0.90, 0.98, alpha)),
                    width: 0.85,
                    ..canvas::Stroke::default()
                });
            }
        }

        // Pulse rings + dot halos
        for (idx, &(pt, z, pulse)) in apts.iter().enumerate() {
            if z > -0.20 {
                let br = ((z + 1.0) * 0.5).clamp(0.0, 1.0);
                // Expanding pulse rings
                for ring in 0..2usize {
                    let raw = (t * 0.018 + idx as f32 * 1.57 + ring as f32 * PI).rem_euclid(TAU) / TAU;
                    let ring_r = raw * r * 0.28;
                    let ring_a = (1.0 - raw) * 0.15 * br;
                    if ring_a > 0.005 {
                        frame.stroke(&canvas::Path::circle(pt, ring_r), canvas::Stroke {
                            style: canvas::Style::Solid(Color::from_rgba(0.08, 0.92, 0.98, ring_a)),
                            width: 1.2 * (1.0 - raw),
                            ..canvas::Stroke::default()
                        });
                    }
                }
                // Halo layers
                frame.fill(&canvas::Path::circle(pt, 20.0 * pulse), Color::from_rgba(0.22, 0.92, 1.0, 0.048 * br));
                frame.fill(&canvas::Path::circle(pt, 10.0 * pulse), Color::from_rgba(0.55, 0.98, 1.0, 0.15  * br));
                frame.fill(&canvas::Path::circle(pt,  5.0 * pulse), Color::from_rgba(0.85, 1.0,  1.0, 0.50  * br));
                frame.fill(&canvas::Path::circle(pt,  2.2),         Color::from_rgba(1.0,  1.0,  1.0, (0.88 + 0.12 * br).min(1.0)));
            }
        }

        // ── Limb darkening — clean dark rings at sphere edge ─────────────
        for i in 0..3usize {
            let ring_r = r - i as f32 * 4.5;
            let alpha = 0.24 / (i as f32 + 1.0);
            frame.stroke(&canvas::Path::circle(Point::new(cx, cy), ring_r), canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.0, 0.0, 0.0, alpha)),
                width: 11.0 - i as f32 * 3.0,
                ..canvas::Stroke::default()
            });
        }

        // ── Outer corona — three layered glow rings ───────────────────────
        {
            let a0 = 0.24 + 0.09 * (t * 0.032).sin();
            frame.stroke(&canvas::Path::circle(Point::new(cx, cy), r + 1.5), canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.58, 0.30, 1.0, a0)),
                width: 2.8,
                ..canvas::Stroke::default()
            });
            let a1 = 0.12 + 0.055 * (t * 0.021 + 1.1).sin();
            frame.stroke(&canvas::Path::circle(Point::new(cx, cy), r + 9.0), canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.42, 0.22, 0.88, a1)),
                width: 1.6,
                ..canvas::Stroke::default()
            });
            let a2 = 0.058 + 0.030 * (t * 0.014 + 2.3).sin();
            frame.stroke(&canvas::Path::circle(Point::new(cx, cy), r + 22.0), canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.20, 0.40, 0.95, a2)),
                width: 1.1,
                ..canvas::Stroke::default()
            });
        }

        // ── Blue pulse shimmer ────────────────────────────────────────────
        {
            let pulse_alpha = 0.042 + 0.030 * (t * 0.041).sin();
            frame.fill(
                &canvas::Path::circle(Point::new(cx, cy), r + 2.0),
                Color::from_rgba(0.04, 0.14, 0.92, pulse_alpha),
            );
        }

        // ── Specular highlight (top-left quadrant, 3D illusion) ───────────
        {
            let hx = cx - r * 0.30;
            let hy = cy - r * 0.36;
            let hi_a = 0.22 + 0.08 * (t * 0.027).sin();
            frame.fill(&canvas::Path::circle(Point::new(hx, hy), r * 0.21), Color::from_rgba(0.62, 0.92, 0.97, hi_a));
            frame.fill(&canvas::Path::circle(Point::new(hx + r * 0.05, hy + r * 0.04), r * 0.08), Color::from_rgba(0.93, 1.0, 1.0, 0.15));
        }

        vec![frame.into_geometry()]
    }
}

// ---------------------------------------------------------------------------
// Aether.StructureMap – legacy Canvas-Renderer (fraktaler 3D-Suchbaum)
// Kept for data generation; rendering now handled by FlowSphereScene.
// ---------------------------------------------------------------------------

/// Trägt die vorberechneten Knoten-Positionen (Theta-Winkel pro Ring).
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
                frame.stroke(
                    &arc,
                    canvas::Stroke {
                        style: canvas::Style::Solid(cut),
                        width: 1.8,
                        ..canvas::Stroke::default()
                    },
                );
            }

            // Knoten zeichnen
            for &theta in &curr {
                let pt = polar(theta, ring_idx);
                if ring_idx == 9 {
                    // Diamant-Anker
                    let r = 6.0f32;
                    let diamond = canvas::Path::new(|b| {
                        b.move_to(Point::new(pt.x,       pt.y - r));
                        b.line_to(Point::new(pt.x + r,   pt.y));
                        b.line_to(Point::new(pt.x,       pt.y + r));
                        b.line_to(Point::new(pt.x - r,   pt.y));
                        b.close();
                    });
                    frame.fill(&diamond, Color::from_rgb8(0xE0, 0xF7, 0xFF));
                    let mut glow = Color::from_rgb8(0xE0, 0xF7, 0xFF);
                    glow.a = 0.08;
                    frame.fill(&canvas::Path::circle(pt, 14.0), glow);
                } else if ring_idx >= 7 {
                    frame.fill(&canvas::Path::circle(pt, 2.5), color);
                } else {
                    let sz = (4.0 - ring_idx as f32 * 0.28).max(1.2);
                    let mut nc = color;
                    nc.a = 0.72;
                    frame.fill(&canvas::Path::circle(pt, sz), nc);
                }
            }
        }

        vec![frame.into_geometry()]
    }
}

// ── AetherLogoScene ──────────────────────────────────────────────────────────

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

// ── ShanwayRobotScene ─────────────────────────────────────────────────────────

struct ShanwayRobotScene {
    tick: u64,
    size: f32,
}

impl canvas::Program<Message> for ShanwayRobotScene {
    type State = ();
    fn draw(&self, _: &(), renderer: &iced::Renderer, _: &Theme, bounds: Rectangle, _: mouse::Cursor) -> Vec<canvas::Geometry<iced::Renderer>> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let t = self.tick as f32;
        let s = self.size;
        let cx = bounds.width * 0.5;
        let cy = bounds.height * 0.5;
        let green = Color::from_rgb8(0x9A, 0x67, 0xFF);
        let cyan  = Color::from_rgb8(0x2A, 0xB6, 0xFF);
        let dark  = Color::from_rgba(0.59, 0.34, 0.96, 0.10);

        // Antenne
        let ant_x = cx;
        let ant_top = cy - s * 0.72;
        let ant_base = cy - s * 0.52;
        let ant = canvas::Path::new(|b| {
            b.move_to(Point::new(ant_x, ant_base));
            b.line_to(Point::new(ant_x, ant_top));
        });
        frame.stroke(&ant, canvas::Stroke { style: canvas::Style::Solid(green), width: 1.8, ..canvas::Stroke::default() });
        frame.fill(&canvas::Path::circle(Point::new(ant_x, ant_top), 3.2), green);

        // Kopf
        let hw = s * 0.42;
        let hh = s * 0.32;
        let hy = cy - s * 0.5 + hh * 0.5;
        let head = canvas::Path::new(|b| {
            let r = 6.0f32;
            b.move_to(Point::new(cx - hw + r, hy - hh));
            b.line_to(Point::new(cx + hw - r, hy - hh));
            b.arc_to(Point::new(cx + hw, hy - hh), Point::new(cx + hw, hy - hh + r), r);
            b.line_to(Point::new(cx + hw, hy + hh - r));
            b.arc_to(Point::new(cx + hw, hy + hh), Point::new(cx + hw - r, hy + hh), r);
            b.line_to(Point::new(cx - hw + r, hy + hh));
            b.arc_to(Point::new(cx - hw, hy + hh), Point::new(cx - hw, hy + hh - r), r);
            b.line_to(Point::new(cx - hw, hy - hh + r));
            b.arc_to(Point::new(cx - hw, hy - hh), Point::new(cx - hw + r, hy - hh), r);
            b.close();
        });
        frame.fill(&head, dark);
        frame.stroke(&head, canvas::Stroke { style: canvas::Style::Solid(green), width: 1.8, ..canvas::Stroke::default() });

        // Augen
        let blink = (t % 120.0) > 116.0;
        let eye_y = hy - s * 0.04;
        let eye_r = if blink { 1.0 } else { s * 0.065 };
        let eye_glow_a = 0.18 + 0.12 * (t * 0.08).sin();
        for &ex in &[cx - hw * 0.38, cx + hw * 0.38] {
            let mut gc = cyan; gc.a = eye_glow_a;
            frame.fill(&canvas::Path::circle(Point::new(ex, eye_y), eye_r * 2.2), gc);
            frame.fill(&canvas::Path::circle(Point::new(ex, eye_y), eye_r), cyan);
        }

        // Mund
        let mouth = canvas::Path::new(|b| {
            b.move_to(Point::new(cx - hw * 0.22, hy + hh * 0.45));
            b.line_to(Point::new(cx + hw * 0.22, hy + hh * 0.45));
        });
        let mut mc = green; mc.a = 0.7;
        frame.stroke(&mouth, canvas::Stroke { style: canvas::Style::Solid(mc), width: 1.5, ..canvas::Stroke::default() });

        // Körper
        let bw = s * 0.38;
        let bh = s * 0.28;
        let by = hy + hh + s * 0.04 + bh * 0.5;
        let body = canvas::Path::new(|b| {
            let r = 5.0f32;
            b.move_to(Point::new(cx - bw + r, by - bh));
            b.line_to(Point::new(cx + bw - r, by - bh));
            b.arc_to(Point::new(cx + bw, by - bh), Point::new(cx + bw, by - bh + r), r);
            b.line_to(Point::new(cx + bw, by + bh - r));
            b.arc_to(Point::new(cx + bw, by + bh), Point::new(cx + bw - r, by + bh), r);
            b.line_to(Point::new(cx - bw + r, by + bh));
            b.arc_to(Point::new(cx - bw, by + bh), Point::new(cx - bw, by + bh - r), r);
            b.line_to(Point::new(cx - bw, by - bh + r));
            b.arc_to(Point::new(cx - bw, by - bh), Point::new(cx - bw + r, by - bh), r);
            b.close();
        });
        frame.fill(&body, dark);
        frame.stroke(&body, canvas::Stroke { style: canvas::Style::Solid(green), width: 1.5, ..canvas::Stroke::default() });

        // Körper-Details
        for i in 0..3 {
            let ly = by - bh * 0.3 + i as f32 * bh * 0.3;
            let mut lc = green; lc.a = 0.25;
            let l = canvas::Path::new(|b| {
                b.move_to(Point::new(cx - bw * 0.55, ly));
                b.line_to(Point::new(cx + bw * 0.55, ly));
            });
            frame.stroke(&l, canvas::Stroke { style: canvas::Style::Solid(lc), width: 1.0, ..canvas::Stroke::default() });
        }

        // Glow-Ring
        let glow_r = hw * 1.35 + 4.0 * (t * 0.05).sin();
        let mut glow_c = green; glow_c.a = 0.05 + 0.03 * (t * 0.05).sin();
        frame.stroke(
            &canvas::Path::circle(Point::new(cx, hy), glow_r),
            canvas::Stroke { style: canvas::Style::Solid(glow_c), width: 8.0, ..canvas::Stroke::default() },
        );

        vec![frame.into_geometry()]
    }
}

// ── Orchestration Canvas ────────────────────────────────────────────────────

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
                    content: "Shanway".to_string(),
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

struct CyberPaneGraphScene {
    tick: u64,
    pulse: f32,
    slide: f32,
}

impl canvas::Program<Message> for CyberPaneGraphScene {
    type State = ();
    fn draw(&self, _s: &(), renderer: &iced::Renderer, _t: &Theme, bounds: Rectangle, _c: mouse::Cursor) -> Vec<canvas::Geometry<iced::Renderer>> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        frame.fill_rectangle(Point::new(0.0, 0.0), bounds.size(), Color::from_rgb8(0x0C, 0x0B, 0x12));
        let t = self.tick as f32;
        let panes = [
            (0.12f32, 0.22f32, 0.24f32, 0.52f32, Color::from_rgba(0.14, 0.42, 0.98, 0.24), "Background"),
            (0.42f32, 0.14f32, 0.22f32, 0.66f32, Color::from_rgba(0.11, 0.82, 0.92, 0.24), "Mid"),
            (0.70f32, 0.24f32, 0.18f32, 0.50f32, Color::from_rgba(0.96, 0.24, 0.66, 0.24), "Overlay"),
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
                style: canvas::Style::Solid(Color::from_rgba(0.20, 0.95, 1.0, 0.60)),
                width: 1.0 + 0.8 * self.pulse,
                ..canvas::Stroke::default()
            });
            let cx = px + pw * 0.5;
            let cy = py + ph * 0.5;
            centers.push(Point::new(cx, cy));
            frame.fill_text(canvas::Text {
                content: format!("{} / {}", label, idx + 1),
                position: Point::new(cx, py + 18.0),
                color: Color::from_rgb8(0xC0, 0xEA, 0xFF),
                size: iced::Pixels(11.0),
                horizontal_alignment: iced::alignment::Horizontal::Center,
                vertical_alignment: iced::alignment::Vertical::Center,
                ..canvas::Text::default()
            });
            let pulse_r = 4.0 + 2.5 * (t * 0.09 + idx as f32).sin().abs();
            frame.fill(&canvas::Path::circle(Point::new(cx, cy), pulse_r), Color::from_rgba(0.0, 1.0, 1.0, 0.9));
        }
        for i in 0..centers.len().saturating_sub(1) {
            let edge = canvas::Path::new(|b| {
                b.move_to(centers[i]);
                b.line_to(centers[i + 1]);
            });
            frame.stroke(&edge, canvas::Stroke {
                style: canvas::Style::Solid(Color::from_rgba(0.16, 0.90, 1.0, 0.70)),
                width: 1.2,
                ..canvas::Stroke::default()
            });
        }
        vec![frame.into_geometry()]
    }
}

// ── Helper functions for new dashboard ───────────────────────────────────────

fn info_icon_button(key: &str) -> Element<'static, Message> {
    button(text("i").size(11).color(c(TEXT_H)))
        .on_press(Message::DashboardInfoToggle(key.to_owned()))
        .padding([2, 8])
        .style(|_: &Theme, _| button::Style {
            background: Some(Background::Color(Color::from_rgba(0.59, 0.34, 0.96, 0.14))),
            border: Border { color: Color::from_rgb8(0xA0, 0x70, 0xFF), width: 1.0, radius: 9.0.into() },
            ..Default::default()
        })
        .into()
}

fn cyber_kpi_card(label: &str, value: String, sub: &str, accent: Color, info_key: &str) -> Element<'static, Message> {
    container(
        column![
            row![
                text("\u{25cf}").size(12).color(accent),
                text(label.to_owned()).size(11).color(c(TEXT_M)),
                iced::widget::Space::new(Length::Fill, Length::Shrink),
                info_icon_button(info_key),
            ]
            .align_y(Alignment::Center),
            text(value).size(32).color(accent),
            text(sub.to_owned()).size(11).color(c(TEXT_D)),
        ]
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

fn ade_subpanel<'a>(title: &'a str, body: Element<'a, Message>, panel_bg: Color) -> Element<'a, Message> {
    container(
        column![
            text(title.to_owned()).size(12).color(Color::from_rgb8(0x9A, 0x67, 0xFF)),
            body,
        ]
        .spacing(8)
        .padding(14),
    )
    .style(move |_: &Theme| container::Style {
        background: Some(Background::Color(panel_bg)),
        border: Border { color: Color::from_rgb8(0x0A, 0x28, 0x38), width: 1.0, radius: 4.0.into() },
        ..Default::default()
    })
    .width(Length::Fill)
    .into()
}

fn standard_card_style(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(c(BG_CARD))),
        border: Border {
            color: c(BORDER),
            width: 1.2,
            radius: 14.0.into(),
        },
        ..Default::default()
    }
}

fn accent_card_style(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(c(BG_CARD2))),
        border: Border {
            color: c(BORDER_ACT),
            width: 1.4,
            radius: 14.0.into(),
        },
        ..Default::default()
    }
}

fn selected_item_style(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(0.59, 0.34, 0.96, 0.20))),
        border: Border {
            color: c(BORDER_ACT),
            width: 1.5,
            radius: 10.0.into(),
        },
        ..Default::default()
    }
}

fn primary_button_style(_: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(Background::Color(Color::from_rgb8(0x96, 0x57, 0xF7))),
        text_color: Color::from_rgb8(0xF2, 0xED, 0xFF),
        border: Border {
            color: Color::from_rgb8(0xB4, 0x84, 0xFF),
            width: 1.0,
            radius: 12.0.into(),
        },
        ..Default::default()
    }
}

fn secondary_button_style(_: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(Background::Color(Color::from_rgb8(0x12, 0x1B, 0x33))),
        text_color: c(TEXT_H),
        border: Border {
            color: Color::from_rgb8(0x2E, 0x2C, 0x4C),
            width: 1.0,
            radius: 12.0.into(),
        },
        ..Default::default()
    }
}

fn panel_frame_style(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgb8(0x13, 0x12, 0x1E))),
        border: Border {
            color: Color::from_rgb8(0x2E, 0x2C, 0x4E),
            width: 1.2,
            radius: 14.0.into(),
        },
        ..Default::default()
    }
}

fn sys_metric_card(label: &str, value: String, fill: f32, accent: Color) -> Element<'static, Message> {
    container(
        column![
            text(label.to_owned())
                .size(11)
                .color(Color::from_rgb8(0x4E, 0x4A, 0x76)),
            text(value)
                .size(22)
                .color(accent),
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
            .height(Length::Fixed(3.0)),
        ]
        .spacing(8),
    )
    .style(accent_card_style)
    .padding([14, 18])
    .width(Length::Fill)
    .into()
}

fn event_row<'a>(time: &str, tag: &str, msg: &str, tag_color: Color) -> Element<'a, Message> {
    container(
        row![
            text(time.to_owned()).size(11).color(Color::from_rgb8(0x62, 0x5E, 0x90)),
            container(text(tag.to_owned()).size(11).color(tag_color))
                .padding([2, 6])
                .style(move |_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgba(tag_color.r * 0.15, tag_color.g * 0.15, tag_color.b * 0.15, 1.0))),
                    border: Border { color: tag_color, width: 1.0, radius: 4.0.into() },
                    ..Default::default()
                }),
            text(msg.to_owned()).size(12).color(Color::from_rgb8(0xA8, 0xC4, 0xD8)),
        ]
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
        column![
            text(title.to_owned()).size(16),
            text(body.to_owned()).size(14),
        ]
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
        column![
            text("▶ ANALYSEFLUSS").size(16),
            progress_bar(0.0..=1.0, progress.clamp(0.0, 1.0)),
            text(make_sparkline(progress)).size(13),
            text(status.to_owned()).size(15),
            text(hint.to_owned()).size(13),
            text(detail.to_owned()).size(13),
        ]
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

fn register_card(entry: RegisterEntry) -> Element<'static, Message> {
    let gain_fill = entry.compression_gain_percent / 100.0;
    let preview_upper = entry.preview_note.to_ascii_uppercase();
    let suspicious = preview_upper.contains("EICAR")
        || preview_upper.contains("OBF")
        || preview_upper.contains("QUARANTINE")
        || preview_upper.contains("CRITICAL");
    container(
        column![
            text(format!("▤ {} | {}", entry.id, entry.file_name)).size(16),
            text(format!(
                "{} | {} B orig | {} B delta | {:.2}% Gain",
                entry.source_kind,
                entry.original_size,
                entry.delta_size,
                entry.compression_gain_percent
            ))
            .size(13),
            text(make_sparkline(gain_fill)).size(12),
            text(entry.anchor_summary.clone()).size(13),
            text(entry.preview_note.clone())
                .size(13)
                .color(if suspicious {
                    Color::from_rgb8(0xFF, 0xAE, 0x42)
                } else {
                    c(TEXT_M)
                }),
        ]
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

async fn analyze_file_for_register(
    path: PathBuf,
    username: String,
    data_key: Option<DataKey>,
) -> Result<FileAnalysisResult, String> {
    let original_bytes = fs::read(&path)
        .map_err(|e| format!("Datei konnte nicht gelesen werden: {e}"))?;

    // Create AEF output directory
    let aef_dir = PathBuf::from("data")
        .join("rust_shell")
        .join("aef_store")
        .join(&username);
    fs::create_dir_all(&aef_dir)
        .map_err(|e| format!("AEF-Verzeichnis konnte nicht erstellt werden: {e}"))?;
    let file_stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let aef_path = aef_dir.join(format!("{file_stem}.aef"));

    // Load vault and build encoder
    let vault = VaultStore::load_default().map_err(|e| format!("Vault: {e}"))?;
    let vault = Arc::new(RwLock::new(vault));
    let engine = Arc::new(EnginePipeline::new());
    let encoder = if let Some(dk) = data_key {
        AefEncoder::new(Arc::clone(&vault), Arc::clone(&engine)).withdatakey(dk)
    } else {
        AefEncoder::new(Arc::clone(&vault), Arc::clone(&engine))
    };

    // Encode the file to .aef
    let encode_result = encoder
        .encode_sync(&path, &aef_path)
        .map_err(|e| format!("AEF-Encoding fehlgeschlagen: {e}"))?;

    let original_size = encode_result.original_size;
    let delta_size = encode_result.delta_size;
    let compression_gain_percent =
        ((1.0 - encode_result.compression_rate).clamp(0.0, 1.0) * 10000.0).round() / 100.0;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unbekannt")
        .to_owned();
    let source_kind = detect_source_kind(&path, &original_bytes);

    let original_text = if is_text_like_file(&path) {
        String::from_utf8_lossy(&original_bytes).to_string()
    } else {
        String::new()
    };
    let ethics = structural_text_integrity(
        &original_text,
        Some(encode_result.coherence_index),
    );
    let obfuscation = if original_text.is_empty() {
        0.0
    } else {
        code_suspicion_score(&original_text)
    };
    let eicar_hit = original_text
        .to_ascii_uppercase()
        .contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE");

    let mut metrics = BTreeMap::from([
        ("entropy_mean".to_owned(), encode_result.coherence_index as f64),
        ("trust_score".to_owned(), encode_result.trust_score as f64),
        (
            "compression_gain_percent".to_owned(),
            compression_gain_percent as f64,
        ),
        (
            "anchor_count".to_owned(),
            encode_result.anchor_count as f64,
        ),
        ("ethics_score".to_owned(), ethics.score),
        ("ethics_zipf".to_owned(), ethics.zipf),
        ("ethics_noether".to_owned(), ethics.noether),
        ("obfuscation_score".to_owned(), obfuscation),
        ("eicar_hit".to_owned(), if eicar_hit { 1.0 } else { 0.0 }),
    ]);

    // Hard boundary: any lab-like metrics must pass strict schema validation before use.
    let safe_id = format!("{}_{}", username, file_stem)
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let lab_response = LabResponse {
        schema_version: LAB_SCHEMA_VERSION,
        request_id: format!("reg_{safe_id}"),
        model: "observer".to_owned(),
        metrics: BTreeMap::from([
            ("h_lambda".to_owned(), encode_result.coherence_index as f64),
            (
                "observer_coherence".to_owned(),
                encode_result.coherence_index as f64,
            ),
            ("beauty_score".to_owned(), encode_result.trust_score as f64),
            (
                "graph_density".to_owned(),
                (compression_gain_percent as f64 / 100.0).clamp(0.0, 1.0),
            ),
        ]),
        diagnostics: vec!["local_rust_analysis".to_owned()],
    };
    validate_response(&lab_response)
        .map_err(|err| format!("Boundary-Reject (fail-closed): {err}"))?;
    let stable_metrics = extract_stable_metrics(&lab_response);
    if let Some(value) = stable_metrics.h_lambda {
        metrics.insert("lab_h_lambda".to_owned(), value);
    }
    if let Some(value) = stable_metrics.observer_coherence {
        metrics.insert("lab_observer_coherence".to_owned(), value);
    }
    if let Some(value) = stable_metrics.graph_density {
        metrics.insert("lab_graph_density".to_owned(), value);
    }
    if let Some(value) = stable_metrics.beauty_score {
        metrics.insert("lab_beauty_score".to_owned(), value);
    }
    let evidence_refs = vec![aef_path.display().to_string()];
    let policy_engine = RuleEngine::new(default_analysis_rules(), None)
        .map_err(|err| format!("Policy-Engine fehlgeschlagen: {err}"))?;
    let policy_hits = policy_engine.evaluate_all(
        &metrics,
        &file_name,
        "aether_iced_analysis",
        &evidence_refs,
        true,
    );
    let policy_summary = if policy_hits.is_empty() {
        "Policy: keine Regel aktiv".to_owned()
    } else {
        let labels = policy_hits
            .iter()
            .map(|entry| format!("{}:{}", entry.action, entry.rule_ids.join("+")))
            .collect::<Vec<_>>()
            .join(" | ");
        format!("Policy: {labels}")
    };
    let cascade_summary = format!(
        "Cascade: Ethics {:.2} | Obf {:.2} | EICAR {}",
        ethics.score,
        obfuscation,
        if eicar_hit { "HIT" } else { "no" }
    );
    let preview_note = format!(
        "AEF | E_\u{03bb}: {:.2} ({}) | Trust: {:.0}% | Lossless: {} | {} | {}",
        encode_result.e_lambda,
        encode_result.e_lambda_label,
        encode_result.trust_score * 100.0,
        if encode_result.lossless_confirmed { "ja" } else { "nein" },
        policy_summary,
        cascade_summary
    );
    let anchor_summary = format!(
        "{} Anker | {:.1}% Kompression | Trust: {:.0}%",
        encode_result.anchor_count,
        compression_gain_percent,
        encode_result.trust_score * 100.0
    );
    let process_summary = format!(
        "AEF-Encoding: {} B \u{2192} {} B | E_\u{03bb}={:.2} | {} | {}",
        original_size, delta_size, encode_result.e_lambda, policy_summary, cascade_summary
    );

    Ok(FileAnalysisResult {
        entry: RegisterEntry {
            id: 0,
            owner_username: username,
            file_name: file_name.clone(),
            full_path: aef_path.to_string_lossy().to_string(),
            source_kind,
            original_size,
            delta_size,
            compression_gain_percent,
            anchor_summary: anchor_summary.clone(),
            process_summary: process_summary.clone(),
            preview_note: preview_note.clone(),
        },
        snapshot: AnalysisSnapshot {
            file_name,
            original_size,
            delta_size,
            compression_gain_percent,
            anchor_summary,
            process_summary,
            preview_note,
        },
    })
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

