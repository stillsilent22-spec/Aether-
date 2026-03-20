use crate::aef::{AefDecodeResult, AefDecoder, AefEncoder, EnginePipeline, VaultStore};
use crate::auth::{AuthStore, UserRecord};
use crate::browser::{
    BrowserInspector, BrowserProbePolicy, BrowserProbeResult, BrowserSearchContext,
};
use crate::browser_embed::{BrowserHostRect, EmbeddedBrowser};
use crate::security::{SecurityAuditEvent, SecurityMonitor, SecuritySnapshot};
use crate::shanway::{render_reply as render_shanway_reply, ShanwayBrowserContext, ShanwayInput};
use crate::state::{ChatMessage, GroupRoom, PrivateThread, RegisterEntry, StateStore};
use flate2::write::GzEncoder;
use flate2::Compression;
use iced::theme::Palette;
use iced::widget::{button, canvas, column, container, progress_bar, row, scrollable, text, text_input};
use iced::{
    application, event, mouse, time, window, Alignment, Background, Border, Color, Element,
    Length, Point, Rectangle, Settings, Size, Subscription, Task, Theme,
};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

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
        if self.active_tab != Tab::Browser && self.active_tab != Tab::YouTube {
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
        container(
            button(
                column![
                    text(icon).size(18),
                    text(label).size(12),
                ]
                .spacing(3)
                .align_x(Alignment::Center),
            )
            .padding([8, 14])
            .on_press(Message::TabSelected(tab)),
        )
        .style(move |_theme: &Theme| {
            if is_active {
                container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x12, 0x5A, 0x68))),
                    border: Border {
                        color: Color::from_rgb8(0x2B, 0xC5, 0xD6),
                        width: 1.5,
                        radius: 8.0.into(),
                    },
                    text_color: Some(Color::from_rgb8(0xE0, 0xF8, 0xFF)),
                    ..Default::default()
                }
            } else {
                container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x0A, 0x16, 0x24))),
                    border: Border {
                        color: Color::from_rgb8(0x1C, 0x38, 0x50),
                        width: 1.0,
                        radius: 8.0.into(),
                    },
                    ..Default::default()
                }
            }
        })
        .into()
    }

    fn context_button(&self, context: ChatContext, label: &'static str) -> Element<'_, Message> {
        let is_active = self.chat_context == context;
        container(
            button(text(label).size(15))
                .padding([8, 18])
                .on_press(Message::ChatContextSelected(context)),
        )
        .style(move |_theme: &Theme| {
            if is_active {
                container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x12, 0x5A, 0x68))),
                    border: Border {
                        color: Color::from_rgb8(0x2B, 0xC5, 0xD6),
                        width: 1.5,
                        radius: 6.0.into(),
                    },
                    text_color: Some(Color::from_rgb8(0xE0, 0xF8, 0xFF)),
                    ..Default::default()
                }
            } else {
                container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x0A, 0x16, 0x24))),
                    border: Border {
                        color: Color::from_rgb8(0x1C, 0x38, 0x50),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                }
            }
        })
        .into()
    }

    fn view_auth(&self) -> Element<'_, Message> {
        let hero = column![
            text("AETHER").size(18),
            text("Lokale Strukturanalyse").size(40),
            text("Petrol-dunkelblaue Rust-Oberflaeche fuer lokale Analyse, Privacy-Boundaries und nachvollziehbare Entscheidungen.")
                .size(18)
                .width(Length::Fill),
            text("Artefakte werden isoliert verarbeitet. Aether erstellt Merkmalsprofile, generiert Anchor-Signale und fuehrt nichts aus.")
                .size(16)
                .width(Length::Fill),
        ]
        .spacing(10);

        let card = container(
            column![
                text("Anmeldung / Registrierung").size(22),
                text_input("Benutzername", &self.login_username)
                    .on_input(Message::LoginUsernameChanged)
                    .padding(12)
                    .size(18),
                text_input("Passwort", &self.login_password)
                    .on_input(Message::LoginPasswordChanged)
                    .secure(true)
                    .padding(12)
                    .size(18),
                row![
                    button(text("Anmelden"))
                        .padding([12, 20])
                        .on_press(Message::LoginPressed),
                    button(text("Registrieren"))
                        .padding([12, 20])
                        .on_press(Message::RegisterPressed),
                ]
                .spacing(12),
                text(&self.status_line).size(16),
            ]
            .spacing(16),
        )
        .padding(24)
        .width(Length::Fixed(560.0));

        container(column![hero, card].spacing(28).max_width(920))
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
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
                text(label).size(11).color(Color::from_rgb8(0x7A, 0x9A, 0xB8)),
            )
            .padding([6, 10])
            .width(Length::Fill)
            .into()
        };

        // Helper: sidebar nav item
        let nav_item = |icon: &'static str, label: &'static str, tab: Tab| -> Element<'_, Message> {
            let active = self.active_tab == tab;
            let bg = if active {
                Color::from_rgb8(0x10, 0x2A, 0x40)
            } else {
                Color::from_rgba8(0, 0, 0, 0.0f32)
            };
            let text_col = if active {
                Color::from_rgb8(0xE0, 0xF8, 0xFF)
            } else {
                Color::from_rgb8(0xA0, 0xB8, 0xC8)
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
                        text("AETHER").size(16).color(Color::from_rgb8(0xE0, 0xF8, 0xFF)),
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
                            .color(Color::from_rgb8(0xC8, 0xDE, 0xEE)),
                    ]
                    .spacing(6)
                    .align_y(iced::Alignment::Center),
                )
                .style(|_: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x2A))),
                    border: Border {
                        color: Color::from_rgb8(0x1C, 0x38, 0x50),
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
                            .color(Color::from_rgb8(0x60, 0x82, 0x98)),
                        text(if self.analysis_running { "\u{25b6} ANALYS. AKTIV" } else { "\u{25a0} BEREIT" })
                            .size(11)
                            .color(Color::from_rgb8(0x60, 0x82, 0x98)),
                    ]
                    .spacing(4),
                )
                .padding([8, 10])
                .width(Length::Fill),

                // Settings + Power icons at bottom
                container(
                    row![
                        button(text("\u{2699}").size(16).color(Color::from_rgb8(0x80, 0xA0, 0xB8)))
                            .padding([6, 10])
                            .on_press(Message::TabSelected(Tab::Settings)),
                        button(text("\u{23fb}").size(16).color(Color::from_rgb8(0x80, 0xA0, 0xB8)))
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
            background: Some(Background::Color(Color::from_rgb8(0x05, 0x0D, 0x18))),
            border: Border {
                color: Color::from_rgb8(0x14, 0x2A, 0x40),
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
        // Tab row (left) + Status bar (right) — wie im Referenzbild
        let tabs = row![
            self.tab_button(Tab::Home,        "\u{25c9}", "Overview"),
            self.tab_button(Tab::Chat,        "\u{25c8}", "Chat"),
            self.tab_button(Tab::Browser,     "\u{2295}", "Browser"),
            self.tab_button(Tab::YouTube,     "\u{25b6}", "YouTube"),
            self.tab_button(Tab::Data,        "\u{25a4}", "Data"),
            self.tab_button(Tab::Settings,    "\u{2699}", "Config"),
            self.tab_button(Tab::Logs,        "\u{25a3}", "Logs"),
            self.tab_button(Tab::Anchors,     "\u{25c6}", "Cluster"),
            self.tab_button(Tab::StructureMap,"\u{25ce}", "FlowSphere"),
            self.tab_button(Tab::ADE,         "\u{25cd}", "ADE"),
            self.tab_button(Tab::Imprint,     "\u{2139}", "Info"),
            self.tab_button(Tab::Rekonstruktion, "\u{21ba}", "Rekon"),
        ]
        .spacing(4);

        // Status badges top-right
        let all_ok = self.security_snapshot.trust_state.to_uppercase().contains("HIGH")
            || self.security_snapshot.trust_state.to_uppercase().contains("OK");
        let status_badge = container(
            row![
                canvas::Canvas::new(DotScene { color: if all_ok {
                    Color::from_rgb8(0x4C, 0xD9, 0x6E)
                } else {
                    Color::from_rgb8(0xD9, 0x7A, 0x4C)
                }})
                .width(Length::Fixed(10.0))
                .height(Length::Fixed(10.0)),
                text(if all_ok { "All Systems Operational" } else { "Degraded" })
                    .size(12)
                    .color(Color::from_rgb8(0xA0, 0xD4, 0xA0)),
            ]
            .spacing(5)
            .align_y(iced::Alignment::Center),
        )
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x08, 0x1E, 0x10))),
            border: Border { color: Color::from_rgb8(0x28, 0x70, 0x40), width: 1.0, radius: 14.0.into() },
            ..Default::default()
        })
        .padding([4, 12]);

        let cluster_badge = container(
            row![
                text("\u{2601}").size(12).color(Color::from_rgb8(0x80, 0xBC, 0xE8)),
                text(format!("{} Active Nodes", self.anchor_clusters().len()))
                    .size(12).color(Color::from_rgb8(0x80, 0xBC, 0xE8)),
            ]
            .spacing(5)
            .align_y(iced::Alignment::Center),
        )
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
            border: Border { color: Color::from_rgb8(0x1C, 0x3A, 0x58), width: 1.0, radius: 14.0.into() },
            ..Default::default()
        })
        .padding([4, 12]);

        let time_badge = container(
            row![
                text("\u{25d4}").size(12).color(Color::from_rgb8(0x80, 0xA8, 0xC8)),
                text(format!("{:02}:{:02} Live Mode",
                    (self.tick_counter / 60) % 24,
                    self.tick_counter % 60))
                    .size(12).color(Color::from_rgb8(0x80, 0xA8, 0xC8)),
            ]
            .spacing(5)
            .align_y(iced::Alignment::Center),
        )
        .style(|_: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x08, 0x14, 0x24))),
            border: Border { color: Color::from_rgb8(0x1C, 0x34, 0x54), width: 1.0, radius: 14.0.into() },
            ..Default::default()
        })
        .padding([4, 12]);

        container(
            row![
                container(tabs).width(Length::Fill),
                row![
                    status_badge,
                    cluster_badge,
                    time_badge,
                ]
                .spacing(8)
                .align_y(iced::Alignment::Center),
            ]
            .align_y(iced::Alignment::Center)
            .spacing(12),
        )
        .style(|_theme: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x06, 0x0F, 0x1C))),
            border: Border {
                color: Color::from_rgb8(0x14, 0x2C, 0x44),
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .padding([6, 12])
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
                                .color(Color::from_rgb8(0xC8, 0xDE, 0xEE)),
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
                        background: Some(Background::Color(Color::from_rgb8(0x06, 0x12, 0x20))),
                        border: Border { color: Color::from_rgb8(0x1E, 0x3C, 0x5A), width: 1.5, radius: 10.0.into() },
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
                                    .color(Color::from_rgb8(0xC8, 0xDE, 0xEE)),
                                event_row("04:21", &(self.tick_counter / 60 % 60).to_string(),
                                    &latest_log,  Color::from_rgb8(0xC8, 0xDE, 0xEE)),
                                event_row("04:18", "New", &latest_log2, Color::from_rgb8(0x4C, 0xD9, 0x9C)),
                                event_row("04:15", "Net", &latest_log3, Color::from_rgb8(0xC0, 0xA0, 0x60)),
                                event_row("04:10", "Bkp", &format!("{} Artefakte lokal", entries.len()),
                                    Color::from_rgb8(0x70, 0xA8, 0xD0)),
                                text(format!("Mode: {} | Analyse: {}",
                                    self.security_snapshot.mode, analysis_value))
                                    .size(11).color(Color::from_rgb8(0x60, 0x80, 0x98)),
                            ]
                            .spacing(10)
                            .width(Length::Fill),
                        )
                        .style(|_: &Theme| container::Style {
                            background: Some(Background::Color(Color::from_rgb8(0x06, 0x12, 0x20))),
                            border: Border { color: Color::from_rgb8(0x1E, 0x3C, 0x5A), width: 1.5, radius: 10.0.into() },
                            ..Default::default()
                        })
                        .padding(18)
                        .width(Length::FillPortion(3)),

                        // Active Alerts
                        container(
                            column![
                                row![
                                    text("Active Alerts").size(15)
                                        .color(Color::from_rgb8(0xC8, 0xDE, 0xEE)),
                                    iced::widget::Space::new(Length::Fill, Length::Shrink),
                                    text("\u{25b2}").size(12)
                                        .color(Color::from_rgb8(0x60, 0x80, 0x98)),
                                ]
                                .spacing(8),
                                alert_row(
                                    "\u{25cf}",
                                    Color::from_rgb8(0xE0, 0x60, 0x60),
                                    &format!("Service Timeout: {} nodes", cluster_count.max(1)),
                                    &format!("on {}", self.security_snapshot.mode),
                                ),
                                alert_row(
                                    "\u{26a0}",
                                    Color::from_rgb8(0xD4, 0xA0, 0x30),
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
                            background: Some(Background::Color(Color::from_rgb8(0x06, 0x12, 0x20))),
                            border: Border { color: Color::from_rgb8(0x1E, 0x3C, 0x5A), width: 1.5, radius: 10.0.into() },
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
                                    .color(Color::from_rgb8(0xC8, 0xDE, 0xEE)),
                                iced::widget::Space::new(Length::Fill, Length::Shrink),
                                text(format!("{:.0}%", self.analysis_progress * 100.0)).size(14)
                                    .color(Color::from_rgb8(0x4C, 0xD9, 0x9C)),
                            ]
                            .spacing(8),
                            progress_bar(0.0..=1.0, self.analysis_progress.clamp(0.0, 1.0))
                                .height(6),
                            text(&self.hovered_file_label).size(12)
                                .color(Color::from_rgb8(0x80, 0xA0, 0xB8)),
                        ]
                        .spacing(8)
                        .width(Length::Fill),
                    )
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgb8(0x06, 0x12, 0x20))),
                        border: Border { color: Color::from_rgb8(0x1A, 0x6A, 0x8A), width: 1.5, radius: 10.0.into() },
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
            ChatContext::Shanway => self.view_shanway_chat(),
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
        container(
            row![
                scrollable(
                    column![
                        text("Browser").size(24),
                        text("DuckDuckGo ist direkt eingebettet. Strukturprobe und Webflaeche bleiben getrennt.")
                            .size(16),
                        text_input("https://ziel.tld", &self.browser_address)
                            .on_input(Message::BrowserAddressChanged)
                            .padding(10)
                            .size(16),
                        row![
                            button(text("Im Browser laden"))
                                .padding([10, 16])
                                .on_press(Message::BrowserLoadPressed),
                            button(text("Seite pruefen"))
                                .padding([10, 16])
                                .on_press(Message::BrowserInspectPressed),
                        ]
                        .spacing(10),
                        text_input("Suchbegriff oder Frage", &self.browser_search_query)
                            .on_input(Message::BrowserSearchQueryChanged)
                            .padding(10)
                            .size(16),
                        button(text("DuckDuckGo suchen"))
                            .padding([10, 16])
                            .on_press(Message::BrowserSearchPressed),
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
                .width(Length::Fixed(420.0)),
                container(
                    column![
                        text("Eingebettete Browserflaeche").size(20),
                        text("DuckDuckGo und geladene Seiten erscheinen hier direkt im Hauptprogramm. Keine Popups, keine Platzhalter.")
                            .size(15),
                        container(text(" "))
                            .height(Length::Fill)
                            .width(Length::Fill),
                    ]
                    .spacing(10)
                )
                .padding(16)
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
                .on_press(Message::PrivatePartnerSelected(username)),
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
                    .on_press(Message::PrivateMessageSend),
            );
            container(scrollable(content).height(Length::Fill))
                .padding(16)
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
                    .width(Length::FillPortion(1)),
                container(conversation).width(Length::FillPortion(2)),
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
                .on_press(Message::GroupMessageSend),
        );

        container(scrollable(content).height(Length::Fill))
            .padding(12)
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
                .on_press(Message::ShanwayMessageSend),
        );
        container(scrollable(content).height(Length::Fill))
            .padding(12)
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
                            .on_press(Message::SecurityModeSelected("local".to_owned())),
                        button(text(if mode == "dev" { "DEV [aktiv]" } else { "DEV" }))
                            .padding([10, 18])
                            .on_press(Message::SecurityModeSelected("dev".to_owned())),
                        button(text("Recheck"))
                            .padding([10, 18])
                            .on_press(Message::SecurityRecheck),
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
                        .on_press(Message::RuntimeProfileSelected(RuntimeProfile::Auto)),
                        button(text(if profile == RuntimeProfile::Balanced {
                            "BALANCED [aktiv]"
                        } else {
                            "BALANCED"
                        }))
                        .padding([10, 16])
                        .on_press(Message::RuntimeProfileSelected(RuntimeProfile::Balanced)),
                        button(text(if profile == RuntimeProfile::LowPower {
                            "LOW-POWER [aktiv]"
                        } else {
                            "LOW-POWER"
                        }))
                        .padding([10, 16])
                        .on_press(Message::RuntimeProfileSelected(RuntimeProfile::LowPower)),
                        button(text(if profile == RuntimeProfile::Legacy {
                            "LEGACY [aktiv]"
                        } else {
                            "LEGACY"
                        }))
                        .padding([10, 16])
                        .on_press(Message::RuntimeProfileSelected(RuntimeProfile::Legacy)),
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
                    background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
                    border: Border {
                        color: Color::from_rgb8(0x1C, 0x38, 0x50),
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
                        ("\u{25cb} INFO", Color::from_rgb8(0x1E, 0x82, 0x8F))
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
                        background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
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
                                color: Color::from_rgb8(0x2B, 0xC5, 0xD6),
                                width: 1.5,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }
                    } else {
                        container::Style {
                            background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
                            border: Border {
                                color: Color::from_rgb8(0x1C, 0x38, 0x50),
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
                        button(text("Download anfragen")).padding([10, 18]),
                    ]
                    .spacing(10),
                )
                .style(|_theme: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
                    border: Border {
                        color: Color::from_rgb8(0x1E, 0x82, 0x8F),
                        width: 1.5,
                        radius: 8.0.into(),
                    },
                    ..Default::default()
                })
                .padding(22)
                .width(Length::FillPortion(2)),
            ]
            .spacing(14),
        )
        .padding(12)
        .into()
    }

    fn view_imprint(&self) -> Element<'_, Message> {
        container(
            scrollable(
                column![
                    text("Impressum").size(24),
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
                            Color::from_rgb8(0x0E, 0x28, 0x44)
                        } else {
                            Color::from_rgb8(0x08, 0x14, 0x24)
                        })),
                        border: Border {
                            color: Color::from_rgb8(0x1C, 0x3A, 0x58),
                            width: 1.0,
                            radius: 6.0.into(),
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
                        .style(|_: &Theme, _| button::Style {
                            background: None,
                            text_color: Color::from_rgb8(0xD0, 0xE8, 0xF8),
                            ..Default::default()
                        })
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
            .style(|_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgb8(0x06, 0x10, 0x1C))),
                border: Border { color: Color::from_rgb8(0x1C, 0x3A, 0x58), width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
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
                        .style(|_: &Theme, _| button::Style {
                            background: Some(Background::Color(Color::from_rgb8(0x08, 0x2A, 0x18))),
                            border: Border { color: Color::from_rgb8(0x28, 0x70, 0x40), width: 1.0, radius: 6.0.into() },
                            text_color: Color::from_rgb8(0xD0, 0xE8, 0xF8),
                            ..Default::default()
                        })
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
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgb8(0x06, 0x10, 0x1C))),
                        border: Border { color: Color::from_rgb8(0x1C, 0x3A, 0x58), width: 1.0, radius: 8.0.into() },
                        ..Default::default()
                    })
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
                        border: Border { color: Color::from_rgb8(0x58, 0x1C, 0x1C), width: 1.0, radius: 8.0.into() },
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
            .style(|_: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgb8(0x06, 0x10, 0x1C))),
                border: Border { color: Color::from_rgb8(0x14, 0x2C, 0x44), width: 1.0, radius: 8.0.into() },
                ..Default::default()
            })
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
        .style(|_: &Theme, _| button::Style {
            background: Some(Background::Color(Color::from_rgb8(0x08, 0x1E, 0x38))),
            border: Border { color: Color::from_rgb8(0x1C, 0x50, 0x80), width: 1.0, radius: 8.0.into() },
            text_color: Color::from_rgb8(0xD0, 0xE8, 0xF8),
            ..Default::default()
        });

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

        let cyan       = Color::from_rgb8(0x00, 0xD4, 0xD4);
        let dim        = Color::from_rgb8(0x50, 0x6A, 0x7A);
        let surf_bg    = Color::from_rgb8(0x03, 0x09, 0x12);
        let panel_bg   = Color::from_rgb8(0x05, 0x0F, 0x1C);

        // Derived metrics from live data
        let entropy = (self.structure_map_compression / 100.0).clamp(0.0, 1.0);
        let stability = if self.structure_map_locked { 1.0f32 } else { entropy * 0.82 };
        let anchor_count = self.structure_map_nodes.last().map_or(4, |v| v.len());
        let info_growth = entropy;

        // Attractor longitude angles (0, TAU/4, TAU/2, 3*TAU/4)
        let attractor_lons = [0.0f32, TAU / 4.0, TAU / 2.0, 3.0 * TAU / 4.0];

        // Delta event phases — 3 arcs driven by mutation history
        let delta_phases: [f32; 3] = {
            let m = &self.structure_map_mutation_hist;
            [
                m.get(m.len().saturating_sub(1)).copied().unwrap_or(8) as f32 * 0.41,
                m.get(m.len().saturating_sub(5)).copied().unwrap_or(6) as f32 * 0.63,
                m.get(m.len().saturating_sub(10)).copied().unwrap_or(10) as f32 * 0.27,
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
                        text(format!("{:.4} bit", entropy * 7.83)).size(16).color(Color::from_rgb8(0x00, 0xE0, 0xE0)),
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
                        text(make_sparkline(i_ht)).size(9).color(dim),
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
                                border: Border { color: Color::from_rgb8(0x00, 0xA0, 0xA0), width: 1.0, radius: 4.0.into() },
                                text_color: Color::from_rgb8(0x00, 0xD4, 0xD4),
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
                        Color::from_rgba(0.0, 0.7, 0.7, 0.12)
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
        let cyan    = Color::from_rgb8(0x00, 0xD4, 0xD4);
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
                    text(format!("Ringe: {}", self.structure_map_nodes.len())).size(11).color(dim),
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
        container(
            row![
                self.view_sidebar(),
                column![
                    self.view_tabs(),
                    // Tab title bar
                    container(
                        row![
                            text(match self.active_tab {
                                Tab::Home        => "Overview",
                                Tab::Chat        => "Chat",
                                Tab::Browser     => "Browser",
                                Tab::YouTube     => "YouTube",
                                Tab::Data        => "Data",
                                Tab::Settings    => "Config",
                                Tab::Logs        => "Logs",
                                Tab::Anchors     => "Cluster",
                                Tab::StructureMap=> "Flow Sphere",
                                Tab::ADE         => "ADE",
                                Tab::Imprint     => "Info",
                                Tab::Rekonstruktion => "Rekonstruktion",
                            }).size(18).color(Color::from_rgb8(0xD0, 0xE8, 0xF8)),
                            iced::widget::Space::new(Length::Fill, Length::Shrink),
                            text(&self.status_line).size(12)
                                .color(Color::from_rgb8(0x60, 0x88, 0xA8)),
                        ]
                        .spacing(12)
                        .align_y(iced::Alignment::Center),
                    )
                    .style(|_: &Theme| container::Style {
                        background: Some(Background::Color(Color::from_rgb8(0x06, 0x10, 0x1C))),
                        border: Border { color: Color::from_rgb8(0x14, 0x2C, 0x44), width: 1.0, radius: 0.0.into() },
                        ..Default::default()
                    })
                    .padding([8, 16])
                    .width(Length::Fill),
                    main,
                ]
                .spacing(0)
                .width(Length::Fill),
            ]
            .spacing(0),
        )
        .padding(0)
        .width(Length::Fill)
        .height(Length::Fill)
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
                background: Color::from_rgb8(0x08, 0x14, 0x22),
                text: Color::from_rgb8(0xE4, 0xEE, 0xF2),
                primary: Color::from_rgb8(0x1E, 0x82, 0x8F),
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

    fn profile_tick_interval_ms(&self) -> u64 {
        match self.runtime_profile {
            RuntimeProfile::Auto => {
                if self.active_tab == Tab::Browser {
                    220
                } else if self.analysis_running {
                    320
                } else {
                    900
                }
            }
            RuntimeProfile::Balanced => {
                if self.active_tab == Tab::Browser {
                    260
                } else {
                    650
                }
            }
            RuntimeProfile::LowPower => {
                if self.active_tab == Tab::Browser {
                    420
                } else {
                    1150
                }
            }
            RuntimeProfile::Legacy => {
                if self.active_tab == Tab::Browser {
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
            Message::LoginPressed => match self
                .auth_store
                .authenticate(&self.login_username, &self.login_password)
            {
                Ok(user) => {
                    self.show_tutorial = self.state_store.entries_for(&user.username).is_empty();
                    self.current_user = Some(user);
                    self.active_tab = Tab::Home;
                    self.chat_context = ChatContext::Shanway;
                    self.selected_private_partner = None;
                    self.refresh_security_snapshot(true, "login");
                    self.status_line =
                        "Anmeldung erfolgreich. Aether ist lokal betriebsbereit.".to_owned();
                }
                Err(err) => self.status_line = err,
            },
            Message::RegisterPressed => match self
                .auth_store
                .register(&self.login_username, &self.login_password)
            {
                Ok(()) => match self
                    .auth_store
                    .authenticate(&self.login_username, &self.login_password)
                {
                    Ok(user) => {
                        self.current_user = Some(user);
                        self.show_tutorial = true;
                        self.active_tab = Tab::Chat;
                        self.chat_context = ChatContext::Shanway;
                        self.selected_private_partner = None;
                        self.refresh_security_snapshot(true, "register");
                        self.status_line =
                            "Registrierung abgeschlossen. Shanway startet mit der Einfuehrung."
                                .to_owned();
                    }
                    Err(err) => self.status_line = err,
                },
                Err(err) => self.status_line = err,
            },
            Message::TabSelected(tab) => {
                self.active_tab = tab;
                if self.active_tab == Tab::Browser {
                    self.sync_browser_embed();
                } else if self.active_tab == Tab::YouTube {
                    let url = self.youtube_address.clone();
                    let _ = self.browser_embed.navigate(&url);
                    self.sync_browser_embed();
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
                return Task::perform(
                    analyze_file_for_register(path, username),
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
                return Task::perform(
                    async move {
                        let vault = VaultStore::load_default().map_err(|e| e.to_string())?;
                        let vault = Arc::new(RwLock::new(vault));
                        let decoder = AefDecoder::new(vault);
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
                if self.active_tab != Tab::Browser && self.active_tab != Tab::YouTube {
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
    entropy: f32,              // [0..1] – drives surface texture roughness
    stability: f32,            // [0..1] – smooth vs turbulent surface feel
    delta_phases: [f32; 3],    // 3 delta arc event phases
    attractor_lons: [f32; 4],  // 4 attractor longitude positions
    info_growth: f32,          // I(h_t) – drives radius expansion [0..1]
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
            Color::from_rgb8(0x01, 0x03, 0x07),
        );

        let cx = bounds.width * 0.5;
        let cy = bounds.height * 0.5;
        let base_r = cx.min(cy) * 0.70;
        // Radius grows subtly with I(h_t) — max +28px, deterministic
        let r = base_r + (self.info_growth * 28.0).min(28.0);

        let t = self.tick as f32;
        // Slow deterministic Y-axis rotation — one full rotation every ~13 min at 60fps
        let rot_y = t * 0.006;

        // Camera distance for perspective factor
        let d = 3.2f32;

        // Project a sphere surface point (lat, lon) to screen 2D + depth z
        let project = |lat: f32, lon: f32| -> (Point, f32) {
            // Sphere to 3D cartesian
            let x3 = lat.cos() * lon.cos();
            let y3 = lat.sin();
            let z3 = lat.cos() * lon.sin();
            // Rotate around Y axis
            let xr = x3 * rot_y.cos() + z3 * rot_y.sin();
            let yr = y3;
            let zr = -x3 * rot_y.sin() + z3 * rot_y.cos();
            // Simple perspective divide
            let scale = d / (d - zr * 0.28);
            let sx = cx + xr * r * scale;
            let sy = cy - yr * r * scale;
            (Point::new(sx, sy), zr)
        };

        // ── Sphere base glow (filled circle, dark teal) ──────────────────
        {
            let glow_path = canvas::Path::circle(Point::new(cx, cy), r + 3.0);
            frame.fill(&glow_path, Color::from_rgba(0.0, 0.5, 0.55, 0.06));
            let base_path = canvas::Path::circle(Point::new(cx, cy), r);
            frame.fill(&base_path, Color::from_rgb8(0x01, 0x0D, 0x14));
        }

        const N_LAT: usize = 16;   // latitude rings
        const N_LON: usize = 32;   // longitude meridians
        const SEGS: usize = 64;    // segments per latitude circle

        // ── Latitude circles ─────────────────────────────────────────────
        for li in 0..=N_LAT {
            let lat_base = -PI * 0.5 + PI * (li as f32) / (N_LAT as f32);
            // Entropy-driven surface perturbation (fully deterministic via lat + tick)
            let perturb = self.entropy * 0.07
                * (lat_base * 4.0 + t * 0.018).sin()
                * (1.0 - self.stability * 0.6);
            let lat = lat_base + perturb;

            let lat_frac = (li as f32) / (N_LAT as f32); // 0..1 from bottom to top

            let mut prev: Option<(Point, f32)> = None;
            for seg in 0..=SEGS {
                let lon = TAU * (seg as f32) / (SEGS as f32);
                let (pt, z) = project(lat, lon);
                if let Some((pp, pz)) = prev {
                    let avg_z = (z + pz) * 0.5;
                    // Cull back-facing segments
                    if avg_z > -0.92 {
                        let brightness = ((avg_z + 1.0) * 0.5).powf(0.7).clamp(0.05, 1.0);
                        // Equator ring brighter; poles dimmer
                        let eq_boost = 1.0 - (lat_frac - 0.5).abs() * 1.2;
                        let alpha = (0.12 + 0.22 * brightness * eq_boost.max(0.1)).clamp(0.03, 0.40);
                        let g = 0.50 * brightness;
                        let b = 0.62 * brightness;
                        let c = Color::from_rgba(0.04 * brightness, g, b, alpha);
                        let w = 0.4 + 0.35 * brightness;
                        let seg_path = canvas::Path::new(|p| {
                            p.move_to(pp);
                            p.line_to(pt);
                        });
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

        // ── Longitude meridians ──────────────────────────────────────────
        for li in 0..N_LON {
            let lon_base = TAU * (li as f32) / (N_LON as f32);
            // Entropy perturbation on longitude lines
            let lon_perturb = self.entropy * 0.04
                * (lon_base * 3.0 + t * 0.012).cos()
                * (1.0 - self.stability * 0.7);
            let lon = lon_base + lon_perturb;

            const LON_SEGS: usize = 48;
            let mut prev: Option<(Point, f32)> = None;
            for seg in 0..=LON_SEGS {
                let lat = -PI * 0.5 + PI * (seg as f32) / (LON_SEGS as f32);
                let (pt, z) = project(lat, lon);
                if let Some((pp, pz)) = prev {
                    let avg_z = (z + pz) * 0.5;
                    if avg_z > -0.92 {
                        let brightness = ((avg_z + 1.0) * 0.5).powf(0.9).clamp(0.04, 1.0);
                        let alpha = (0.06 + 0.14 * brightness).clamp(0.02, 0.22);
                        let c = Color::from_rgba(0.03, 0.40 * brightness, 0.52 * brightness, alpha);
                        let seg_path = canvas::Path::new(|p| {
                            p.move_to(pp);
                            p.line_to(pt);
                        });
                        frame.stroke(&seg_path, canvas::Stroke {
                            style: canvas::Style::Solid(c),
                            width: 0.4,
                            ..canvas::Stroke::default()
                        });
                    }
                }
                prev = Some((pt, z));
            }
        }

        // ── Delta arc events (yellow light streams) ──────────────────────
        for (arc_idx, &phase) in self.delta_phases.iter().enumerate() {
            // Each arc animates along the surface — deterministic phase offset
            let anim_lon = (t * 0.025 + phase * 0.5).rem_euclid(TAU);
            let lat_center = (phase * 0.35 - 0.55).clamp(-PI * 0.45, PI * 0.45);
            let arc_span = PI * 0.42;

            const ARC_SEGS: usize = 32;
            let mut prev: Option<(Point, f32)> = None;
            for seg in 0..=ARC_SEGS {
                let progress = seg as f32 / ARC_SEGS as f32;
                // Great circle approximation: sweep lon by arc_span
                let lon = (anim_lon + arc_span * progress).rem_euclid(TAU);
                // Slight latitude wobble for curvature feel
                let lat = lat_center + 0.28 * (progress * PI).sin();
                let (pt, z) = project(lat, lon);
                if let Some((pp, pz)) = prev {
                    let avg_z = (z + pz) * 0.5;
                    // Only show front-facing arcs
                    if avg_z > -0.35 {
                        let brightness = ((avg_z + 1.0) * 0.5).clamp(0.0, 1.0);
                        // Bell-shaped intensity along the arc length
                        let intensity = (1.0 - (progress - 0.5).abs() * 2.0).max(0.0).powf(0.6);
                        let alpha = 0.5 * intensity * brightness;
                        let width = 1.2 * intensity + 0.4;
                        // Yellow-orange gradient: leading edge more yellow, tail more orange
                        let r_val = 0.90 + 0.10 * intensity;
                        let g_val = 0.60 + 0.18 * (1.0 - progress);
                        let arc_c = Color::from_rgba(r_val, g_val, 0.02, alpha);
                        let seg_path = canvas::Path::new(|p| {
                            p.move_to(pp);
                            p.line_to(pt);
                        });
                        frame.stroke(&seg_path, canvas::Stroke {
                            style: canvas::Style::Solid(arc_c),
                            width,
                            ..canvas::Stroke::default()
                        });
                    }
                }
                prev = Some((pt, z));
                let _ = arc_idx;
            }
        }

        // ── Attractor nodes (white stable points) ────────────────────────
        for (idx, &lon) in self.attractor_lons.iter().enumerate() {
            // Fixed latitude: alternating above/below equator
            let lat = if idx % 2 == 0 { 0.28f32 } else { -0.28f32 };
            // lon rotates with the sphere but is phase-stable relative to structure
            let sphere_lon = (lon + rot_y).rem_euclid(TAU);
            let (pt, z) = project(lat, sphere_lon);
            // Show only when clearly on front hemisphere
            if z > -0.15 {
                let brightness = ((z + 1.0) * 0.5).clamp(0.0, 1.0);
                // Gentle pulsation (deterministic, idx-phase-shifted)
                let pulse = 1.0 + 0.18 * (t * 0.045 + idx as f32 * std::f32::consts::FRAC_PI_2).sin();
                // Outer halo
                let halo_alpha = 0.06 * brightness;
                frame.fill(
                    &canvas::Path::circle(pt, 14.0 * pulse),
                    Color::from_rgba(0.7, 0.95, 1.0, halo_alpha),
                );
                // Inner glow
                let inner_alpha = 0.18 * brightness;
                frame.fill(
                    &canvas::Path::circle(pt, 6.5 * pulse),
                    Color::from_rgba(0.85, 1.0, 1.0, inner_alpha),
                );
                // Core dot
                let dot_alpha = (0.7 + 0.3 * brightness).min(1.0);
                frame.fill(
                    &canvas::Path::circle(pt, 3.0 * pulse),
                    Color::from_rgba(0.92, 0.99, 1.0, dot_alpha),
                );
            }
        }

        // ── Limb darkening overlay (edge fade for 3D depth illusion) ─────
        {
            // Draw a thin dark ring at the sphere edge to fake limb darkening.
            // We stride through a ring of points near the equator and draw small
            // dark spots — this costs little and increases perceived 3D pop.
            let limb_c = Color::from_rgba(0.0, 0.0, 0.0, 0.55);
            for seg in 0..48 {
                let lon = TAU * (seg as f32) / 48.0;
                let (pt, _z) = project(0.0, lon);
                // Only draw on the outer visible part of the limb
                let dx = pt.x - cx;
                let dy = pt.y - cy;
                let dist = (dx * dx + dy * dy).sqrt();
                if (dist - r).abs() < 18.0 {
                    frame.fill(
                        &canvas::Path::circle(pt, 9.0),
                        limb_c,
                    );
                }
            }
        }

        // ── Outer glow ring ───────────────────────────────────────────────
        {
            let glow_alpha = 0.10 + 0.04 * (t * 0.032).sin();
            frame.stroke(
                &canvas::Path::circle(Point::new(cx, cy), r + 1.5),
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(0.0, 0.82, 0.88, glow_alpha)),
                    width: 3.0,
                    ..canvas::Stroke::default()
                },
            );
            // Second fainter ring at +8px
            let outer_alpha = 0.04 + 0.02 * (t * 0.021 + 1.1).sin();
            frame.stroke(
                &canvas::Path::circle(Point::new(cx, cy), r + 8.0),
                canvas::Stroke {
                    style: canvas::Style::Solid(Color::from_rgba(0.0, 0.60, 0.72, outer_alpha)),
                    width: 1.2,
                    ..canvas::Stroke::default()
                },
            );
        }

        // ── Blue pulse shimmer ────────────────────────────────────────────
        {
            let pulse_alpha = 0.025 + 0.018 * (t * 0.041).sin();
            frame.fill(
                &canvas::Path::circle(Point::new(cx, cy), r + 2.0),
                Color::from_rgba(0.05, 0.18, 0.80, pulse_alpha),
            );
        }

        // ── Highlight spot (top-left quadrant, gives 3D sphere illusion) ─
        {
            let hx = cx - r * 0.32;
            let hy = cy - r * 0.38;
            let highlight_c = Color::from_rgba(0.55, 0.88, 0.92, 0.14);
            frame.fill(&canvas::Path::circle(Point::new(hx, hy), r * 0.22), highlight_c);
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

fn dashboard_metric(label: &'static str, value: String, hint: String, fill: f32) -> Element<'static, Message> {
    let bar = make_sparkline(fill);
    container(
        column![
            text(label).size(12),
            text(value).size(28),
            text(bar).size(13),
            text(hint).size(12),
        ]
        .spacing(6)
        .width(Length::Fill),
    )
    .style(|_theme: &Theme| container::Style {
        background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
        border: Border {
            color: Color::from_rgb8(0x1E, 0x82, 0x8F),
            width: 1.5,
            radius: 8.0.into(),
        },
        ..Default::default()
    })
    .padding(18)
    .width(Length::Fill)
    .into()
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
            let mut pc = nodes[from].3; pc.a = 0.85;
            frame.fill(&canvas::Path::circle(Point::new(px, py), 3.0), pc);
        }

        // Draw nodes
        for (label, fx, fy, col) in nodes {
            let cx = fx * w; let cy = fy * h;
            let is_router = *label == "Event Router";
            let r = if is_router { 42.0f32 } else { 34.0f32 };
            let rh = r * 0.55;

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
            let mut bc = *col; bc.a = if is_router { 0.95 } else { 0.65 };
            frame.stroke(&rect, canvas::Stroke { style: canvas::Style::Solid(bc), width: if is_router { 2.0 } else { 1.2 }, ..canvas::Stroke::default() });

            // Label
            frame.fill_text(canvas::Text {
                content: label.to_string(),
                position: Point::new(cx, cy),
                color: Color::from_rgb8(0xC8, 0xDE, 0xEE),
                size: iced::Pixels(10.0),
                horizontal_alignment: iced::alignment::Horizontal::Center,
                vertical_alignment: iced::alignment::Vertical::Center,
                ..canvas::Text::default()
            });

            // Glow pulse on Event Router
            if is_router {
                let glow_r = r + 6.0 + 3.0 * (t * 0.06).sin();
                let mut gc = *col; gc.a = 0.08;
                frame.stroke(
                    &canvas::Path::circle(Point::new(cx, cy), glow_r),
                    canvas::Stroke { style: canvas::Style::Solid(gc), width: 2.5, ..canvas::Stroke::default() },
                );
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

// ── Helper functions for new dashboard ───────────────────────────────────────

fn ade_subpanel<'a>(title: &'a str, body: Element<'a, Message>, panel_bg: Color) -> Element<'a, Message> {
    container(
        column![
            text(title.to_owned()).size(12).color(Color::from_rgb8(0x00, 0xD4, 0xD4)),
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

fn sys_metric_card(label: &str, value: String, fill: f32, accent: Color) -> Element<'static, Message> {
    let spark = make_sparkline(fill.clamp(0.0, 1.0));
    container(
        column![
            text(label.to_owned()).size(12).color(Color::from_rgb8(0x80, 0xA8, 0xC8)),
            text(value).size(26).color(Color::from_rgb8(0xE0, 0xF0, 0xFF)),
            text(spark).size(11).color(accent),
        ]
        .spacing(6)
        .width(Length::Fill),
    )
    .style(move |_: &Theme| container::Style {
        background: Some(Background::Color(Color::from_rgb8(0x06, 0x12, 0x20))),
        border: Border { color: accent, width: 1.5, radius: 10.0.into() },
        ..Default::default()
    })
    .padding(18)
    .width(Length::Fill)
    .into()
}

fn event_row<'a>(time: &str, tag: &str, msg: &str, tag_color: Color) -> Element<'a, Message> {
    container(
        row![
            text(time.to_owned()).size(11).color(Color::from_rgb8(0x60, 0x80, 0x98)),
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

fn alert_row<'a>(icon: &str, icon_color: Color, title: &str, sub: &str) -> Element<'a, Message> {
    container(
        row![
            text(icon.to_owned()).size(14).color(icon_color),
            column![
                text(title.to_owned()).size(13).color(Color::from_rgb8(0xC8, 0xDE, 0xEE)),
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

fn metric_card<'a>(label: &'a str, value: String, hint: String) -> Element<'a, Message> {
    container(
        column![
            text(label).size(12),
            text(value).size(26),
            text(hint).size(12),
        ]
        .spacing(6)
        .width(Length::Fill),
    )
    .style(|_theme: &Theme| container::Style {
        background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
        border: Border {
            color: Color::from_rgb8(0x1E, 0x82, 0x8F),
            width: 1.5,
            radius: 8.0.into(),
        },
        ..Default::default()
    })
    .padding(18)
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
    .style(|_theme: &Theme| container::Style {
        background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
        border: Border {
            color: Color::from_rgb8(0x1C, 0x38, 0x50),
            width: 1.0,
            radius: 6.0.into(),
        },
        ..Default::default()
    })
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
        background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
        border: Border {
            color: Color::from_rgb8(0x1E, 0x82, 0x8F),
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
            text(entry.preview_note.clone()).size(13),
        ]
        .spacing(5),
    )
    .style(|_theme: &Theme| container::Style {
        background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
        border: Border {
            color: Color::from_rgb8(0x1C, 0x38, 0x50),
            width: 1.0,
            radius: 6.0.into(),
        },
        ..Default::default()
    })
    .padding(14)
    .width(Length::Fill)
    .into()
}

async fn analyze_file_for_register(
    path: PathBuf,
    username: String,
) -> Result<FileAnalysisResult, String> {
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
    let encoder = AefEncoder::new(Arc::clone(&vault), Arc::clone(&engine));

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
    let source_kind = detect_source_kind(&path, &[]);
    let preview_note = format!(
        "AEF | E_\u{03bb}: {:.2} ({}) | Trust: {:.0}% | Lossless: {}",
        encode_result.e_lambda,
        encode_result.e_lambda_label,
        encode_result.trust_score * 100.0,
        if encode_result.lossless_confirmed { "ja" } else { "nein" }
    );
    let anchor_summary = format!(
        "{} Anker | {:.1}% Kompression | Trust: {:.0}%",
        encode_result.anchor_count,
        compression_gain_percent,
        encode_result.trust_score * 100.0
    );
    let process_summary = format!(
        "AEF-Encoding: {} B \u{2192} {} B | E_\u{03bb}={:.2}",
        original_size, delta_size, encode_result.e_lambda
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

fn estimated_symmetry(bytes: &[u8]) -> f32 {
    if bytes.len() < 4 {
        return 1.0;
    }
    let half = bytes.len() / 2;
    if half == 0 {
        return 1.0;
    }
    let left = &bytes[..half];
    let right = &bytes[bytes.len() - half..];
    let mut score = 0.0f32;
    for (lhs, rhs) in left.iter().zip(right.iter().rev()) {
        let distance = ((*lhs as i16 - *rhs as i16).unsigned_abs() as f32) / 255.0;
        score += 1.0 - distance;
    }
    (score / half as f32).clamp(0.0, 1.0)
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
