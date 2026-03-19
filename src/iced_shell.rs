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
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Home,
    Chat,
    Browser,
    Data,
    Settings,
    Logs,
    Anchors,
    Imprint,
    StructureMap,
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
    FileHovered(PathBuf),
    FileHoverCleared,
    FileDropped(PathBuf),
    FileAnalysisCompleted(Result<FileAnalysisResult, String>),
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
    // --- StructureMap ---
    structure_map_nodes: Vec<Vec<f32>>,
    structure_map_compression: f32,
    structure_map_locked: bool,
    structure_map_anchor_hist: Vec<f32>,
    structure_map_mutation_hist: Vec<u32>,
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
        if self.active_tab != Tab::Browser {
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
        let node_prefix = self
            .security_snapshot
            .node_id
            .chars()
            .take(12)
            .collect::<String>();
        let trust_dot = if self.security_snapshot.trust_state.to_uppercase().contains("HIGH")
            || self.security_snapshot.trust_state.to_uppercase().contains("OK")
            || self.security_snapshot.trust_state.to_uppercase().contains("SECURE")
        {
            "\u{25cf} "
        } else if self.security_snapshot.trust_state.to_uppercase().contains("WARN") {
            "\u{25d0} "
        } else {
            "\u{25cb} "
        };
        let entries_count = self
            .current_username()
            .map(|u| self.state_store.entries_for(&u).len())
            .unwrap_or(0);
        container(
            column![
                container(
                    column![
                        text("\u{2b21}").size(34),
                        text("AETHER").size(17),
                        text("Petrol Shell").size(11),
                    ]
                    .spacing(2)
                    .align_x(Alignment::Center),
                )
                .style(|_theme: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x06, 0x11, 0x1E))),
                    border: Border {
                        color: Color::from_rgb8(0x1E, 0x82, 0x8F),
                        width: 1.5,
                        radius: 8.0.into(),
                    },
                    ..Default::default()
                })
                .padding([12, 14])
                .width(Length::Fill),

                text("\u{2014} IDENTITY \u{2014}").size(10),
                container(
                    column![
                        text(format!("  \u{25b8} {}", username)).size(14),
                        text(format!("  Node {}", node_prefix)).size(11),
                    ]
                    .spacing(3),
                )
                .style(|_theme: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x24))),
                    border: Border {
                        color: Color::from_rgb8(0x1C, 0x38, 0x50),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                })
                .padding([10, 12])
                .width(Length::Fill),

                text("\u{2014} STATUS \u{2014}").size(10),
                container(
                    column![
                        text(format!("{}{}", trust_dot, self.security_snapshot.trust_state)).size(13),
                        text(format!("  Mode: {}", self.security_snapshot.mode)).size(11),
                        text(format!("  Maze: {}", self.security_snapshot.maze_state)).size(11),
                    ]
                    .spacing(4),
                )
                .style(|_theme: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x24))),
                    border: Border {
                        color: Color::from_rgb8(0x1C, 0x38, 0x50),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                })
                .padding([10, 12])
                .width(Length::Fill),

                text("\u{2014} SYSTEM \u{2014}").size(10),
                container(
                    column![
                        text(format!("  \u{25a4} Artefakte: {}", entries_count)).size(13),
                        text(format!("  \u{25b6} Analyse: {:.0}%", self.analysis_progress * 100.0)).size(13),
                        text(format!("  \u{2699} Profil: {}", self.runtime_profile_label())).size(12),
                        text(if self.analysis_running { "  \u{25b6} AKTIV" } else { "  \u{25a0} BEREIT" }).size(12),
                    ]
                    .spacing(4),
                )
                .style(|_theme: &Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x24))),
                    border: Border {
                        color: Color::from_rgb8(0x1C, 0x38, 0x50),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                })
                .padding([10, 12])
                .width(Length::Fill),
            ]
            .spacing(8)
            .height(Length::Fill),
        )
        .style(|_theme: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x07, 0x10, 0x1A))),
            border: Border {
                color: Color::from_rgb8(0x1E, 0x40, 0x5F),
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .padding(12)
        .width(Length::Fixed(195.0))
        .height(Length::Fill)
        .into()
    }

    fn view_tabs(&self) -> Element<'_, Message> {
        container(
            row![
                self.tab_button(Tab::Home,     "\u{25c9}",  "Overview"),
                self.tab_button(Tab::Chat,     "\u{25c8}",  "Chat"),
                self.tab_button(Tab::Browser,  "\u{2295}",  "Browser"),
                self.tab_button(Tab::Data,     "\u{25a4}",  "Data"),
                self.tab_button(Tab::Settings, "\u{2699}",  "Config"),
                self.tab_button(Tab::Logs,     "\u{25a3}",  "Logs"),
                self.tab_button(Tab::Anchors,      "\u{25c6}",  "Cluster"),
                self.tab_button(Tab::StructureMap, "\u{29bf}",  "StrMap"),
                self.tab_button(Tab::Imprint,      "\u{2139}",  "Info"),
            ]
            .spacing(6),
        )
        .style(|_theme: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x07, 0x10, 0x1A))),
            border: Border {
                color: Color::from_rgb8(0x1C, 0x38, 0x50),
                width: 1.0,
                radius: 10.0.into(),
            },
            ..Default::default()
        })
        .padding([6, 8])
        .into()
    }

    fn view_home(&self) -> Element<'_, Message> {
        let entries = self.entries();
        let total_bytes: u64 = entries.iter().map(|entry| entry.original_size).sum();
        let latest_log = self
            .security_audit_events
            .first()
            .map(|item| item.summary.clone())
            .unwrap_or_else(|| "Keine Audit-Ereignisse.".to_owned());
        let latest_analysis_hint = self
            .last_analysis
            .as_ref()
            .map(|analysis| {
                format!(
                    "{} | {:.2}% Gewinn | {} B -> {} B\n{}\n{}",
                    analysis.file_name,
                    analysis.compression_gain_percent,
                    analysis.original_size,
                    analysis.delta_size,
                    analysis.anchor_summary,
                    analysis.process_summary
                )
            })
            .unwrap_or_else(|| "Noch keine Artefaktanalyse abgeschlossen.".to_owned());
        let analysis_value = if self.analysis_running {
            format!("{:.0}%", self.analysis_progress * 100.0)
        } else if let Some(a) = &self.last_analysis {
            format!("{:.2}% Gain", a.compression_gain_percent)
        } else {
            "Bereit".to_owned()
        };
        let cluster_count = self.anchor_clusters().len();
        let cluster_fill = (cluster_count.min(10) as f32) / 10.0_f32;
        let entry_fill = (entries.len().min(20) as f32) / 20.0_f32;
        container(
            scrollable(
                column![
                    // --- Row 1: 4 Metric Dashboard Cards ---
                    row![
                        dashboard_metric(
                            "\u{25ce} STATUS",
                            self.security_snapshot.trust_state.clone(),
                            self.security_snapshot.summary.clone(),
                            1.0,
                        ),
                        dashboard_metric(
                            "\u{25a4} ARTEFAKTE",
                            entries.len().to_string(),
                            format!("{} B lokal", total_bytes),
                            entry_fill,
                        ),
                        dashboard_metric(
                            "\u{25b6} ANALYSE",
                            analysis_value,
                            self.analysis_status.clone(),
                            self.analysis_progress,
                        ),
                        dashboard_metric(
                            "\u{25c6} CLUSTER",
                            cluster_count.to_string(),
                            "Datengetrieben".to_owned(),
                            cluster_fill,
                        ),
                    ]
                    .spacing(12),

                    // --- Orchestration Flow Map ---
                    orchestration_map_card(),

                    // --- Analysis + Events split ---
                    row![
                        container(
                            column![
                                text("\u{25b6} ANALYSEFLUSS").size(16),
                                progress_bar(0.0..=1.0, self.analysis_progress.clamp(0.0, 1.0)),
                                text(make_sparkline(self.analysis_progress)).size(13),
                                text(self.analysis_status.clone()).size(14),
                                text(self.hovered_file_label.clone()).size(13),
                                text(latest_analysis_hint.clone()).size(13),
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
                        .width(Length::FillPortion(2)),

                        container(
                            column![
                                text("\u{25ce} RECENT EVENTS").size(16),
                                text(latest_log.clone()).size(13),
                                text("").size(4),
                                text("\u{2014} SYSTEMSTATUS \u{2014}").size(12),
                                text(format!("Mode: {}", self.security_snapshot.mode)).size(13),
                                text(format!("Maze: {}", self.security_snapshot.maze_state)).size(13),
                            ]
                            .spacing(6)
                            .width(Length::Fill),
                        )
                        .style(|_theme: &Theme| container::Style {
                            background: Some(Background::Color(Color::from_rgb8(0x08, 0x18, 0x28))),
                            border: Border {
                                color: Color::from_rgb8(0x1C, 0x38, 0x50),
                                width: 1.5,
                                radius: 8.0.into(),
                            },
                            ..Default::default()
                        })
                        .padding(18)
                        .width(Length::FillPortion(1)),
                    ]
                    .spacing(12),
                ]
                .spacing(14),
            )
            .height(Length::Fill),
        )
        .padding(12)
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

    fn view_structure_map(&self) -> Element<'_, Message> {
        let accent = Color::from_rgb8(0x1E, 0x90, 0xFF);
        let dim    = Color::from_rgb8(0xA7, 0xB0, 0xB7);
        let surf   = Color::from_rgb8(0x07, 0x10, 0x1A);

        let comp_pct = self.structure_map_compression;
        let comp_label = if self.structure_map_locked {
            format!("{:.0}%  \u{25cf} LOCKED", comp_pct)
        } else {
            format!("{:.0}%", comp_pct)
        };

        let anchor_spark: String = {
            let h = &self.structure_map_anchor_hist;
            let max = h.iter().cloned().fold(0.1f32, f32::max);
            h.iter().map(|&v| {
                let p = (v / max).clamp(0.0, 1.0);
                if p > 0.75 { '\u{2588}' } else if p > 0.50 { '\u{2593}' }
                else if p > 0.25 { '\u{2592}' } else { '\u{2591}' }
            }).collect()
        };
        let mut_spark: String = self.structure_map_mutation_hist.iter().map(|&v| {
            if v >= 12 { '\u{2588}' } else if v >= 8 { '\u{2593}' }
            else if v >= 4 { '\u{2592}' } else { '\u{2591}' }
        }).collect();

        let overlay = container(
            scrollable(
                column![
                    text("\u{25c8} DOM\u{c4}NEN").size(11).color(accent),
                    text("\u{25c6} KLIMA").size(10)
                        .color(Color::from_rgb8(0x1E, 0x90, 0xFF)),
                    text("\u{25c6} WASSER").size(10)
                        .color(Color::from_rgb8(0x00, 0xCF, 0xFF)),
                    text("\u{25c6} GESUNDHEIT").size(10)
                        .color(Color::from_rgb8(0x9B, 0x59, 0xB6)),
                    text("\u{25c6} BODEN").size(10)
                        .color(Color::from_rgb8(0x7F, 0xFF, 0x00)),
                    text("\u{25c6} LUFT").size(10)
                        .color(Color::from_rgb8(0xFF, 0xD7, 0x00)),
                    text("\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}").size(8).color(dim),
                    text("\u{25c8} ANKER-DICHTE").size(10).color(accent),
                    text(anchor_spark.clone()).size(10)
                        .color(Color::from_rgb8(0x9B, 0xD4, 0xFF)),
                    text("\u{25c8} MUTATION Ring 5").size(10)
                        .color(Color::from_rgb8(0x7F, 0xFF, 0x00)),
                    text(mut_spark.clone()).size(10)
                        .color(Color::from_rgb8(0xFF, 0xA5, 0x00)),
                    text("\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}").size(8).color(dim),
                    text("\u{25c8} KOMPRESSION").size(10)
                        .color(Color::from_rgb8(0xE0, 0xF7, 0xFF)),
                    text(comp_label.clone()).size(22),
                    progress_bar(0.0..=100.0, comp_pct).height(8),
                    text("\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}").size(8).color(dim),
                    text("Ring 1  Rohdaten").size(9)
                        .color(Color::from_rgb8(0xFF, 0x44, 0x44)),
                    text("Ring 2\u{2013}6  Verarbeit.").size(9)
                        .color(Color::from_rgb8(0x7F, 0xFF, 0x00)),
                    text("Ring 7  Ockham-Cut").size(9).color(Color::WHITE),
                    text("Ring 8\u{2013}9  Kompr.").size(9)
                        .color(Color::from_rgb8(0x9B, 0xD4, 0xFF)),
                    text("Ring 10  Anker \u{25c6}").size(9)
                        .color(Color::from_rgb8(0xE0, 0xF7, 0xFF)),
                ]
                .spacing(5)
                .padding(10),
            )
            .height(Length::Fill),
        )
        .width(Length::Fixed(195.0))
        .height(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(surf)),
            border: Border {
                color: Color::from_rgb8(0x1C, 0x38, 0x50),
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        });

        let scene = StructureMapScene {
            nodes: self.structure_map_nodes.clone(),
        };

        let tree_canvas = canvas::Canvas::new(scene)
            .width(Length::Fill)
            .height(Length::Fill);

        container(
            column![
                row![
                    text("AETHER \u{00b7} STRUCTUREMAP")
                        .size(13)
                        .color(accent),
                    text("  \u{25e6}  Ockham-Kollaps  \u{25e6}  Mutationspfade  \u{25e6}  Kompressionszonen  \u{25e6}  Reine Diagnose")
                        .size(10)
                        .color(dim),
                ]
                .spacing(0),
                row![
                    tree_canvas,
                    overlay,
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
        .into()
    }

    fn view_shell(&self) -> Element<'_, Message> {
        let main = match self.active_tab {
            Tab::Home => self.view_home(),
            Tab::Chat => self.view_chat(),
            Tab::Browser => self.view_browser(),
            Tab::Data => self.view_data(),
            Tab::Settings => self.view_settings(),
            Tab::Logs => self.view_logs(),
            Tab::Anchors => self.view_anchors(),
            Tab::StructureMap => self.view_structure_map(),
            Tab::Imprint => self.view_imprint(),
        };
        container(
            row![
                self.view_sidebar(),
                column![self.view_tabs(), text(&self.status_line).size(15), main]
                    .spacing(12)
                    .width(Length::Fill),
            ]
            .spacing(18),
        )
        .padding(18)
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
                                "Cluster-Zuordnung abgeschlossen. {} | {:.2}% Gewinn",
                                result.snapshot.file_name, result.snapshot.compression_gain_percent
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
            Message::WindowResized(width, height) => {
                self.window_width = width;
                self.window_height = height;
                if self.active_tab == Tab::Browser {
                    self.sync_browser_embed();
                }
            }
            Message::Tick => {
                self.tick_counter = self.tick_counter.wrapping_add(1);
                if self.active_tab == Tab::StructureMap {
                    self.step_structure_map();
                    return Task::none();
                }
                if self.active_tab != Tab::Browser {
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
// Aether.StructureMap – Canvas-Renderer für den fraktalen 3D-Suchbaum
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

fn orchestration_map_card() -> Element<'static, Message> {
    container(
        column![
            text("◎ ORCHESTRIERUNG — Aether Datenfluss").size(16),
            container(
                column![
                    text("  [DROP] ──▶ [STRUKTURANALYSE] ──▶ [MERKMALSPROFIL]").size(14),
                    text("                                          │").size(14),
                    text("                                  [ANCHOR-SIGNALE]").size(14),
                    text("                                          │").size(14),
                    text("                         [CLUSTER-ZUORDNUNG] ──▶ [SPEICHER]").size(14),
                ]
                .spacing(2),
            )
            .style(|_theme: &Theme| container::Style {
                background: Some(Background::Color(Color::from_rgb8(0x04, 0x0E, 0x18))),
                border: Border {
                    color: Color::from_rgb8(0x1C, 0x5A, 0x68),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            })
            .padding([12, 16]),
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
    let bytes =
        fs::read(&path).map_err(|err| format!("Datei konnte nicht gelesen werden: {err}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|err| format!("Metadaten konnten nicht gelesen werden: {err}"))?;
    let original_size = metadata.len();
    let delta_size = estimate_compressed_size(&bytes)?;
    let ratio = if original_size == 0 {
        0.0
    } else {
        delta_size as f32 / original_size as f32
    };
    let compression_gain_percent = ((1.0 - ratio).clamp(0.0, 1.0) * 10000.0).round() / 100.0;
    let entropy = shannon_entropy(&bytes);
    let drift = byte_drift(&bytes);
    let source_kind = detect_source_kind(&path, &bytes);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unbekannt")
        .to_owned();
    let symmetry = estimated_symmetry(&bytes);
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
    Ok(FileAnalysisResult {
        entry: RegisterEntry {
            id: 0,
            owner_username: username,
            file_name: file_name.clone(),
            full_path: path.to_string_lossy().to_string(),
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
