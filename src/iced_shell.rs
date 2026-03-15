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
use iced::widget::{button, column, container, progress_bar, row, scrollable, text, text_input};
use iced::{
    application, event, time, window, Alignment, Color, Element, Length, Settings, Subscription,
    Task, Theme,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatContext {
    Private,
    Group,
    Shanway,
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
        };
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

    fn tab_button(&self, tab: Tab, label: &'static str) -> Element<'_, Message> {
        let underline = if self.active_tab == tab {
            "____"
        } else {
            "    "
        };
        container(
            column![
                button(text(label).size(16))
                    .padding([8, 14])
                    .on_press(Message::TabSelected(tab)),
                text(underline).size(14),
            ]
            .spacing(2)
            .align_x(Alignment::Center),
        )
        .into()
    }

    fn context_button(&self, context: ChatContext, label: &'static str) -> Element<'_, Message> {
        let marker = if self.chat_context == context {
            "[aktiv]"
        } else {
            ""
        };
        button(text(format!("{label} {marker}")).size(15))
            .padding([8, 14])
            .on_press(Message::ChatContextSelected(context))
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
            .take(18)
            .collect::<String>();
        container(
            column![
                text("A").size(40),
                text("AETHER").size(20),
                text("Petrol Shell").size(15),
                text(format!("Nutzer: {}", username)).size(14),
                text(format!("Trust: {}", self.security_snapshot.trust_state)).size(14),
                text(format!("Mode: {}", self.security_snapshot.mode)).size(14),
                text(format!("Node: {}", node_prefix)).size(13),
                text(" ").size(20),
                text("SYS").size(14),
                text("PWR").size(14),
            ]
            .spacing(8)
            .height(Length::Fill),
        )
        .padding(22)
        .width(Length::Fixed(180.0))
        .height(Length::Fill)
        .into()
    }

    fn view_tabs(&self) -> Element<'_, Message> {
        row![
            self.tab_button(Tab::Home, "Home"),
            self.tab_button(Tab::Chat, "Chat"),
            self.tab_button(Tab::Browser, "Browser"),
            self.tab_button(Tab::Data, "Data"),
            self.tab_button(Tab::Settings, "Einstellungen"),
            self.tab_button(Tab::Logs, "Logs"),
            self.tab_button(Tab::Anchors, "Anker"),
            self.tab_button(Tab::Imprint, "Impressum"),
        ]
        .spacing(8)
        .into()
    }

    fn view_home(&self) -> Element<'_, Message> {
        let entries = self.entries();
        let total_bytes: u64 = entries.iter().map(|entry| entry.original_size).sum();
        let latest_log = self
            .security_audit_events
            .first()
            .map(|item| item.summary.clone())
            .unwrap_or_else(|| "Noch keine Audit-Ereignisse.".to_owned());
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
        container(
            scrollable(
                column![
                    row![
                        metric_card("Status", self.security_snapshot.trust_state.clone(), self.security_snapshot.summary.clone()),
                        metric_card("Artefakte", entries.len().to_string(), format!("{} B lokal organisiert", total_bytes)),
                        metric_card(
                            "Analyse",
                            if self.analysis_running {
                                format!("{:.0}%", self.analysis_progress * 100.0)
                            } else if let Some(analysis) = &self.last_analysis {
                                format!("{:.2}%", analysis.compression_gain_percent)
                            } else {
                                "0%".to_owned()
                            },
                            self.analysis_status.clone(),
                        ),
                    ]
                    .spacing(14),
                    info_card(
                        "Orchestrierung",
                        "Artefakt erkannt -> Strukturanalyse gestartet -> Merkmalsprofil erstellt -> Anchor-Signale generiert -> Cluster-Zuordnung abgeschlossen.",
                    ),
                    analysis_card(
                        self.analysis_progress,
                        &self.analysis_status,
                        &self.hovered_file_label,
                        &latest_analysis_hint,
                    ),
                    row![
                        info_card("Systemstatus", &format!("Mode: {}\nMaze: {}", self.security_snapshot.mode, self.security_snapshot.maze_state)),
                        info_card("Letzte Meldung", &latest_log),
                    ]
                    .spacing(14),
                ]
                .spacing(18),
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
            text("Logs").size(24),
            text("Lokale technische Meldungen fuer Audit und Security.").size(16),
        ]
        .spacing(14);
        if self.security_audit_events.is_empty() {
            items = items.push(info_card(
                "Noch keine Logs",
                "Nach Anmeldung oder Security-Recheck erscheinen hier Ereignisse.",
            ));
        } else {
            for event in &self.security_audit_events {
                items = items.push(info_card(
                    &format!("{} | {}", event.reason, event.trust_state),
                    &format!(
                        "{}\nMode: {} | Maze: {}",
                        event.summary, event.mode, event.maze_state
                    ),
                ));
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
            text("Anker").size(24),
            text("Kategorien entstehen datengetrieben aus Strukturmerkmalen und Metadaten.")
                .size(16),
        ]
        .spacing(12);
        for (index, cluster) in clusters.iter().enumerate() {
            list = list.push(
                button(
                    column![
                        text(cluster.title.clone()).size(18),
                        text(cluster.descriptor.clone()).size(14),
                        text(format!("{} Artefakte", cluster.item_count)).size(14),
                    ]
                    .spacing(4),
                )
                .padding([12, 14])
                .on_press(Message::AnchorGroupSelected(index)),
            );
        }
        container(
            row![
                container(scrollable(list).height(Length::Fill))
                    .padding(18)
                    .width(Length::FillPortion(1)),
                container(
                    column![
                        text(selected.title).size(24),
                        text(selected.descriptor).size(16),
                        text(format!("Groesse: {} B", selected.total_bytes)).size(16),
                        text(selected.sample_note).size(16),
                        button(text("Download optional anfragen")).padding([10, 18]),
                    ]
                    .spacing(10),
                )
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

    fn view_shell(&self) -> Element<'_, Message> {
        let main = match self.active_tab {
            Tab::Home => self.view_home(),
            Tab::Chat => self.view_chat(),
            Tab::Browser => self.view_browser(),
            Tab::Data => self.view_data(),
            Tab::Settings => self.view_settings(),
            Tab::Logs => self.view_logs(),
            Tab::Anchors => self.view_anchors(),
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
                if self.active_tab == Tab::Browser {
                    self.sync_browser_embed();
                } else {
                    self.browser_embed.hide();
                }
                for event in self.browser_embed.poll_events(8) {
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

fn app_subscription(_state: &AetherIcedShell) -> Subscription<Message> {
    Subscription::batch(vec![
        event::listen_with(app_event),
        time::every(Duration::from_millis(350)).map(|_| Message::Tick),
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

fn metric_card<'a>(label: &'a str, value: String, hint: String) -> Element<'a, Message> {
    container(
        column![
            text(label).size(14),
            text(value).size(24),
            text(hint).size(14)
        ]
        .spacing(6)
        .width(Length::Fill),
    )
    .padding(18)
    .width(Length::Fill)
    .into()
}

fn info_card<'a>(title: &str, body: &str) -> Element<'a, Message> {
    container(
        column![
            text(title.to_owned()).size(18),
            text(body.to_owned()).size(15)
        ]
        .spacing(8)
        .width(Length::Fill),
    )
    .padding(18)
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
            text("Analysefluss").size(20),
            text(status.to_owned()).size(16),
            progress_bar(0.0..=1.0, progress.clamp(0.0, 1.0)),
            text(hint.to_owned()).size(14),
            text(detail.to_owned()).size(14),
        ]
        .spacing(10)
        .width(Length::Fill),
    )
    .padding(18)
    .width(Length::Fill)
    .into()
}

fn register_card(entry: RegisterEntry) -> Element<'static, Message> {
    container(
        column![
            text(format!("{} | {}", entry.id, entry.file_name)).size(18),
            text(format!(
                "{} | Original {} B | Delta {} B | Gewinn {:.2}%",
                entry.source_kind,
                entry.original_size,
                entry.delta_size,
                entry.compression_gain_percent
            ))
            .size(15),
            text(entry.anchor_summary.clone()).size(15),
            text(entry.preview_note.clone()).size(15),
        ]
        .spacing(6),
    )
    .padding(16)
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
