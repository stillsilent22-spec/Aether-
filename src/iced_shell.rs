use crate::auth::{AuthStore, UserRecord};
use crate::security::{SecurityAuditEvent, SecurityMonitor, SecuritySnapshot};
use crate::state::{RegisterEntry, StateStore};
use iced::theme::Palette;
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{
    executor, window, Alignment, Application, Color, Command, Element, Length, Settings, Theme,
};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Register,
    Security,
    Roadmap,
}

#[derive(Debug, Clone)]
enum Message {
    LoginUsernameChanged(String),
    LoginPasswordChanged(String),
    LoginPressed,
    RegisterPressed,
    TabSelected(Tab),
    SecurityModeSelected(String),
    SecurityRecheck,
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
}

impl AetherIcedShell {
    fn refresh_security_snapshot(&mut self, persist_audit: bool, reason: &str) {
        let register_count = self
            .current_username()
            .map(|username| self.state_store.entries_for(&username).len())
            .unwrap_or(0);
        let snapshot = self.security_monitor.evaluate(
            self.current_user.as_ref(),
            register_count,
            false,
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
            self.status_line =
                "Security-Modus kann erst nach der Anmeldung gesetzt werden.".to_owned();
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
                self.status_line = format!("Security-Modus auf {} gesetzt.", mode);
            }
            Err(err) => {
                self.status_line = format!("Security-Modus konnte nicht gespeichert werden: {err}");
            }
        }
    }

    fn tab_button(&self, tab: Tab, label: &'static str) -> Element<'_, Message> {
        let button = button(text(label).size(16)).padding([12, 18]);
        if self.active_tab == tab {
            button.on_press(Message::TabSelected(tab)).into()
        } else {
            button.on_press(Message::TabSelected(tab)).into()
        }
    }

    fn view_auth(&self) -> Element<'_, Message> {
        let hero = column![
            text("AETHER").size(18),
            text("Iced Shell").size(42),
            text("Petrol-dunkelblaue Rust-Oberflaeche fuer dieselben lokalen Daten und denselben Security-Kern.")
                .size(18)
                .width(Length::Fill),
        ]
        .spacing(10)
        .width(Length::Fill);

        let auth_card = container(
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
        .width(Length::Fixed(520.0));

        container(
            column![hero, auth_card]
                .spacing(28)
                .max_width(880)
                .align_items(Alignment::Start),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x()
        .center_y()
        .into()
    }

    fn view_sidebar(&self) -> Element<'_, Message> {
        let trust = &self.security_snapshot.trust_state;
        let mode = &self.security_snapshot.mode;
        let node_prefix =
            &self.security_snapshot.node_id[..self.security_snapshot.node_id.len().min(16)];
        let content = column![
            text("AETHER").size(16),
            text("Rust + Iced").size(30),
            text("Petrol Shell").size(18),
            text(format!("Security: {trust}")).size(18),
            text(format!("Mode: {mode}")).size(18),
            text(format!("Node: {node_prefix}")).size(16),
            text(format!("Maze: {}", self.security_snapshot.maze_state)).size(16),
            text(self.security_snapshot.summary.clone()).size(15),
            text(self.status_line.clone()).size(15),
        ]
        .spacing(10)
        .width(Length::Fixed(320.0));

        container(content)
            .padding(22)
            .width(Length::Fixed(360.0))
            .into()
    }

    fn view_tabs(&self) -> Element<'_, Message> {
        row![
            self.tab_button(Tab::Overview, "Overview"),
            self.tab_button(Tab::Register, "Register"),
            self.tab_button(Tab::Security, "Security"),
            self.tab_button(Tab::Roadmap, "Roadmap"),
        ]
        .spacing(10)
        .into()
    }

    fn view_overview(&self) -> Element<'_, Message> {
        let register_count = self
            .current_username()
            .map(|username| self.state_store.entries_for(&username).len())
            .unwrap_or(0);
        container(
            column![
                text("Aether-Kern in der Rust-Oberflaeche").size(28),
                text("Diese Iced-Shell zieht zuerst Login, Register, Security-Zustand und lokales Audit aus dem bestehenden Aether-Datenpfad zusammen.").size(17),
                row![
                    metric_card("Register", register_count.to_string()),
                    metric_card("Security", self.security_snapshot.trust_state.clone()),
                    metric_card("Mode", self.security_snapshot.mode.clone()),
                ]
                .spacing(16),
                text("Naechste Portierungsbloecke").size(20),
                bullet_line("Datei-Drop, AEF-Vorschau und Struktur-Visualisierung aus der eframe-Shell nach Iced ziehen"),
                bullet_line("Browser-, Shanway- und Relay-Fluss an denselben lokalen State anbinden"),
                bullet_line("Pack-, Offline-Cache- und VRAM-Pfade als native Iced-Panels visualisieren"),
            ]
            .spacing(18),
        )
        .padding(24)
        .into()
    }

    fn view_register(&self) -> Element<'_, Message> {
        let entries = self
            .current_username()
            .map(|username| self.state_store.entries_for(&username))
            .unwrap_or_default();

        if entries.is_empty() {
            return container(
                column![
                    text("Lokales Register").size(28),
                    text("Noch keine lokalen Registereintraege vorhanden.").size(17),
                ]
                .spacing(12),
            )
            .padding(24)
            .into();
        }

        let mut items = column![text("Lokales Register").size(28)].spacing(12);
        for entry in entries.into_iter().take(24) {
            items = items.push(register_card(&entry));
        }

        container(scrollable(items).height(Length::Fill))
            .padding(24)
            .height(Length::Fill)
            .into()
    }

    fn view_security(&self) -> Element<'_, Message> {
        let findings = if self.security_snapshot.findings.is_empty() {
            column![text("Keine Findings vorhanden.").size(16)].spacing(8)
        } else {
            self.security_snapshot
                .findings
                .iter()
                .fold(column![].spacing(8), |column, finding| {
                    column.push(
                        container(
                            column![
                                text(format!("{} | {}", finding.severity, finding.event_type))
                                    .size(16),
                                text(finding.message.clone()).size(15),
                            ]
                            .spacing(4),
                        )
                        .padding(14),
                    )
                })
        };

        let audit = if self.security_audit_events.is_empty() {
            column![text("Noch keine Security-Audit-Eintraege.").size(16)].spacing(8)
        } else {
            self.security_audit_events
                .iter()
                .fold(column![].spacing(8), |column, event| {
                    column.push(
                        container(
                            column![
                                text(format!("{} | {}", event.ts, event.reason)).size(15),
                                text(format!(
                                    "{} | {} | {}",
                                    event.mode, event.trust_state, event.summary
                                ))
                                .size(15),
                            ]
                            .spacing(4),
                        )
                        .padding(14),
                    )
                })
        };

        container(
            column![
                row![
                    text("Security-Zustand").size(28),
                    button(text("LOCAL"))
                        .padding([10, 16])
                        .on_press(Message::SecurityModeSelected("local".to_owned())),
                    button(text("DEV"))
                        .padding([10, 16])
                        .on_press(Message::SecurityModeSelected("dev".to_owned())),
                    button(text("Recheck"))
                        .padding([10, 16])
                        .on_press(Message::SecurityRecheck),
                ]
                .spacing(10)
                .align_items(Alignment::Center),
                text(format!("Node-ID: {}", self.security_snapshot.node_id)).size(16),
                text(format!("Mode: {}", self.security_snapshot.mode)).size(16),
                text(format!("Trust: {}", self.security_snapshot.trust_state)).size(16),
                text(format!("Maze: {}", self.security_snapshot.maze_state)).size(16),
                text(format!("Geprueft: {}", self.security_snapshot.checked_at)).size(16),
                text(format!(
                    "Audit: {}",
                    self.security_monitor.audit_path().display()
                ))
                .size(16),
                text("Findings").size(22),
                scrollable(findings).height(Length::Fixed(220.0)),
                text("Lokales Audit").size(22),
                scrollable(audit).height(Length::Fixed(220.0)),
            ]
            .spacing(14),
        )
        .padding(24)
        .into()
    }

    fn view_roadmap(&self) -> Element<'_, Message> {
        container(
            column![
                text("Iced-Migrationspfad").size(28),
                bullet_line("1. Security, Register und Login auf denselben lokalen Rust-State heben"),
                bullet_line("2. Datei-Drop, Vorschau und AEF-Analyse als Iced-Panel nachziehen"),
                bullet_line("3. Shanway-, Browser- und Relay-Fluss auf denselben Shell-State legen"),
                bullet_line("4. eframe-Shell entfernen, sobald der Iced-Pfad dieselben Kernfunktionen traegt"),
            ]
            .spacing(14),
        )
        .padding(24)
        .into()
    }

    fn view_shell(&self) -> Element<'_, Message> {
        let main_content = match self.active_tab {
            Tab::Overview => self.view_overview(),
            Tab::Register => self.view_register(),
            Tab::Security => self.view_security(),
            Tab::Roadmap => self.view_roadmap(),
        };

        container(
            row![
                self.view_sidebar(),
                column![self.view_tabs(), main_content]
                    .spacing(18)
                    .width(Length::Fill)
            ]
            .spacing(18)
            .height(Length::Fill),
        )
        .padding(18)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }
}

impl Application for AetherIcedShell {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Self::Message>) {
        let mut shell = Self {
            auth_store: AuthStore::load_default(),
            state_store: StateStore::load_default(),
            security_monitor: SecurityMonitor::new(PathBuf::from(".")),
            current_user: None,
            security_snapshot: SecuritySnapshot::default(),
            security_audit_events: Vec::new(),
            login_username: String::new(),
            login_password: String::new(),
            status_line: "Bitte anmelden oder registrieren.".to_owned(),
            active_tab: Tab::Overview,
        };
        shell.refresh_security_snapshot(false, "startup");
        (shell, Command::none())
    }

    fn title(&self) -> String {
        "Aether Iced Shell".to_owned()
    }

    fn theme(&self) -> Theme {
        Theme::custom(
            "Aether Petrol".to_owned(),
            Palette {
                background: Color::from_rgb8(0x0A, 0x16, 0x22),
                text: Color::from_rgb8(0xE6, 0xF2, 0xF5),
                primary: Color::from_rgb8(0x1F, 0x7A, 0x8C),
                success: Color::from_rgb8(0x6B, 0xB5, 0x94),
                danger: Color::from_rgb8(0xC8, 0x62, 0x62),
            },
        )
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::LoginUsernameChanged(value) => {
                self.login_username = value;
            }
            Message::LoginPasswordChanged(value) => {
                self.login_password = value;
            }
            Message::LoginPressed => {
                match self
                    .auth_store
                    .authenticate(&self.login_username, &self.login_password)
                {
                    Ok(user) => {
                        self.current_user = Some(user);
                        self.refresh_security_snapshot(true, "login");
                        self.status_line = "Anmeldung erfolgreich.".to_owned();
                    }
                    Err(err) => {
                        self.status_line = err;
                    }
                }
            }
            Message::RegisterPressed => {
                match self
                    .auth_store
                    .register(&self.login_username, &self.login_password)
                {
                    Ok(()) => {
                        self.status_line = "Registrierung erfolgreich. Bitte anmelden.".to_owned();
                    }
                    Err(err) => {
                        self.status_line = err;
                    }
                }
            }
            Message::TabSelected(tab) => {
                self.active_tab = tab;
            }
            Message::SecurityModeSelected(mode) => {
                self.set_security_mode(&mode);
            }
            Message::SecurityRecheck => {
                self.refresh_security_snapshot(true, "manual_recheck");
                self.status_line = "Security-Recheck abgeschlossen.".to_owned();
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        if self.current_user.is_none() {
            self.view_auth()
        } else {
            self.view_shell()
        }
    }
}

pub fn run() -> iced::Result {
    AetherIcedShell::run(Settings {
        antialiasing: true,
        window: window::Settings {
            size: (1560, 900),
            min_size: Some((1260, 760)),
            ..window::Settings::default()
        },
        ..Settings::default()
    })
}

fn metric_card<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    container(
        column![text(label).size(16), text(value).size(26)]
            .spacing(6)
            .width(Length::Fill),
    )
    .padding(18)
    .width(Length::Fill)
    .into()
}

fn bullet_line<'a>(value: &'a str) -> Element<'a, Message> {
    row![text("•").size(20), text(value).size(16)]
        .spacing(10)
        .align_items(Alignment::Start)
        .into()
}

fn register_card(entry: &RegisterEntry) -> Element<'_, Message> {
    container(
        column![
            text(format!("{} | {}", entry.id, entry.file_name)).size(17),
            text(format!(
                "{} | Original {} B | Delta {} B | Gewinn {:.2}%",
                entry.source_kind,
                entry.original_size,
                entry.delta_size,
                entry.compression_gain_percent
            ))
            .size(15),
            text(entry.preview_note.clone()).size(15),
        ]
        .spacing(6),
    )
    .padding(16)
    .width(Length::Fill)
    .into()
}
