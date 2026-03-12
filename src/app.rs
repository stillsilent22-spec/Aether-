use crate::aef::{AefEncoder, AefInspector, AefReport, EnginePipeline, VaultStore};
use crate::auth::{AuthStore, UserRecord};
use crate::shanway::{render_reply as render_shanway_reply, ShanwayInput};
use crate::state::{ChatMessage, RegisterEntry, StateStore};
use eframe::egui::{self, Color32, ColorImage, RichText, Sense, Stroke, TextEdit, TextureHandle, Vec2};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopTab {
    Analyse,
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
struct ProcessedFile {
    file_name: String,
    full_path: String,
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
    preview_texture: Option<TextureHandle>,
    current_file: Option<ProcessedFile>,
    last_aef_report: Option<AefReport>,
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
}

impl AetherRustShell {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let aef_vault = Arc::new(RwLock::new(load_local_vault_store()));
        let aef_engine = Arc::new(EnginePipeline::new());
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
            browser_note: "Browser-Tab ist vorbereitet. Netzpfade bleiben fail-closed, bis der Transport portiert ist.".to_owned(),
            preview_texture: None,
            current_file: None,
            last_aef_report: None,
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
        AefInspector::inspect(&output_path).map_err(|err| format!("AEF-Inspektion fehlgeschlagen: {err}"))
    }

    fn current_shanway_input(&self) -> Option<ShanwayInput> {
        self.current_file.as_ref().map(|file| ShanwayInput {
            file_name: file.file_name.clone(),
            file_type: file.source_kind.clone(),
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
            residual_ratio: (file.delta_size as f32 / file.original_size.max(1) as f32).clamp(0.0, 1.0),
            observer_mutual_info: (file.symmetry * (1.0 - (file.drift / 255.0).clamp(0.0, 1.0))).clamp(0.0, 1.0),
            h_lambda: (file.entropy * (1.0 - file.symmetry).clamp(0.0, 1.0)).max(0.0),
            boundary: if file.symmetry < 0.58 {
                "GOEDEL_LIMIT".to_owned()
            } else if file.symmetry < 0.76 {
                "STRUCTURAL_HYPOTHESIS".to_owned()
            } else {
                "RECONSTRUCTABLE".to_owned()
            },
            anchor_summary: file.anchor_summary.clone(),
            process_summary: file.process_summary.clone(),
        })
    }

    fn append_log(&mut self, message: impl Into<String>) {
        self.activity_log.push(message.into());
        if self.activity_log.len() > 64 {
            let remove_count = self.activity_log.len().saturating_sub(64);
            self.activity_log.drain(0..remove_count);
        }
    }

    fn draw_shanway_face(&self, ui: &mut egui::Ui) {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(220.0, 220.0), Sense::hover());
        let painter = ui.painter_at(rect);
        let center = rect.center();
        painter.circle_filled(center, 82.0, Color32::from_rgb(35, 46, 70));
        painter.circle_stroke(center, 82.0, Stroke::new(2.0, Color32::from_rgb(120, 180, 255)));
        painter.circle_filled(egui::pos2(center.x - 28.0, center.y - 16.0), 10.0, Color32::LIGHT_BLUE);
        painter.circle_filled(egui::pos2(center.x + 28.0, center.y - 16.0), 10.0, Color32::LIGHT_BLUE);
        painter.line_segment(
            [egui::pos2(center.x - 34.0, center.y + 30.0), egui::pos2(center.x + 34.0, center.y + 30.0)],
            Stroke::new(3.0, Color32::from_rgb(120, 180, 255)),
        );
    }

    fn ui_auth(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(120.0);
                ui.heading("Aether Rust Shell");
                ui.label("Lokale Anmeldung bleibt Pflicht.");
                ui.add_space(20.0);
                ui.group(|ui| {
                    ui.set_max_width(420.0);
                    ui.label(RichText::new("Anmeldung / Registrierung").strong());
                    ui.label("Benutzername");
                    ui.add(TextEdit::singleline(&mut self.login_username).desired_width(320.0));
                    ui.label("Passwort");
                    ui.add(TextEdit::singleline(&mut self.login_password).password(true).desired_width(320.0));
                    ui.horizontal(|ui| {
                        if ui.button("Anmelden").clicked() {
                            match self.auth_store.authenticate(&self.login_username, &self.login_password) {
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
                            match self.auth_store.register(&self.login_username, &self.login_password) {
                                Ok(()) => {
                                    self.status_line = "Registrierung erfolgreich. Bitte anmelden.".to_owned();
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
                ui.add_space(12.0);
                ui.label(RichText::new(&self.status_line).color(Color32::LIGHT_BLUE));
            });
        });
    }

    fn ui_left_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("shanway_left").resizable(false).default_width(340.0).show(ctx, |ui| {
            self.draw_shanway_face(ui);
            ui.heading("Shanway");
            ui.label("Struktureller Beobachter. Dateien werden nur per Drag and Drop eingefuehrt.");
            ui.label(RichText::new("Sicherheitsfilter: aktiv").color(Color32::LIGHT_GREEN));
            ui.label(RichText::new("Netzpfad: standardmaessig aus").color(Color32::LIGHT_YELLOW));
            ui.separator();
            if let Some(file) = &self.current_file {
                ui.label(RichText::new("Aktive Datei").strong());
                ui.label(format!("Name: {}", file.file_name));
                ui.label(format!("Typ: {}", file.source_kind));
                ui.label(format!("Groesse: {} Bytes", file.original_size));
                ui.label(format!("Kompressionsgewinn: {:.2}%", file.compression_gain_percent));
            } else {
                ui.label("Noch keine Datei aktiv.");
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
            }
            if ui.button("Shanway-Chat oeffnen").clicked() {
                self.top_tab = TopTab::Chats;
                self.chat_tab = ChatTab::Shanway;
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
        ui.horizontal(|ui| {
            for (tab, label) in [
                (TopTab::Analyse, "Datei"),
                (TopTab::Browser, "Browser"),
                (TopTab::Chats, "Chats"),
                (TopTab::Register, "Register"),
            ] {
                if ui.selectable_label(self.top_tab == tab, label).clicked() {
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
        let bytes = fs::read(path).map_err(|err| format!("Datei konnte nicht gelesen werden: {err}"))?;
        let metadata = fs::metadata(path).map_err(|err| format!("Metadaten konnten nicht gelesen werden: {err}"))?;
        let original_size = metadata.len();
        let delta_size = estimate_compressed_size(&bytes)?;
        let ratio = if original_size == 0 { 0.0 } else { delta_size as f32 / original_size as f32 };
        let compression_gain_percent = ((1.0 - ratio).clamp(0.0, 1.0) * 10000.0).round() / 100.0;
        let entropy = shannon_entropy(&bytes);
        let preview = build_preview_image(path, &bytes);
        let symmetry = preview_symmetry(&preview);
        let drift = byte_drift(&bytes);
        let source_kind = detect_source_kind(path, &bytes);
        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("unbekannt").to_owned();
        let preview_note = format!(
            "{} | Entropie {:.2} bit | Symmetrie {:.1}% | Drift {:.2}",
            source_kind,
            entropy,
            symmetry * 100.0,
            drift
        );
        let anchor_summary = build_anchor_summary(entropy, symmetry, drift);
        let process_summary = build_process_summary(entropy, symmetry, compression_gain_percent, &source_kind);
        let excerpt = build_excerpt(&source_kind, &bytes);
        self.preview_texture = Some(
            ctx.load_texture(
                format!("preview::{file_name}"),
                preview,
                egui::TextureOptions::LINEAR,
            ),
        );

        let mut processed = ProcessedFile {
            file_name: file_name.clone(),
            full_path: path.to_string_lossy().to_string(),
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
        if let Ok(report) = self.encode_aef_for_path(path) {
            processed.process_summary = format!(
                "{}\nAEF: {:.2}% | Delta {:.2}% | Lossless {}",
                processed.process_summary,
                report.compression_rate_percent,
                report.delta_percent,
                if report.lossless_confirmed { "JA" } else { "NEIN" }
            );
            self.last_aef_report = Some(report.clone());
            self.append_log(format!(
                ".aef geschrieben: {} | Lossless {} | Trust {:.2}",
                report.filename,
                if report.lossless_confirmed { "JA" } else { "NEIN" },
                report.trust_score
            ));
        }
        self.current_file = Some(processed.clone());

        let entry = RegisterEntry {
            id: 0,
            owner_username: username.to_owned(),
            file_name,
            full_path: path.to_string_lossy().to_string(),
            source_kind,
            original_size,
            delta_size,
            compression_gain_percent,
            anchor_summary,
            process_summary,
            preview_note,
        };
        let entry_id = self.state_store.add_register_entry(entry)?;
        self.selected_register_id = Some(entry_id);
        Ok(processed)
    }

    fn load_register_entry(&mut self, ctx: &egui::Context, entry: &RegisterEntry) {
        self.selected_register_id = Some(entry.id);
        if Path::new(&entry.full_path).exists() {
            if let Ok(file) = self.preview_existing_file(Path::new(&entry.full_path), ctx) {
                self.current_file = Some(file.clone());
                self.status_line = format!("Registereintrag geladen: {}", file.file_name);
                self.append_log(format!("Registereintrag geladen: {}", file.file_name));
                return;
            }
        }
        self.current_file = Some(ProcessedFile {
            file_name: entry.file_name.clone(),
            full_path: entry.full_path.clone(),
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
        self.preview_texture = Some(
            ctx.load_texture(
                format!("register::{}", entry.id),
                placeholder_preview_image(),
                egui::TextureOptions::LINEAR,
            ),
        );
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
                            if report.lossless_confirmed { "JA" } else { "NEIN" }
                        ));
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
                            report.trust_score,
                            report.coherence_index,
                            report.delta_size_bytes
                        ));
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

    fn ui_browser_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(RichText::new("Browser-Arbeitsflaeche").strong());
            ui.label("Tabs sind vorbereitet. Netzpfade bleiben fail-closed, bis der Rust-Transportport steht.");
            ui.horizontal(|ui| {
                ui.label("Adresse");
                ui.add(TextEdit::singleline(&mut self.browser_address).desired_width(520.0));
                if ui.button("An Shanway uebergeben").clicked() {
                    self.top_tab = TopTab::Chats;
                    self.chat_tab = ChatTab::Shanway;
                    self.shanway_message_input = format!("Bitte Browser-Kontext strukturell pruefen: {}", self.browser_address);
                }
            });
            ui.add_space(8.0);
            ui.label(&self.browser_note);
        });
    }

    fn ui_chats_tab(&mut self, ui: &mut egui::Ui) {
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
        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
            for thread in threads {
                let label = format!("{} ({})", thread.partner_name, thread.messages.len());
                if ui.selectable_label(self.selected_private_partner == thread.partner_name, label).clicked() {
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
        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
            for message in messages {
                ui.label(format!("{}: {}", message.author, message.body));
            }
        });
        ui.add(TextEdit::multiline(&mut self.private_message_input).desired_rows(3).hint_text("Nachricht eingeben"));
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
        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
            for room in rooms {
                let label = format!("{} ({})", room.name, room.messages.len());
                if ui.selectable_label(self.selected_group_name == room.name, label).clicked() {
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
        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
            for message in messages {
                ui.label(format!("{}: {}", message.author, message.body));
            }
        });
        ui.add(TextEdit::multiline(&mut self.group_message_input).desired_rows(3).hint_text("Gruppennachricht eingeben"));
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
        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            for message in &messages {
                ui.label(format!("{}: {}", message.author, message.body));
            }
        });
        ui.add(TextEdit::multiline(&mut self.shanway_message_input).desired_rows(4).hint_text("Frage an Shanway"));
        if ui.button("An Shanway senden").clicked() {
            let prompt = self.shanway_message_input.trim().to_owned();
            if !prompt.is_empty() {
                let shanway_input = self.current_shanway_input();
                let reply = render_shanway_reply(shanway_input.as_ref(), &prompt);
                let shanway_thread = self.state_store.private_thread(&username, "Shanway");
                shanway_thread.messages.push(ChatMessage {
                    author: username.clone(),
                    body: prompt,
                });
                shanway_thread.messages.push(ChatMessage {
                    author: "Shanway".to_owned(),
                    body: reply,
                });
                let _ = self.state_store.save();
                self.shanway_message_input.clear();
            }
        }
    }

    fn preview_existing_file(&mut self, path: &Path, ctx: &egui::Context) -> Result<ProcessedFile, String> {
        let bytes = fs::read(path).map_err(|err| format!("Datei konnte nicht gelesen werden: {err}"))?;
        let metadata = fs::metadata(path).map_err(|err| format!("Metadaten konnten nicht gelesen werden: {err}"))?;
        let original_size = metadata.len();
        let delta_size = estimate_compressed_size(&bytes)?;
        let ratio = if original_size == 0 { 0.0 } else { delta_size as f32 / original_size as f32 };
        let compression_gain_percent = ((1.0 - ratio).clamp(0.0, 1.0) * 10000.0).round() / 100.0;
        let entropy = shannon_entropy(&bytes);
        let preview = build_preview_image(path, &bytes);
        let symmetry = preview_symmetry(&preview);
        let drift = byte_drift(&bytes);
        let source_kind = detect_source_kind(path, &bytes);
        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("unbekannt").to_owned();
        let preview_note = format!(
            "{} | Entropie {:.2} bit | Symmetrie {:.1}% | Drift {:.2}",
            source_kind,
            entropy,
            symmetry * 100.0,
            drift
        );
        let anchor_summary = build_anchor_summary(entropy, symmetry, drift);
        let process_summary = build_process_summary(entropy, symmetry, compression_gain_percent, &source_kind);
        let excerpt = build_excerpt(&source_kind, &bytes);
        self.preview_texture = Some(
            ctx.load_texture(
                format!("preview::{file_name}"),
                preview,
                egui::TextureOptions::LINEAR,
            ),
        );
        Ok(ProcessedFile {
            file_name,
            full_path: path.to_string_lossy().to_string(),
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
            egui::Grid::new("register_grid").striped(true).show(ui, |ui| {
                ui.strong("ID");
                ui.strong("Datei");
                ui.strong("Typ");
                ui.strong("Original");
                ui.strong("Delta");
                ui.strong("Gewinn");
                ui.end_row();
                for entry in entries {
                    let selected = self.selected_register_id == Some(entry.id);
                    if ui.selectable_label(selected, entry.id.to_string()).clicked() {
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
        if self.current_user.is_none() {
            self.ui_auth(ctx);
            return;
        }
        self.handle_dropped_files(ctx);
        self.ui_left_panel(ctx);
        egui::TopBottomPanel::top("main_tabs_top").show(ctx, |ui| self.ui_top_tabs(ui));
        egui::CentralPanel::default().show(ctx, |ui| match self.top_tab {
            TopTab::Analyse => self.ui_analyse_tab(ui),
            TopTab::Browser => self.ui_browser_tab(ui),
            TopTab::Chats => self.ui_chats_tab(ui),
            TopTab::Register => self.ui_register_tab(ui, ctx),
        });
    }
}

fn detect_source_kind(path: &Path, bytes: &[u8]) -> String {
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or_default().to_ascii_lowercase();
    match extension.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tif" | "tiff" | "webp" => "Bild".to_owned(),
        "txt" | "md" | "json" | "toml" | "yaml" | "yml" | "rs" | "py" | "js" | "html" | "css" => "Text / Code".to_owned(),
        "wav" | "mp3" | "flac" | "ogg" => "Audio".to_owned(),
        "mp4" | "mov" | "mkv" | "avi" | "webm" => "Video".to_owned(),
        _ if bytes.starts_with(b"%PDF") => "PDF".to_owned(),
        _ => "Binaer".to_owned(),
    }
}

fn build_excerpt(source_kind: &str, bytes: &[u8]) -> String {
    if source_kind == "Text / Code" || source_kind == "PDF" {
        if let Ok(text) = String::from_utf8(bytes.iter().copied().take(2400).collect()) {
            return text.replace('\r', "").replace('\0', " ").chars().take(420).collect();
        }
    }
    let hex: Vec<String> = bytes.iter().take(64).map(|byte| format!("{byte:02x}")).collect();
    format!("Hex-Anriss: {}", hex.join(" "))
}

fn estimate_compressed_size(bytes: &[u8]) -> Result<u64, String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).map_err(|err| format!("Kompressionsprobe fehlgeschlagen: {err}"))?;
    let output = encoder.finish().map_err(|err| format!("Kompressionsprobe konnte nicht abgeschlossen werden: {err}"))?;
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
    counts.iter().filter(|count| **count > 0).map(|count| {
        let probability = *count as f32 / total;
        -(probability * probability.log2())
    }).sum()
}

fn byte_drift(bytes: &[u8]) -> f32 {
    if bytes.len() < 2 {
        return 0.0;
    }
    let total: u64 = bytes.windows(2).map(|window| (window[0] as i32 - window[1] as i32).unsigned_abs() as u64).sum();
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
    format!("{noether} | {mandelbrot} | {heisenberg} | Entropie {:.2}", entropy)
}

fn build_process_summary(entropy: f32, symmetry: f32, compression_gain_percent: f32, source_kind: &str) -> String {
    format!(
        "Quelle: {source_kind}\nVerdichtung: {:.2}% Gewinn\nEntropiepfad: {:.2} bit\nSymmetriestabilitaet: {:.1}%",
        compression_gain_percent,
        entropy,
        symmetry * 100.0
    )
}

fn load_local_vault_store() -> VaultStore {
    VaultStore::load_default().unwrap_or_default()
}

fn aef_output_path(path: &Path) -> PathBuf {
    let stem = path.file_stem().and_then(|value| value.to_str()).unwrap_or("artifact");
    let file_name = format!("{stem}.aef");
    PathBuf::from("data").join("rust_shell").join("aef").join(file_name)
}

fn build_preview_image(path: &Path, bytes: &[u8]) -> ColorImage {
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or_default().to_ascii_lowercase();
    if matches!(extension.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tif" | "tiff" | "webp") {
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
    if comparisons == 0 { 0.0 } else { total_score / comparisons as f32 }
}
