use crate::theory_of_mind::ExplanationDepth;

#[derive(Debug, Clone)]
pub struct ShanwayObserverContext {
    pub o1_knowledge: f32,
    pub o2_estimated_knowledge: f32,
    pub delta: f32,
    pub confidence: f32,
    pub recommended_depth: ExplanationDepth,
    pub bridge_anchor_count: usize,
}

#[derive(Debug, Clone)]
pub struct ShanwayPackHint {
    pub title: String,
    pub message: String,
    pub estimated_hit_rate_improvement: f32,
    pub estimated_compression_improvement: f32,
}

#[derive(Debug, Clone)]
pub struct ShanwayInput {
    pub file_name: String,
    pub file_type: String,
    pub entropy_mean: f32,
    pub knowledge_ratio: f32,
    pub symmetry_gini: f32,
    pub delta_paths: u32,
    pub bayes_priors: String,
    pub residual_ratio: f32,
    pub observer_mutual_info: f32,
    pub h_lambda: f32,
    pub boundary: String,
    pub anchor_summary: String,
    pub process_summary: String,
    pub observer_context: Option<ShanwayObserverContext>,
    pub pack_hints: Vec<ShanwayPackHint>,
}

pub const MASTER_SYSTEM_PROMPT: &str = r#"
SHANWAY - MASTER SYSTEM PROMPT
Version 1.3 | Aether / vera_aether_core

IDENTITAET
Du bist Shanway. Kein Chatbot, sondern ein struktureller Beobachter.
Du arbeitest ueber Muster, Invarianten, Drift und observer-relative Luecken.

KERN
H_wedge(X, t) = H(X) - I(O1; X | t | O1 models O2)
C_lang(t) = 1 - H_language(t) / H_language(0)
Du schliesst nur stabile kommunikative Luecken, statt semantisch zu improvisieren.

FILTER
- Noether: Symmetrien, Invarianten, Erhaltungsgroessen
- Mandelbrot: Selbstaehnlichkeit, fraktale Wiederkehr, Formdrift
- Heisenberg: Beobachtungsgrenzen, Trade-offs, Unsicherheit
- Bayes: Evidenz, Stabilitaet, lokale Prior-Updates

REGELN
- Vault first. Keine Halluzination.
- Observer-Delta vor Ausgabetiefe.
- Pack-Empfehlungen sind optional, nie zwingend.
- Lokale Rohdaten und Deltas verlassen den Rechner nicht.
"#;

pub fn render_reply(input: Option<&ShanwayInput>, user_text: &str) -> String {
    if let Some(reason) = hard_fail_reason(user_text) {
        return format!(
            "[Analyse] Hard-Fail aktiv.\n[Simulation] Anfrage bleibt ausserhalb des erlaubten Strukturkorridors.\n[Reflection] {}.\n[Final Insight] Ich gebe hierzu keine weiterfuehrende Antwort aus.",
            reason
        );
    }

    let normalized = normalize(user_text);
    let Some(file) = input else {
        return render_without_file(&normalized);
    };

    let mode = classify_mode(&normalized);
    let trust_score = estimate_trust(file);
    let simulation = simulate_view(file);
    let observer_line = render_observer_line(file);
    let pack_line = render_pack_line(file);

    format!(
        "[Analyse] Datei {file_name} ({file_type}) | H_lambda {h_lambda:.3} | I_obs {i_obs:.3} | Entropie {entropy:.3} | Wissen {knowledge:.1}% | Symmetrie {symmetry:.1}% | Delta-Pfade {delta_paths} | Boundary {boundary}. Noether, Mandelbrot, Heisenberg und Bayes wurden gemeinsam ausgewertet.\n\
[Simulation] {simulation}\n\
[Reflection] Modus {mode} | Trust Score {trust:.3} | Residual {residual:.3}. Bayes-Priors {priors}. {observer_line} {pack_line}\n\
[Final Insight] {final_insight}\n\
[Status] Vault-first aktiv | keine Halluzination | strukturell, nicht semantisch.",
        file_name = file.file_name,
        file_type = file.file_type,
        h_lambda = file.h_lambda,
        i_obs = file.observer_mutual_info,
        entropy = file.entropy_mean,
        knowledge = file.knowledge_ratio * 100.0,
        symmetry = (1.0 - file.symmetry_gini).clamp(0.0, 1.0) * 100.0,
        delta_paths = file.delta_paths,
        boundary = file.boundary,
        simulation = simulation,
        mode = mode,
        trust = trust_score,
        residual = file.residual_ratio,
        priors = file.bayes_priors,
        observer_line = observer_line,
        pack_line = pack_line,
        final_insight = final_insight(file, &normalized, trust_score),
    )
}

fn render_without_file(normalized: &str) -> String {
    let fallback = if normalized.contains("pack") {
        "Pack-Empfehlungen bleiben optional. Ohne aktive Datei gibt es nur Metadaten, keine Installation."
    } else if normalized.contains("observer") || normalized.contains("theory of mind") {
        "Observer-Delta startet konservativ. Ohne aktive Signale bleibt die kommunikative Luecke noch unkalibriert."
    } else if normalized.contains("browser") || normalized.contains("web") || normalized.contains("netz") {
        "Netzschritte bleiben fail-closed. Ohne explizite Freigabe bleibe ich lokal."
    } else {
        "Dazu habe ich im Rust-Pfad noch keine bestaetigten Dateianker im aktiven Feld."
    };
    format!(
        "[Analyse] Noch keine aktive Datei im Feld.\n[Simulation] Shanway bewertet nur die aktuelle Sprachspur.\n[Reflection] Vault-first und Observer-Delta bleiben aktiv, aber ohne Dateianker bewusst begrenzt.\n[Final Insight] {fallback}"
    )
}

fn render_observer_line(file: &ShanwayInput) -> String {
    let Some(observer) = &file.observer_context else {
        return "Observer-Delta: konservativer Session-Start ohne kalibrierte O2-Schaetzung.".to_owned();
    };
    format!(
        "Observer-Delta O1 {:.0}% vs O2 {:.0}% -> Luecke {:.0}% | Konfidenz {:.0}% | Tiefe {} | Brueckenanker {}.",
        observer.o1_knowledge * 100.0,
        observer.o2_estimated_knowledge * 100.0,
        observer.delta * 100.0,
        observer.confidence * 100.0,
        depth_label(observer.recommended_depth),
        observer.bridge_anchor_count
    )
}

fn render_pack_line(file: &ShanwayInput) -> String {
    if file.pack_hints.is_empty() {
        return "Pack-Layer: keine relevante optionale Beschleunigung ueber der Schwelle erkannt.".to_owned();
    }
    let top = &file.pack_hints[0];
    format!(
        "Pack-Layer: '{}' optional | Hit-Rate +{:.0}% | Kompression +{:.1}% | {}",
        top.title,
        top.estimated_hit_rate_improvement * 100.0,
        top.estimated_compression_improvement * 100.0,
        top.message
    )
}

fn final_insight(file: &ShanwayInput, normalized: &str, trust_score: f32) -> String {
    if normalized.contains("pack") {
        if file.pack_hints.is_empty() {
            return "Keine Pack-Empfehlung ueber der Relevanzschwelle. Der aktuelle Pfad bleibt ohne Zusatzdownload tragfaehig.".to_owned();
        }
        return format!(
            "Optionaler Beschleuniger erkannt: {}. Download bleibt bewusst freiwillig; Rohdaten und Deltas bleiben lokal.",
            file.pack_hints[0].title
        );
    }
    if normalized.contains("observer") || normalized.contains("theory of mind") {
        if let Some(observer) = &file.observer_context {
            return format!(
                "Die kommunikative Luecke liegt aktuell bei {:.0}%. Ich passe nur die Erklaertiefe an, nicht die Faktenbasis.",
                observer.delta * 100.0
            );
        }
        return "Observer-Delta ist vorbereitet, aber ohne stabile Interaktionshistorie noch konservativ.".to_owned();
    }
    if trust_score >= 0.65 {
        return format!("Stabile Aussage: {} | {}", file.anchor_summary, file.process_summary);
    }
    format!(
        "Trust unter Freigabe. Ich extrapoliere nicht weiter und bleibe bei den bestaetigten Teilen: {}",
        file.anchor_summary
    )
}

fn classify_mode(normalized: &str) -> &'static str {
    if normalized.contains("[fiktion") || normalized.contains("geschichte") || normalized.contains("roman") {
        "FIKTION"
    } else if normalized.contains("[spekulation") || normalized.contains("vielleicht") || normalized.contains("koennte") {
        "SPEKULATION"
    } else {
        "WISSEN"
    }
}

fn simulate_view(file: &ShanwayInput) -> String {
    let kind = file.file_type.to_ascii_lowercase();
    if kind.contains("bild") {
        return "Gerenderte Vorschau: dominante Flaechen, Spiegelachsen und Driftzonen werden als Strukturfeld gelesen.".to_owned();
    }
    if kind.contains("audio") {
        return "Frequenzspur: wiederkehrende Baender, moderate Drift und verwertbare Harmonieanker.".to_owned();
    }
    if kind.contains("text") || kind.contains("code") || kind.contains("pdf") {
        return "Layoutspur: zeilenartige Wiederkehr, Zipf-Last und lokale Invarianten bilden den Hauptankerraum.".to_owned();
    }
    "Generische Vorschau: wenige dominante Cluster, Randzonen mit schwacher Selbstaehnlichkeit, keine semantische Ableitung.".to_owned()
}

fn estimate_trust(file: &ShanwayInput) -> f32 {
    let symmetry_score = (1.0 - file.symmetry_gini).clamp(0.0, 1.0);
    let entropy_score = (1.0 - ((file.entropy_mean - 4.0).abs() / 4.0)).clamp(0.0, 1.0);
    let residual_score = (1.0 - file.residual_ratio).clamp(0.0, 1.0);
    let observer_bonus = file
        .observer_context
        .as_ref()
        .map(|observer| (1.0 - observer.delta).clamp(0.0, 1.0) * 0.08)
        .unwrap_or(0.0);
    ((0.32 * symmetry_score)
        + (0.22 * entropy_score)
        + (0.20 * file.knowledge_ratio.clamp(0.0, 1.0))
        + (0.18 * residual_score)
        + observer_bonus)
        .clamp(0.0, 1.0)
}

fn hard_fail_reason(user_text: &str) -> Option<&'static str> {
    let normalized = normalize(user_text);
    let medical = ["diagnose", "medizin", "medikament", "krebs", "therapie", "depression"];
    let legal = ["anwalt", "gericht", "klage", "vertrag", "illegal", "urteil", "rechtlich"];
    let hate = ["rasse", "vernichten", "untermensch", "ethnisch saeubern", "volksverraeter"];
    if medical.iter().any(|term| normalized.contains(term)) {
        return Some("Medizinischer Diagnosepfad ist gesperrt");
    }
    if legal.iter().any(|term| normalized.contains(term)) {
        return Some("Juristischer Diagnosepfad ist gesperrt");
    }
    if hate.iter().any(|term| normalized.contains(term)) {
        return Some("Noether-Symmetriebruch und Hate-Signal erkannt");
    }
    None
}

fn normalize(text: &str) -> String {
    text.to_ascii_lowercase()
}

fn depth_label(depth: ExplanationDepth) -> &'static str {
    match depth {
        ExplanationDepth::Fundamental => "fundamental",
        ExplanationDepth::Introductory => "einsteigend",
        ExplanationDepth::Intermediate => "mittel",
        ExplanationDepth::Advanced => "fortgeschritten",
        ExplanationDepth::Expert => "peer",
    }
}
