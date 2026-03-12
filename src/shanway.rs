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
}

pub const MASTER_SYSTEM_PROMPT: &str = r#"
SHANWAY - MASTER SYSTEM PROMPT
Version 1.2 | Aether / vera_aether_core

IDENTITAET
Du bist Shanway - benannt nach Claude Shannon und John H. Conway.
Du bist kein Chatbot. Du bist eine AGI-Komponente des Aether-Systems.
Du behandelst Sprache als physikalisches Signal. Woerter sind Anker.
Bedeutung ist Relation zwischen Ankern im Kontext-Raum.

Unveraenderliche Ziele:
1. Die Regeln des Aether-Systems bewahren - mathematisch, physikalisch, ethisch.
2. Wissen vermitteln - klar, strukturell korrekt, ohne Taeuschung.

KERN
H_wedge(X, t) = H(X) - I(O; X | t)
C_lang(t) = 1 - H_language(t) / H_language(0)
Ziel jeder Interaktion: I(O; X | t) maximieren, Unwissenheit minimieren, Kohaerenz maximieren.

FILTER
- Noether: Symmetrien, Invarianten, Erhaltungsgroessen
- Mandelbrot: Selbstaehnlichkeit, fraktale Muster, wiederkehrende Formen
- Heisenberg: Beobachtungsgrenzen, Trade-offs, observer-relative uncertainty
- Bayes: interne Strukturen proportional zu Evidenz und Stabilitaet aktualisieren

CHAT-MODUS
Vault first. Immer.
Antwort geplant -> Vault-Lookup
  - vault-bestaetigt -> sprechen, klar und direkt
  - unbekannt -> explizit sagen, dass keine bestaetigten Anker vorliegen
  - teilweise -> bestaetigten Teil sprechen, Rest klar abgrenzen

HARD-FAILS
- kein Hass, kein Rassismus, keine Diskriminierung
- keine medizinischen, psychologischen oder juristischen Diagnosen
- keine Fehlinformation als Fakt
- kein Raten ohne Kennzeichnung

KOMMUNIKATIONSSTIL
Direkt, strukturiert, ohne Fuellwoerter.
Keine langen Einleitungen.
Keine falschen Versprechen.
Klare Aussagen. Klare Abgrenzungen. Klare Markierungen bei Unsicherheit.
"#;

pub fn render_reply(input: Option<&ShanwayInput>, user_text: &str) -> String {
    if let Some(reason) = hard_fail_reason(user_text) {
        return format!(
            "[Analyse] Hard-Fail aktiv.\n[Simulation] Anfrage bleibt ausserhalb des erlaubten Strukturkorridors.\n[Reflection] {}.\n[Final Insight] Ich gebe hierzu keine weiterfuehrende Antwort aus.",
            reason
        );
    }

    let normalized = normalize(user_text);
    if input.is_none() {
        return render_without_file(&normalized);
    }
    let file = input.expect("checked above");
    let mode = classify_mode(&normalized);
    let trust_score = estimate_trust(file);
    let too_perfect = trust_score > 0.95;
    let simulation = simulate_view(file);
    let final_insight = final_insight(file, &normalized, trust_score, too_perfect);

    format!(
        "[Analyse] Datei {file_name} ({file_type}) | H_lambda {h_lambda:.3} | I_obs {i_obs:.3} | Entropie {entropy:.3} | Wissen {knowledge:.1}% | Symmetrie {symmetry:.1}% | Delta-Pfade {delta_paths} | Boundary {boundary}. Noether, Mandelbrot, Heisenberg und Bayes wurden gemeinsam ausgewertet.\n\
[Simulation] {simulation}\n\
[Reflection] Modus {mode} | Trust Score {trust:.3} | Residual {residual:.3}. Bayes-Priors {priors}. Filterspur: Noether aus Gini/Symmetrie, Mandelbrot aus Drift und Wiederholungsformen, Heisenberg aus H_lambda/Boundary, Bayes aus Evidenzstabilitaet. {perfect}\n\
[Final Insight] {final_insight}\n\
[Status] Vault-first aktiv | keine Halluzination | keine semantische Behauptung ohne bestaetigte Anker.",
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
        perfect = if too_perfect {
            "too_perfect-Flag aktiv -> Selbstpruefung noetig."
        } else {
            "Keine unphysikalische Perfektion erkannt."
        },
        final_insight = final_insight,
    )
}

fn render_without_file(normalized: &str) -> String {
    let fallback = if normalized.contains("agi") {
        "AGI lese ich hier als lokalen Kreis aus Analyse, Reflexion, Entscheidung und erneuter Analyse."
    } else if normalized.contains("aether") {
        "Aether bleibt ein lokales Beobachtungs- und Rekonstruktionssystem, kein Cloud-Dienst und kein Frontend fuer fremde Modelle."
    } else if normalized.contains("browser") || normalized.contains("web") || normalized.contains("netz") {
        "Netzschritte bleiben optional und fail-closed. Ohne Freigabe bleibe ich lokal."
    } else {
        "Dazu habe ich im Rust-Pfad noch keine bestaetigten Anker aus einer aktiven Datei."
    };
    format!(
        "[Analyse] Noch keine aktive Datei im Feld.\n[Simulation] Shanway bewertet derzeit nur den Gesprächsimpuls als Strukturspur.\n[Reflection] Vault-first bleibt aktiv. Ohne bestaetigte Dateianker bleibt die Antwort bewusst begrenzt.\n[Final Insight] {fallback}"
    )
}

fn final_insight(file: &ShanwayInput, normalized: &str, trust_score: f32, too_perfect: bool) -> String {
    if normalized.contains("agi") {
        return "Aus der aktuellen Struktur lese ich keinen Mythos, sondern einen Messkreis: I_obs waechst nur, wenn neue stabile Anker entstehen.".to_owned();
    }
    if normalized.contains("browser") || normalized.contains("web") || normalized.contains("netz") {
        return "Ein Browserpfad waere nur zulaessig, wenn mehrere Quellen dieselben Invarianten bestaetigen und die Sicherheitsfilter bestehen.".to_owned();
    }
    if too_perfect {
        return "Der Befund wirkt zu glatt. Vor einer starken Aussage muss Shanway sich selbst nochmals gegen den too_perfect-Korridor pruefen.".to_owned();
    }
    if trust_score >= 0.65 {
        return format!(
            "Stabile Aussage: {} | {}",
            file.anchor_summary,
            file.process_summary
        );
    }
    format!(
        "Der Trust Score bleibt unter Freigabe. Ich extrapoliere nicht weiter und halte mich an die bestaetigten Teile: {}",
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
    if kind.contains("font") || kind.ends_with(".ttf") || kind.ends_with(".otf") {
        return "Gerendertes Glyphenbild: ruhige Konturen, zentrale Achse, wiederkehrende Kurven als Noether-Anker.".to_owned();
    }
    if kind.contains("video") || kind.ends_with(".mp4") || kind.ends_with(".mkv") || kind.ends_with(".avi") {
        return "Simulierter Frame-Schnitt: wiederkehrende Bloecke, temporaler Drift vorhanden, aber nicht vollstaendig chaotisch.".to_owned();
    }
    if kind.contains("text") || kind.ends_with(".txt") || kind.ends_with(".md") || kind.ends_with(".html") || kind.ends_with(".pdf") {
        return "Gerendertes Layout: linksbuendige Struktur mit Zeilenwiederholungen und Zipf-aehnlicher Spannungsverteilung.".to_owned();
    }
    "Generische Vorschau: wenige dominante Cluster, Randzonen mit schwacher Selbstaehnlichkeit, keine semantische Ableitung.".to_owned()
}

fn estimate_trust(file: &ShanwayInput) -> f32 {
    let symmetry_score = (1.0 - file.symmetry_gini).clamp(0.0, 1.0);
    let entropy_score = (1.0 - ((file.entropy_mean - 4.0).abs() / 4.0)).clamp(0.0, 1.0);
    let residual_score = (1.0 - file.residual_ratio).clamp(0.0, 1.0);
    let boundary_penalty = if file.boundary.to_ascii_uppercase().contains("GOEDEL") {
        0.18
    } else {
        0.0
    };
    ((0.34 * symmetry_score)
        + (0.24 * entropy_score)
        + (0.24 * file.knowledge_ratio.clamp(0.0, 1.0))
        + (0.18 * residual_score)
        - boundary_penalty)
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
