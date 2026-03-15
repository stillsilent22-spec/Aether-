use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObserverModelScope {
    SessionOnly,
    PersistentLocal,
    NeverStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverModel {
    pub observer_id: Uuid,
    pub knowledge_anchors: HashMap<Uuid, KnowledgeEstimate>,
    pub domain_familiarity: HashMap<String, f32>,
    pub communication_style: CommunicationStyle,
    pub interaction_history: Vec<InteractionRecord>,
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEstimate {
    pub anchor_id: Uuid,
    pub estimated_familiarity: f32,
    pub confidence: f32,
    pub evidence: Vec<EvidenceSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceSource {
    ExplicitStatement,
    QuestionAsked(String),
    CorrectUsage(Uuid),
    MisunderstandingDetected,
    VocabularyMatch(f32),
    DomainContextClue(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationStyle {
    pub preferred_depth: f32,
    pub preferred_length: f32,
    pub analogy_receptive: bool,
    pub example_receptive: bool,
    pub formality: f32,
    pub language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionRecord {
    pub timestamp: u64,
    pub signal_hash: [u8; 32],
    pub shanway_depth_used: ExplanationDepth,
    pub comprehension_signal: ComprehensionSignal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComprehensionSignal {
    Understood,
    PartiallyUnderstood,
    NotUnderstood,
    AlreadyKnew,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SignalAnchor {
    pub anchor_id: Uuid,
    pub domain: String,
    pub weight: f32,
}

#[derive(Debug, Clone)]
pub struct ProcessedSignal {
    pub signal_hash: [u8; 32],
    pub anchors: Vec<SignalAnchor>,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct ObserverDelta {
    pub signal_hash: [u8; 32],
    pub o1_knowledge: f32,
    pub o2_estimated_knowledge: f32,
    pub delta: f32,
    pub confidence: f32,
    pub recommended_depth: ExplanationDepth,
    pub recommended_anchors: Vec<Uuid>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExplanationDepth {
    Fundamental,
    Introductory,
    Intermediate,
    Advanced,
    Expert,
}

#[derive(Debug, Clone)]
pub struct AdaptedOutput {
    pub content: String,
    pub depth_used: ExplanationDepth,
    pub bridge_note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextSignal {
    Confusion,
    AlreadyFamiliar,
    Understood,
    Neutral,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredObserverState {
    models: Vec<ObserverModel>,
}

pub struct MindModelEngine {
    scope: ObserverModelScope,
    path: PathBuf,
    observer_models: HashMap<Uuid, ObserverModel>,
}

pub struct ComprehensionDetector;

pub struct ToMOutputAdapter;

impl Default for CommunicationStyle {
    fn default() -> Self {
        Self {
            preferred_depth: 0.5,
            preferred_length: 0.45,
            analogy_receptive: true,
            example_receptive: true,
            formality: 0.5,
            language: "de".to_owned(),
        }
    }
}

impl ObserverModel {
    fn average_confidence(&self) -> f32 {
        if self.knowledge_anchors.is_empty() {
            return 0.3;
        }
        self.knowledge_anchors
            .values()
            .map(|item| item.confidence)
            .sum::<f32>()
            / self.knowledge_anchors.len() as f32
    }
}

impl ProcessedSignal {
    pub fn from_summary(summary: impl Into<String>, domains: Vec<String>) -> Self {
        let summary = summary.into();
        let anchors = domains
            .into_iter()
            .enumerate()
            .map(|(index, domain)| SignalAnchor {
                anchor_id: stable_uuid(&format!("{domain}:{summary}:{index}")),
                domain,
                weight: 1.0 / (index.max(1) as f32),
            })
            .collect::<Vec<_>>();
        let signal_hash = sha256_bytes(summary.as_bytes());
        Self {
            signal_hash,
            anchors,
            summary,
        }
    }
}

impl MindModelEngine {
    pub fn new(scope: ObserverModelScope) -> Self {
        let path = PathBuf::from("data")
            .join("rust_shell")
            .join("observer_models.json");
        let observer_models = if scope == ObserverModelScope::PersistentLocal && path.exists() {
            fs::read_to_string(&path)
                .ok()
                .and_then(|raw| serde_json::from_str::<StoredObserverState>(&raw).ok())
                .map(|stored| {
                    stored
                        .models
                        .into_iter()
                        .map(|model| (model.observer_id, model))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        Self {
            scope,
            path,
            observer_models,
        }
    }

    pub fn ensure_observer(&mut self, observer_id: Uuid) {
        self.observer_models
            .entry(observer_id)
            .or_insert_with(|| ObserverModel {
                observer_id,
                knowledge_anchors: HashMap::new(),
                domain_familiarity: HashMap::new(),
                communication_style: CommunicationStyle::default(),
                interaction_history: Vec::new(),
                last_updated: now_epoch(),
            });
    }

    pub fn scope(&self) -> ObserverModelScope {
        self.scope
    }

    pub fn enable_persistent_local(&mut self) {
        self.scope = ObserverModelScope::PersistentLocal;
        let _ = self.save();
    }

    pub fn clear_persistent_state(&mut self) -> Result<(), String> {
        self.observer_models.clear();
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    pub fn calculate_observer_delta(
        &self,
        signal: &ProcessedSignal,
        observer_id: Uuid,
    ) -> ObserverDelta {
        let o1_knowledge = 0.92;
        let o2_estimated_knowledge = self
            .observer_models
            .get(&observer_id)
            .map(|model| self.estimate_o2_knowledge(signal, model))
            .unwrap_or_else(|| self.default_knowledge_estimate(signal));
        let delta = (o1_knowledge - o2_estimated_knowledge).clamp(0.0, 1.0);
        let confidence = self
            .observer_models
            .get(&observer_id)
            .map(|model| model.average_confidence())
            .unwrap_or(0.3);
        ObserverDelta {
            signal_hash: signal.signal_hash,
            o1_knowledge,
            o2_estimated_knowledge,
            delta,
            confidence,
            recommended_depth: self
                .calculate_recommended_depth(o1_knowledge, o2_estimated_knowledge),
            recommended_anchors: self.select_bridging_anchors(signal, observer_id),
        }
    }

    pub fn learn_from_user_prompt(
        &mut self,
        observer_id: Uuid,
        signal: &ProcessedSignal,
        user_text: &str,
    ) {
        self.ensure_observer(observer_id);
        let text_signal = ComprehensionDetector::detect_text_signal(user_text);
        let domain_hints = detect_domain_hints(user_text);
        let model = self
            .observer_models
            .get_mut(&observer_id)
            .expect("observer inserted");
        for hint in domain_hints {
            let entry = model.domain_familiarity.entry(hint).or_insert(0.3);
            *entry = (*entry + 0.08).clamp(0.0, 1.0);
        }
        for anchor in &signal.anchors {
            let knowledge =
                model
                    .knowledge_anchors
                    .entry(anchor.anchor_id)
                    .or_insert(KnowledgeEstimate {
                        anchor_id: anchor.anchor_id,
                        estimated_familiarity: 0.45,
                        confidence: 0.15,
                        evidence: Vec::new(),
                    });
            match text_signal {
                TextSignal::AlreadyFamiliar => {
                    knowledge.estimated_familiarity =
                        (knowledge.estimated_familiarity * 0.7 + 0.9 * 0.3).clamp(0.0, 1.0);
                    knowledge.evidence.push(EvidenceSource::ExplicitStatement);
                }
                TextSignal::Confusion => {
                    knowledge.estimated_familiarity =
                        (knowledge.estimated_familiarity * 0.6 + 0.1 * 0.4).clamp(0.0, 1.0);
                    knowledge
                        .evidence
                        .push(EvidenceSource::MisunderstandingDetected);
                }
                _ => {
                    knowledge
                        .evidence
                        .push(EvidenceSource::QuestionAsked(user_text.to_owned()));
                }
            }
            knowledge.confidence = (knowledge.confidence + 0.08).clamp(0.0, 0.95);
        }
        model.last_updated = now_epoch();
        let _ = self.save();
    }

    pub fn record_interaction(
        &mut self,
        observer_id: Uuid,
        signal_hash: [u8; 32],
        depth: ExplanationDepth,
        comprehension_signal: ComprehensionSignal,
    ) {
        self.ensure_observer(observer_id);
        let model = self
            .observer_models
            .get_mut(&observer_id)
            .expect("observer inserted");
        model.interaction_history.push(InteractionRecord {
            timestamp: now_epoch(),
            signal_hash,
            shanway_depth_used: depth,
            comprehension_signal,
        });
        if model.interaction_history.len() > 64 {
            let drop_count = model.interaction_history.len().saturating_sub(64);
            model.interaction_history.drain(0..drop_count);
        }
        match comprehension_signal {
            ComprehensionSignal::NotUnderstood => {
                model.communication_style.preferred_depth =
                    (model.communication_style.preferred_depth - 0.08).clamp(0.0, 1.0);
            }
            ComprehensionSignal::AlreadyKnew => {
                model.communication_style.preferred_depth =
                    (model.communication_style.preferred_depth + 0.08).clamp(0.0, 1.0);
            }
            _ => {}
        }
        model.last_updated = now_epoch();
        let _ = self.save();
    }

    pub fn observer_status(&self, observer_id: Uuid) -> String {
        let Some(model) = self.observer_models.get(&observer_id) else {
            return "Observer-Delta: konservativer Session-Start, noch kein kalibriertes Gegenueber-Modell.".to_owned();
        };
        format!(
            "Observer-Delta aktiv | bekannte Anker {} | Domaenen {} | Tiefe {:.0}% | Konfidenz {:.0}%",
            model.knowledge_anchors.len(),
            model.domain_familiarity.len(),
            model.communication_style.preferred_depth * 100.0,
            model.average_confidence() * 100.0
        )
    }

    pub fn observer_model(&self, observer_id: Uuid) -> Option<&ObserverModel> {
        self.observer_models.get(&observer_id)
    }

    fn estimate_o2_knowledge(&self, signal: &ProcessedSignal, model: &ObserverModel) -> f32 {
        let mut weighted = 0.0f32;
        let mut weight_sum = 0.0f32;
        for anchor in &signal.anchors {
            let familiarity = model
                .knowledge_anchors
                .get(&anchor.anchor_id)
                .map(|knowledge| knowledge.estimated_familiarity)
                .unwrap_or(0.0);
            let domain_bonus = model
                .domain_familiarity
                .get(&anchor.domain)
                .copied()
                .unwrap_or(0.0)
                * 0.30;
            weighted += (familiarity + domain_bonus).min(1.0) * anchor.weight;
            weight_sum += anchor.weight;
        }
        if weight_sum <= f32::EPSILON {
            0.0
        } else {
            (weighted / weight_sum).clamp(0.0, 1.0)
        }
    }

    fn default_knowledge_estimate(&self, signal: &ProcessedSignal) -> f32 {
        if signal.summary.len() > 120 {
            0.28
        } else {
            0.38
        }
    }

    fn calculate_recommended_depth(&self, o1: f32, o2: f32) -> ExplanationDepth {
        match (o1 - o2).clamp(0.0, 1.0) {
            delta if delta > 0.80 => ExplanationDepth::Fundamental,
            delta if delta > 0.55 => ExplanationDepth::Introductory,
            delta if delta > 0.30 => ExplanationDepth::Intermediate,
            delta if delta > 0.12 => ExplanationDepth::Advanced,
            _ => ExplanationDepth::Expert,
        }
    }

    fn select_bridging_anchors(&self, signal: &ProcessedSignal, observer_id: Uuid) -> Vec<Uuid> {
        let Some(model) = self.observer_models.get(&observer_id) else {
            return signal
                .anchors
                .iter()
                .take(2)
                .map(|anchor| anchor.anchor_id)
                .collect();
        };
        let mut scored = signal
            .anchors
            .iter()
            .map(|anchor| {
                let familiarity = model
                    .knowledge_anchors
                    .get(&anchor.anchor_id)
                    .map(|knowledge| knowledge.estimated_familiarity)
                    .unwrap_or(0.0);
                (
                    familiarity
                        + model
                            .domain_familiarity
                            .get(&anchor.domain)
                            .copied()
                            .unwrap_or(0.0),
                    anchor.anchor_id,
                )
            })
            .collect::<Vec<_>>();
        scored.sort_by(|left, right| {
            right
                .0
                .partial_cmp(&left.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored
            .into_iter()
            .take(3)
            .map(|(_, anchor_id)| anchor_id)
            .collect()
    }

    fn save(&self) -> Result<(), String> {
        if self.scope != ObserverModelScope::PersistentLocal {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let state = StoredObserverState {
            models: self.observer_models.values().cloned().collect(),
        };
        let raw = serde_json::to_string_pretty(&state).map_err(|err| err.to_string())?;
        fs::write(&self.path, raw).map_err(|err| err.to_string())
    }
}

impl ComprehensionDetector {
    pub fn detect_text_signal(user_input: &str) -> TextSignal {
        let normalized = user_input.to_ascii_lowercase();
        let confusion = [
            "ich verstehe",
            "was meinst",
            "unklar",
            "hae",
            "warum",
            "wie genau",
        ];
        let familiar = [
            "das weiss ich",
            "kenne ich",
            "ist mir bekannt",
            "already know",
            "klar",
        ];
        let understood = ["ah ok", "verstanden", "macht sinn", "jetzt klar"];
        if confusion.iter().any(|term| normalized.contains(term)) {
            TextSignal::Confusion
        } else if familiar.iter().any(|term| normalized.contains(term)) {
            TextSignal::AlreadyFamiliar
        } else if understood.iter().any(|term| normalized.contains(term)) {
            TextSignal::Understood
        } else {
            TextSignal::Neutral
        }
    }
}

impl ToMOutputAdapter {
    pub fn adapt_output(
        raw_output: &str,
        delta: &ObserverDelta,
        observer_model: Option<&ObserverModel>,
    ) -> AdaptedOutput {
        let prefix = match delta.recommended_depth {
            ExplanationDepth::Fundamental => "Ich starte bei den Grundankern.",
            ExplanationDepth::Introductory => "Ich bleibe auf Einstiegstiefe.",
            ExplanationDepth::Intermediate => "Ich kann an vorhandene Fachanker anschliessen.",
            ExplanationDepth::Advanced => "Ich halte die Erklaerung kompakt und fachlich.",
            ExplanationDepth::Expert => "Ich spreche auf Peer-Level ohne Grundkurs.",
        };
        let bridge_note = observer_model.and_then(|model| {
            if model.communication_style.analogy_receptive && delta.delta > 0.45 {
                Some(
                    "Brueckenanker aktiv: bekannte Domaenen werden als Uebergang genutzt."
                        .to_owned(),
                )
            } else {
                None
            }
        });
        AdaptedOutput {
            content: format!("{prefix} {raw_output}"),
            depth_used: delta.recommended_depth,
            bridge_note,
        }
    }
}

fn stable_uuid(value: &str) -> Uuid {
    let digest = sha256_bytes(value.as_bytes());
    Uuid::from_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
        digest[15],
    ])
}

fn sha256_bytes(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn detect_domain_hints(text: &str) -> Vec<String> {
    let normalized = text.to_ascii_lowercase();
    let mut domains = Vec::new();
    for (needle, domain) in [
        ("rust", "development_rust"),
        ("python", "development_python"),
        ("bild", "image_editing"),
        ("audio", "audio_production"),
        ("sicherheit", "security"),
        ("entropie", "science_mathematics"),
        ("shannon", "science_mathematics"),
    ] {
        if normalized.contains(needle) {
            domains.push(domain.to_owned());
        }
    }
    domains
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_delta_reduces_with_known_anchor() {
        let observer_id = Uuid::new_v4();
        let signal =
            ProcessedSignal::from_summary("rust entropy", vec!["development_rust".to_owned()]);
        let mut engine = MindModelEngine::new(ObserverModelScope::SessionOnly);
        engine.ensure_observer(observer_id);
        let before = engine.calculate_observer_delta(&signal, observer_id);
        engine.learn_from_user_prompt(observer_id, &signal, "das weiss ich, rust kenne ich");
        let after = engine.calculate_observer_delta(&signal, observer_id);
        assert!(after.o2_estimated_knowledge >= before.o2_estimated_knowledge);
    }

    #[test]
    fn comprehension_detector_flags_confusion() {
        assert_eq!(
            ComprehensionDetector::detect_text_signal("ich verstehe nicht was du meinst"),
            TextSignal::Confusion
        );
    }
}
