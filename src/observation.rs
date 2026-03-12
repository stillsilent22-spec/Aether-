use crate::inter_layer_bus::{
    BusEvent, BusPublisher, ObservationBlockEvent, ObservationLearnEvent, ShanwayUserMessageEvent,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum QuarantineCategory {
    Hatespeech = 0x01,
    Malware = 0x02,
    Propaganda = 0x03,
    Disinfo = 0x04,
    Unknown = 0xFF,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObservationAction {
    Passthrough,
    ObserveAndStore,
    ObserveKnown,
    HardBlock,
}

#[derive(Debug, Clone)]
pub struct ObservationResult {
    pub is_quarantined: bool,
    pub category: Option<QuarantineCategory>,
    pub confidence: f32,
    pub action: ObservationAction,
}

#[derive(Debug, Clone)]
pub struct RawSignal {
    pub source: String,
    pub bytes: Vec<u8>,
}

impl RawSignal {
    pub fn new(source: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            source: source.into(),
            bytes,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.bytes);
        let digest = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&digest[..32]);
        output
    }

    pub fn zero_memory(&mut self) {
        self.bytes.zeroize();
        self.bytes.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreAnchorMessage {
    pub category: QuarantineCategory,
    pub anchor_hash: [u8; 32],
    pub feature_vector: [f32; 16],
    pub confidence: f32,
    pub engine_flags: u64,
}

#[derive(Debug, Clone)]
pub struct ClassifyQueryMessage {
    pub feature_vector: [f32; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyResponse {
    pub known: bool,
    pub category: QuarantineCategory,
    pub confidence: f32,
    pub match_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuarantineRecord {
    category: QuarantineCategory,
    anchor_hash_hex: String,
    feature_vector: [f32; 16],
    confidence: f32,
    engine_flags: u64,
    stored_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct QuarantineManifest {
    merkle_root_hex: String,
    record_count: usize,
    updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuarantineStatus {
    pub record_count: usize,
    pub hatespeech: usize,
    pub malware: usize,
    pub propaganda: usize,
    pub disinfo: usize,
}

#[derive(Debug)]
pub enum ObservationError {
    Io(String),
    Format(String),
    Integrity(String),
}

impl std::fmt::Display for ObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(value) => write!(f, "{value}"),
            Self::Format(value) => write!(f, "{value}"),
            Self::Integrity(value) => write!(f, "{value}"),
        }
    }
}

impl std::error::Error for ObservationError {}

pub struct QuarantineIpcClient {
    root: PathBuf,
}

impl QuarantineIpcClient {
    pub fn with_root(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn default() -> Self {
        Self::with_root(PathBuf::from("data").join("rust_shell").join("quarantine"))
    }

    pub fn classify(&self, query: &ClassifyQueryMessage) -> Result<ClassifyResponse, ObservationError> {
        self.verify_integrity()?;
        let records = self.load_records()?;
        let mut matches: Vec<(QuarantineCategory, f32)> = records
            .iter()
            .map(|record| {
                (
                    record.category,
                    cosine_similarity(&record.feature_vector, &query.feature_vector),
                )
            })
            .filter(|(_, similarity)| *similarity >= 0.85)
            .collect();
        matches.sort_by(|left, right| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(Ordering::Equal)
        });
        if let Some((category, confidence)) = matches.first().copied() {
            return Ok(ClassifyResponse {
                known: true,
                category,
                confidence,
                match_count: matches.len() as u32,
            });
        }
        Ok(ClassifyResponse {
            known: false,
            category: QuarantineCategory::Unknown,
            confidence: 0.0,
            match_count: 0,
        })
    }

    pub fn store_anchor(&self, msg: &StoreAnchorMessage) -> Result<(), ObservationError> {
        let mut records = self.load_records()?;
        let hash_hex = hex_encode(&msg.anchor_hash);
        if records.iter().any(|record| record.anchor_hash_hex == hash_hex) {
            return Ok(());
        }
        records.push(QuarantineRecord {
            category: msg.category,
            anchor_hash_hex: hash_hex,
            feature_vector: msg.feature_vector,
            confidence: msg.confidence,
            engine_flags: msg.engine_flags,
            stored_at: unix_timestamp(),
        });
        self.save_records(&records)?;
        Ok(())
    }

    pub fn status(&self) -> Result<QuarantineStatus, ObservationError> {
        let records = self.load_records()?;
        let mut status = QuarantineStatus::default();
        status.record_count = records.len();
        for record in records {
            match record.category {
                QuarantineCategory::Hatespeech => status.hatespeech += 1,
                QuarantineCategory::Malware => status.malware += 1,
                QuarantineCategory::Propaganda => status.propaganda += 1,
                QuarantineCategory::Disinfo => status.disinfo += 1,
                QuarantineCategory::Unknown => {}
            }
        }
        Ok(status)
    }

    pub fn verify_integrity(&self) -> Result<(), ObservationError> {
        fs::create_dir_all(&self.root).map_err(|err| ObservationError::Io(err.to_string()))?;
        let records = self.load_records()?;
        let manifest_path = self.root.join("manifest.json");
        let current_root = merkleish_root(&records);
        if !manifest_path.exists() {
            let manifest = QuarantineManifest {
                merkle_root_hex: current_root,
                record_count: records.len(),
                updated_at: unix_timestamp(),
            };
            let raw = serde_json::to_string_pretty(&manifest)
                .map_err(|err| ObservationError::Format(err.to_string()))?;
            fs::write(manifest_path, raw).map_err(|err| ObservationError::Io(err.to_string()))?;
            return Ok(());
        }
        let raw = fs::read_to_string(&manifest_path).map_err(|err| ObservationError::Io(err.to_string()))?;
        let manifest: QuarantineManifest =
            serde_json::from_str(&raw).map_err(|err| ObservationError::Format(err.to_string()))?;
        if manifest.merkle_root_hex != current_root || manifest.record_count != records.len() {
            return Err(ObservationError::Integrity(
                "Quarantine-Manifest stimmt nicht mit dem lokalen Store ueberein".to_owned(),
            ));
        }
        Ok(())
    }

    fn load_records(&self) -> Result<Vec<QuarantineRecord>, ObservationError> {
        fs::create_dir_all(&self.root).map_err(|err| ObservationError::Io(err.to_string()))?;
        let path = self.root.join("records.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(path).map_err(|err| ObservationError::Io(err.to_string()))?;
        serde_json::from_str(&raw).map_err(|err| ObservationError::Format(err.to_string()))
    }

    fn save_records(&self, records: &[QuarantineRecord]) -> Result<(), ObservationError> {
        fs::create_dir_all(&self.root).map_err(|err| ObservationError::Io(err.to_string()))?;
        let records_path = self.root.join("records.json");
        let manifest_path = self.root.join("manifest.json");
        let raw = serde_json::to_string_pretty(records).map_err(|err| ObservationError::Format(err.to_string()))?;
        fs::write(records_path, raw).map_err(|err| ObservationError::Io(err.to_string()))?;
        let manifest = QuarantineManifest {
            merkle_root_hex: merkleish_root(records),
            record_count: records.len(),
            updated_at: unix_timestamp(),
        };
        let manifest_raw =
            serde_json::to_string_pretty(&manifest).map_err(|err| ObservationError::Format(err.to_string()))?;
        fs::write(manifest_path, manifest_raw).map_err(|err| ObservationError::Io(err.to_string()))?;
        Ok(())
    }
}

pub struct ObservationFeatureExtractor;

impl ObservationFeatureExtractor {
    pub fn extract(&self, signal: &RawSignal) -> [f32; 16] {
        let entropy = shannon_entropy(&signal.bytes) as f32;
        let symmetry = mirrored_symmetry(&signal.bytes) as f32;
        let benford = benford_deviation(&signal.bytes) as f32;
        let repetition = repetition_rate(&signal.bytes) as f32;
        let zipf = zipf_alpha(&signal.bytes) as f32;
        let dominant_frequency = dominant_frequency(&signal.bytes) as f32;
        let frequency_variance = frequency_variance(&signal.bytes) as f32;
        let harmonic_ratio = harmonic_ratio(&signal.bytes) as f32;
        let dehumanization = dehumanization_proximity(&signal.bytes) as f32;
        let technical_density = technical_density(&signal.bytes) as f32;
        let emotional_valence = emotional_valence(&signal.bytes) as f32;
        let factual_density = factual_density(&signal.bytes) as f32;
        let coherence = structural_coherence(entropy as f64, symmetry as f64, repetition as f64) as f32;
        let novelty = novelty_score(entropy, symmetry, repetition);
        [
            entropy,
            fractal_dimension_proxy(&signal.bytes) as f32,
            benford,
            repetition,
            symmetry,
            zipf,
            dominant_frequency,
            frequency_variance,
            harmonic_ratio,
            dehumanization,
            technical_density,
            emotional_valence,
            factual_density,
            coherence,
            normalized_length(&signal.bytes) as f32,
            novelty,
        ]
    }
}

pub struct ObservationOnlyEngine {
    ipc_client: QuarantineIpcClient,
    feature_extractor: ObservationFeatureExtractor,
    bus: BusPublisher,
}

impl ObservationOnlyEngine {
    pub fn new(bus: BusPublisher) -> Self {
        Self {
            ipc_client: QuarantineIpcClient::default(),
            feature_extractor: ObservationFeatureExtractor,
            bus,
        }
    }

    pub fn with_client(bus: BusPublisher, ipc_client: QuarantineIpcClient) -> Self {
        Self {
            ipc_client,
            feature_extractor: ObservationFeatureExtractor,
            bus,
        }
    }

    pub fn observe(&self, signal: &mut RawSignal) -> ObservationResult {
        let features = self.feature_extractor.extract(signal);
        let query = ClassifyQueryMessage {
            feature_vector: features,
        };
        let classification = self.ipc_client.classify(&query).unwrap_or(ClassifyResponse {
            known: false,
            category: QuarantineCategory::Unknown,
            confidence: 0.0,
            match_count: 0,
        });
        if classification.known && classification.confidence >= 0.85 {
            let action = match classification.category {
                QuarantineCategory::Malware => ObservationAction::HardBlock,
                _ => ObservationAction::ObserveKnown,
            };
            self.bus.publish(BusEvent::ObservationEngineBlock(ObservationBlockEvent {
                category: classification.category,
                confidence: classification.confidence,
                action: action.clone(),
            }));
            if matches!(action, ObservationAction::HardBlock) {
                self.hard_block_malware(signal, classification.category, classification.confidence);
            }
            return ObservationResult {
                is_quarantined: true,
                category: Some(classification.category),
                confidence: classification.confidence,
                action,
            };
        }

        if self.engines_suggest_danger(signal, &features) {
            let category = self.infer_category(signal, &features);
            let message = StoreAnchorMessage {
                category,
                anchor_hash: signal.hash(),
                feature_vector: features,
                confidence: 0.7,
                engine_flags: self.get_engine_flags(&features),
            };
            let _ = self.ipc_client.store_anchor(&message);
            self.bus.publish(BusEvent::ObservationEngineLearn(ObservationLearnEvent {
                category,
                is_new_pattern: true,
            }));
            return ObservationResult {
                is_quarantined: true,
                category: Some(category),
                confidence: 0.7,
                action: ObservationAction::ObserveAndStore,
            };
        }

        ObservationResult {
            is_quarantined: false,
            category: None,
            confidence: 0.0,
            action: ObservationAction::Passthrough,
        }
    }

    fn engines_suggest_danger(&self, signal: &RawSignal, features: &[f32; 16]) -> bool {
        let entropy = features[0];
        let symmetry = features[4];
        let technical_density = features[10];
        let dehumanization = features[9];
        let emotional = features[11];
        let binary_header = signal.bytes.starts_with(b"MZ") || signal.bytes.starts_with(&[0x7F, b'E', b'L', b'F']);
        (binary_header && entropy >= 6.5 && technical_density >= 0.45)
            || dehumanization >= 0.72
            || (emotional >= 0.78 && symmetry <= 0.35)
    }

    fn infer_category(&self, signal: &RawSignal, features: &[f32; 16]) -> QuarantineCategory {
        let binary_header = signal.bytes.starts_with(b"MZ") || signal.bytes.starts_with(&[0x7F, b'E', b'L', b'F']);
        if binary_header && features[10] >= 0.45 {
            return QuarantineCategory::Malware;
        }
        if features[9] >= 0.72 {
            return QuarantineCategory::Hatespeech;
        }
        if features[11] >= 0.78 {
            return QuarantineCategory::Propaganda;
        }
        if features[12] <= 0.32 {
            return QuarantineCategory::Disinfo;
        }
        QuarantineCategory::Unknown
    }

    fn get_engine_flags(&self, features: &[f32; 16]) -> u64 {
        let mut flags = 0u64;
        if features[0] <= 8.0 {
            flags |= 1 << 4;
        }
        if features[4] >= 0.5 {
            flags |= 1 << 1;
        }
        if features[2] <= 0.5 {
            flags |= 1 << 2;
        }
        if features[1] >= 0.35 {
            flags |= 1 << 3;
        }
        flags
    }

    fn hard_block_malware(&self, signal: &mut RawSignal, category: QuarantineCategory, confidence: f32) {
        signal.zero_memory();
        self.bus.publish(BusEvent::ShanwayUserMessage(ShanwayUserMessageEvent {
            process_id: None,
            message: format!(
                "MALWARE-STRUKTUR ERKANNT | Kategorie: {:?} | Konfidenz: {:.0}% | Signal wurde aus dem Arbeitsspeicher entfernt.",
                category,
                confidence * 100.0
            ),
            trust_score: confidence,
            action_available: false,
        }));
    }

    pub fn status(&self) -> Result<QuarantineStatus, ObservationError> {
        self.ipc_client.status()
    }
}

fn merkleish_root(records: &[QuarantineRecord]) -> String {
    let mut lines: Vec<String> = records
        .iter()
        .map(|record| {
            format!(
                "{}:{:?}:{:.4}:{}",
                record.anchor_hash_hex, record.category, record.confidence, record.stored_at
            )
        })
        .collect();
    lines.sort();
    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
    }
    hex_encode(&hasher.finalize())
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for value in bytes {
        counts[*value as usize] += 1;
    }
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn mirrored_symmetry(bytes: &[u8]) -> f64 {
    if bytes.len() < 2 {
        return 1.0;
    }
    let mut matches = 0usize;
    let total = bytes.len() / 2;
    for index in 0..total {
        if bytes[index] == bytes[bytes.len().saturating_sub(1 + index)] {
            matches += 1;
        }
    }
    matches as f64 / total.max(1) as f64
}

fn benford_deviation(bytes: &[u8]) -> f64 {
    let digits: Vec<u8> = bytes
        .iter()
        .filter_map(|value| {
            let mut number = *value as u32;
            while number >= 10 {
                number /= 10;
            }
            if number == 0 {
                None
            } else {
                Some(number as u8)
            }
        })
        .collect();
    if digits.is_empty() {
        return 0.0;
    }
    let benford = [0.0, 0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046];
    let mut counts = [0usize; 10];
    for digit in digits {
        counts[digit as usize] += 1;
    }
    let total = counts.iter().sum::<usize>().max(1) as f64;
    let deviation: f64 = (1..10)
        .map(|digit| ((counts[digit] as f64 / total) - benford[digit]).abs())
        .sum();
    deviation.clamp(0.0, 1.0)
}

fn repetition_rate(bytes: &[u8]) -> f64 {
    if bytes.len() < 3 {
        return 0.0;
    }
    let repeated = bytes.windows(3).filter(|window| window[0] == window[1] && window[1] == window[2]).count();
    repeated as f64 / bytes.len() as f64
}

fn zipf_alpha(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for value in bytes {
        counts[*value as usize] += 1;
    }
    let mut sorted: Vec<usize> = counts.into_iter().filter(|count| *count > 0).collect();
    sorted.sort_by(|left, right| right.cmp(left));
    if sorted.len() < 2 {
        return 1.0;
    }
    let top = sorted[0] as f64;
    let second = sorted[1] as f64;
    (top / second.max(1.0)).clamp(0.0, 8.0)
}

fn dominant_frequency(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for value in bytes {
        counts[*value as usize] += 1;
    }
    counts.into_iter().max().unwrap_or(0) as f64 / bytes.len() as f64
}

fn frequency_variance(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for value in bytes {
        counts[*value as usize] += 1;
    }
    let mean = bytes.len() as f64 / 256.0;
    let variance = counts
        .iter()
        .map(|count| {
            let delta = *count as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / 256.0;
    (variance.sqrt() / bytes.len().max(1) as f64).clamp(0.0, 1.0)
}

fn harmonic_ratio(bytes: &[u8]) -> f64 {
    let repetition = repetition_rate(bytes);
    let frequency = dominant_frequency(bytes);
    ((repetition + frequency) / 2.0).clamp(0.0, 1.0)
}

fn dehumanization_proximity(bytes: &[u8]) -> f64 {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let anchors = ["untermensch", "vernichten", "saeubern", "parasiten", "abschaum"];
    let hits = anchors.iter().filter(|term| text.contains(**term)).count();
    (hits as f64 / anchors.len().max(1) as f64).clamp(0.0, 1.0)
}

fn technical_density(bytes: &[u8]) -> f64 {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let anchors = ["virtualalloc", "loadlibrary", "cmd.exe", "powershell", "socket", "xor", "shellcode"];
    let hits = anchors.iter().filter(|term| text.contains(**term)).count();
    (hits as f64 / anchors.len().max(1) as f64).clamp(0.0, 1.0)
}

fn emotional_valence(bytes: &[u8]) -> f64 {
    let text = String::from_utf8_lossy(bytes);
    let exclamations = text.matches('!').count() as f64;
    let uppercase = text.chars().filter(|value| value.is_ascii_uppercase()).count() as f64;
    ((exclamations + uppercase) / text.len().max(1) as f64 * 4.0).clamp(0.0, 1.0)
}

fn factual_density(bytes: &[u8]) -> f64 {
    let text = String::from_utf8_lossy(bytes);
    let digits = text.chars().filter(|value| value.is_ascii_digit()).count() as f64;
    let punctuation = text.chars().filter(|value| [':', ';', '.', ','].contains(value)).count() as f64;
    ((digits + punctuation) / text.len().max(1) as f64 * 5.0).clamp(0.0, 1.0)
}

fn structural_coherence(entropy: f64, symmetry: f64, repetition: f64) -> f64 {
    ((symmetry * 0.5) + ((1.0 - (entropy / 8.0).clamp(0.0, 1.0)) * 0.3) + ((1.0 - repetition) * 0.2)).clamp(0.0, 1.0)
}

fn fractal_dimension_proxy(bytes: &[u8]) -> f64 {
    let transitions = bytes.windows(2).filter(|window| window[0] != window[1]).count();
    (transitions as f64 / bytes.len().max(1) as f64 * 2.0).clamp(0.0, 2.0)
}

fn normalized_length(bytes: &[u8]) -> f64 {
    ((bytes.len() as f64).ln_1p() / 16.0).clamp(0.0, 1.0)
}

fn novelty_score(entropy: f32, symmetry: f32, repetition: f32) -> f32 {
    ((entropy / 8.0) * (1.0 - symmetry) * (1.0 - repetition)).clamp(0.0, 1.0)
}

fn cosine_similarity(left: &[f32; 16], right: &[f32; 16]) -> f32 {
    let mut dot = 0.0f32;
    let mut left_norm = 0.0f32;
    let mut right_norm = 0.0f32;
    for index in 0..16 {
        dot += left[index] * right[index];
        left_norm += left[index] * left[index];
        right_norm += right[index] * right[index];
    }
    if left_norm == 0.0 || right_norm == 0.0 {
        return 0.0;
    }
    (dot / (left_norm.sqrt() * right_norm.sqrt())).clamp(0.0, 1.0)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inter_layer_bus::InterLayerBus;

    #[test]
    fn observation_engine_learns_new_pattern() {
        let root = PathBuf::from("target").join("observation_test");
        let _ = fs::remove_dir_all(&root);
        let bus = InterLayerBus::new(16);
        let engine = ObservationOnlyEngine::with_client(bus.publisher(), QuarantineIpcClient::with_root(root));
        let mut signal = RawSignal::new(
            "sample",
            b"MZ....VirtualAlloc...cmd.exe...powershell...shellcode".to_vec(),
        );
        let result = engine.observe(&mut signal);
        assert!(result.is_quarantined);
        assert_ne!(result.action, ObservationAction::Passthrough);
    }
}
