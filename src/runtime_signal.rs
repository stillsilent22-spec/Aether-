use crate::inter_layer_bus::{
    BusEvent, BusPublisher, OptimizationType, ProcessStartedEvent, RuntimeAnomalyEvent,
    RuntimeOptimizationEvent, RuntimeSignalFrameEvent, SemanticClusterEvent,
    ShanwayOptimizationEvent, ShanwayUserMessageEvent, VaultGapEvent, VaultWriteEvent,
};
use crate::vault_access::VaultAccessLayer;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum RuntimeSignalSource {
    ProcessMonitor(u32),
    SystemMetrics,
    GameFrameCapture(u32),
    LogStream(String),
    NetworkStream(String),
}

#[derive(Debug, Clone)]
pub struct ProcessProfile {
    pub pid: u32,
    pub process_name: String,
    pub sample_count: u64,
    pub runtime_source: RuntimeSignalSource,
}

#[derive(Debug, Clone)]
struct RawFrame {
    process_id: u32,
    process_name: String,
    memory_accesses: Vec<u64>,
    frame_time: Option<f32>,
    entropy: f64,
    active_anchors: Vec<Uuid>,
}

#[derive(Debug, Clone)]
struct ActiveAnchorSet {
    ids: Vec<Uuid>,
    cpu_distribution: HashMap<Uuid, f32>,
}

/// ABSOLUTE PRIVACY BOUNDARY
/// Kein privates Signal erreicht je den Bus.
/// Hard-verdrahtet und nicht konfigurierbar.
pub fn is_private_context(source: &str, content_hint: &str) -> bool {
    const COMMUNICATION: &[&str] = &[
        "chat",
        "dm",
        "direct_message",
        "message",
        "messenger",
        "groupchat",
        "group_chat",
        "group_message",
        "channel_message",
        "whatsapp",
        "telegram",
        "signal_app",
        "discord_dm",
        "slack_dm",
        "teams_chat",
        "sms",
        "mms",
        "imessage",
        "facetime",
        "skype",
        "viber",
    ];
    const EMAIL: &[&str] = &[
        "mail",
        "email",
        "e-mail",
        "inbox",
        "outbox",
        "outlook",
        "gmail",
        "thunderbird",
        "protonmail",
        "smtp",
        "imap",
        "pop3",
        "compose",
        "draft",
        "sent_mail",
        "mailbox",
    ];
    const CREDENTIALS: &[&str] = &[
        "password",
        "passwort",
        "passwd",
        "pwd",
        "passphrase",
        "credentials",
        "credential",
        "login_form",
        "auth_token",
        "access_token",
        "refresh_token",
        "api_key",
        "secret_key",
        "private_key",
        "signing_key",
        "2fa",
        "otp",
        "totp",
        "pin_entry",
        "pin_code",
        "security_code",
    ];
    const PERSONAL: &[&str] = &[
        "keychain",
        "password_manager",
        "biometric",
        "face_id",
        "fingerprint",
        "touch_id",
        "personal_vault",
        "private_notes",
    ];

    let src = source.to_lowercase();
    let hint = content_hint.to_lowercase();
    let categories: [&[&str]; 4] = [COMMUNICATION, EMAIL, CREDENTIALS, PERSONAL];
    for patterns in categories {
        if patterns
            .iter()
            .any(|pattern| src.contains(pattern) || hint.contains(pattern))
        {
            return true;
        }
    }
    contains_email_pattern(&hint) || contains_password_field_pattern(&hint)
}

fn contains_email_pattern(text: &str) -> bool {
    let Some(at_pos) = text.find('@') else {
        return false;
    };
    let before = &text[..at_pos];
    let after = &text[at_pos + 1..];
    !before.is_empty()
        && !after.is_empty()
        && after.contains('.')
        && before
            .chars()
            .last()
            .map(|value| value.is_ascii_alphanumeric())
            .unwrap_or(false)
}

fn contains_password_field_pattern(text: &str) -> bool {
    text.contains("type=\"password\"")
        || text.contains("type='password'")
        || text.contains("input_type=password")
        || text.contains("pwd=")
        || text.contains("pass=")
}

pub struct RuntimeSignalCollector {
    bus: BusPublisher,
    pub sample_rate_ms: u64,
    active_processes: HashMap<u32, ProcessProfile>,
}

impl RuntimeSignalCollector {
    pub fn new(bus: BusPublisher) -> Self {
        Self {
            bus,
            sample_rate_ms: 16,
            active_processes: HashMap::new(),
        }
    }

    pub fn attach_process(&mut self, pid: u32, process_name: impl Into<String>) {
        let process_name = process_name.into();
        let blocked = is_private_context(&process_name, &process_name);
        self.active_processes.insert(
            pid,
            ProcessProfile {
                pid,
                process_name: process_name.clone(),
                sample_count: 0,
                runtime_source: RuntimeSignalSource::ProcessMonitor(pid),
            },
        );
        if !blocked {
            self.bus
                .publish(BusEvent::ProcessStarted(ProcessStartedEvent {
                    process_id: pid,
                    process_name,
                    timestamp: unix_timestamp(),
                }));
        }
    }

    pub fn sample_once(&mut self, pid: u32) -> Option<RuntimeSignalFrameEvent> {
        let frame = self.sample_process(pid)?;
        if is_private_context(&frame.process_name, &frame.process_name) {
            return None;
        }
        let active = self.match_frame_to_vault_anchors(&frame);
        let event = RuntimeSignalFrameEvent {
            process_id: frame.process_id,
            process_name: frame.process_name.clone(),
            timestamp: unix_timestamp(),
            cpu_per_anchor: active.cpu_distribution,
            memory_pattern: frame.memory_accesses.clone(),
            frame_timing_ms: frame.frame_time,
            active_anchors: active.ids,
            entropy_stream: frame.entropy,
        };
        self.bus
            .publish(BusEvent::RuntimeSignalFrame(event.clone()));
        if let Some(anomaly) = self.detect_anomaly(&event) {
            self.bus.publish(BusEvent::RuntimeAnomalyDetected(anomaly));
        }
        Some(event)
    }

    pub fn collect(&self, source: &str, content_hint: &str, bytes: Vec<u8>) {
        if is_private_context(source, content_hint)
            || contains_email_pattern(content_hint)
            || contains_password_field_pattern(content_hint)
        {
            return;
        }
        let memory_pattern = bytes
            .chunks(8)
            .map(|chunk| {
                let mut padded = [0u8; 8];
                let len = chunk.len().min(8);
                padded[..len].copy_from_slice(&chunk[..len]);
                u64::from_le_bytes(padded)
            })
            .collect::<Vec<_>>();
        let entropy_stream = if bytes.is_empty() {
            0.0
        } else {
            let mut counts = HashMap::<u8, usize>::new();
            for byte in &bytes {
                *counts.entry(*byte).or_insert(0) += 1;
            }
            let total = bytes.len() as f64;
            -counts
                .values()
                .map(|count| {
                    let probability = *count as f64 / total;
                    probability * probability.log2()
                })
                .sum::<f64>()
        };
        self.bus
            .publish(BusEvent::RuntimeSignalFrame(RuntimeSignalFrameEvent {
                process_id: deterministic_u32(source, content_hint),
                process_name: source.to_owned(),
                timestamp: unix_timestamp(),
                cpu_per_anchor: HashMap::new(),
                memory_pattern,
                frame_timing_ms: None,
                active_anchors: Vec::new(),
                entropy_stream,
            }));
    }

    fn sample_process(&mut self, pid: u32) -> Option<RawFrame> {
        let profile = self.active_processes.get_mut(&pid)?;
        profile.sample_count += 1;
        let phase = profile.sample_count as f64;
        let entropy = ((pid as f64 % 17.0) / 17.0 * 4.0) + ((phase.sin().abs()) * 3.5) + 0.5;
        let frame_time = Some((11.0 + (phase as f32 % 7.0) * 3.0).clamp(11.0, 40.0));
        let memory_accesses = vec![
            phase as u64 * 2,
            phase as u64 * 2 + (pid as u64 % 5),
            phase as u64 * 2 + (pid as u64 % 9),
        ];
        let active_anchors = vec![
            deterministic_uuid(pid, 0),
            deterministic_uuid(pid, profile.sample_count),
        ];
        Some(RawFrame {
            process_id: pid,
            process_name: profile.process_name.clone(),
            memory_accesses,
            frame_time,
            entropy,
            active_anchors,
        })
    }

    fn match_frame_to_vault_anchors(&self, frame: &RawFrame) -> ActiveAnchorSet {
        let mut cpu_distribution = HashMap::new();
        for (index, anchor_id) in frame.active_anchors.iter().enumerate() {
            cpu_distribution.insert(*anchor_id, (0.18 + index as f32 * 0.11).clamp(0.0, 1.0));
        }
        ActiveAnchorSet {
            ids: frame.active_anchors.clone(),
            cpu_distribution,
        }
    }

    fn detect_anomaly(&self, frame: &RuntimeSignalFrameEvent) -> Option<RuntimeAnomalyEvent> {
        if frame.entropy_stream >= 6.8 || frame.frame_timing_ms.unwrap_or_default() >= 33.0 {
            return Some(RuntimeAnomalyEvent {
                process_id: frame.process_id,
                process_name: frame.process_name.clone(),
                severity: ((frame.entropy_stream as f32 / 8.0)
                    + (frame.frame_timing_ms.unwrap_or(0.0) / 40.0))
                    .clamp(0.0, 1.0)
                    / 2.0,
                reason: "Entropie-Spike oder Timing-Einbruch im Laufzeitsignal".to_owned(),
                entropy_stream: frame.entropy_stream,
            });
        }
        None
    }
}

pub struct RuntimeOptimizer {
    vault: Arc<VaultAccessLayer>,
    bus: BusPublisher,
}

impl RuntimeOptimizer {
    pub fn new(vault: Arc<VaultAccessLayer>, bus: BusPublisher) -> Self {
        Self { vault, bus }
    }

    pub async fn analyze_frame(
        &self,
        frame: RuntimeSignalFrameEvent,
    ) -> Vec<RuntimeOptimizationEvent> {
        let mut optimizations = Vec::new();
        for anchor_id in &frame.active_anchors {
            let vault_ref = uuid_to_vault_ref(anchor_id);
            let vault_hit = matches!(self.vault.lookup_anchor(&vault_ref).await, Ok(Some(_)));
            let confidence = (((1.0 - (frame.entropy_stream as f32 / 8.0).clamp(0.0, 1.0)) * 0.6)
                + 0.4)
                .clamp(0.0, 1.0);
            // Laufzeitoptimierungen duerfen auch dann vorgeschlagen werden, wenn das Muster
            // strukturell stabil ist, aber noch nicht 1:1 als Vault-Ref vorliegt.
            if vault_hit || confidence >= 0.72 {
                let optimization = RuntimeOptimizationEvent {
                    process_id: frame.process_id,
                    anchor_id: *anchor_id,
                    vault_match: *anchor_id,
                    optimization_type: if vault_hit {
                        OptimizationType::CacheSubstitution
                    } else {
                        OptimizationType::ExecutionReorder
                    },
                    estimated_gain_percent: (confidence * 18.0).clamp(2.0, 18.0),
                    confidence,
                };
                self.bus
                    .publish(BusEvent::RuntimeOptimizationAvailable(optimization.clone()));
                optimizations.push(optimization);
            }
        }
        optimizations
    }
}

#[derive(Debug, Clone)]
pub struct RawPattern {
    pub anchor_id: Uuid,
    pub domain: String,
    pub similarity: f32,
}

impl RawPattern {
    pub fn matches_anchor(&self, write: &VaultWriteEvent) -> bool {
        self.domain == write.domain || self.anchor_id == write.anchor_id || self.similarity >= 0.8
    }
}

#[derive(Debug, Clone, Default)]
pub struct LanguageContext {
    pub last_cluster: Option<String>,
    pub total_clusters: usize,
}

#[derive(Debug, Clone)]
pub struct ProcessContext {
    pub pid: u32,
    pub name: String,
    pub known_anchors: Vec<Uuid>,
    pub unknown_patterns: Vec<RawPattern>,
    pub current_trust_score: f32,
    pub optimization_history: Vec<ShanwayOptimizationEvent>,
    pub frame_count: u64,
}

pub struct ShanwayCoordinator {
    bus_publisher: BusPublisher,
    pub active_processes: HashMap<u32, ProcessContext>,
    pub pending_optimizations: Vec<RuntimeOptimizationEvent>,
    pub language_context: LanguageContext,
    pub gap_queue: Vec<VaultGapEvent>,
}

impl ShanwayCoordinator {
    pub fn new(bus_publisher: BusPublisher) -> Self {
        Self {
            bus_publisher,
            active_processes: HashMap::new(),
            pending_optimizations: Vec::new(),
            language_context: LanguageContext::default(),
            gap_queue: Vec::new(),
        }
    }

    pub fn handle_event(&mut self, event: BusEvent) -> Vec<BusEvent> {
        let mut outputs = Vec::new();
        match event {
            BusEvent::RuntimeSignalFrame(frame) => {
                self.update_process_context(&frame);
                if frame.entropy_stream >= 6.8 {
                    let gap = VaultGapEvent {
                        domain: "runtime".to_owned(),
                        gap_magnitude: (frame.entropy_stream as f32 / 8.0).clamp(0.0, 1.0),
                        description: format!(
                            "Unbekanntes Laufzeitsignal in {}",
                            frame.process_name
                        ),
                        process_id: Some(frame.process_id),
                    };
                    self.gap_queue.push(gap.clone());
                    outputs.push(BusEvent::VaultGapDetected(gap));
                }
            }
            BusEvent::RuntimeOptimizationAvailable(opt) => {
                if opt.confidence >= 0.65 {
                    let applied = ShanwayOptimizationEvent {
                        process_id: opt.process_id,
                        optimization_type: opt.optimization_type,
                        applied: true,
                        confidence: opt.confidence,
                        note: format!("Optimierung fuer Prozess {} freigegeben", opt.process_id),
                    };
                    if let Some(context) = self.active_processes.get_mut(&opt.process_id) {
                        context.optimization_history.push(applied.clone());
                    }
                    outputs.push(BusEvent::ShanwayOptimizationApplied(applied.clone()));
                    outputs.push(BusEvent::ShanwayUserMessage(ShanwayUserMessageEvent {
                        process_id: Some(opt.process_id),
                        message: format!(
                            "Shanway erkennt eine Laufzeitoptimierung: {:?} mit {:.1}% Gewinn.",
                            opt.optimization_type, opt.estimated_gain_percent
                        ),
                        trust_score: opt.confidence,
                        action_available: true,
                    }));
                } else {
                    self.pending_optimizations.push(opt);
                }
            }
            BusEvent::VaultWrite(write) => {
                outputs.extend(self.check_new_anchor_for_runtime_gain(&write));
            }
            BusEvent::SemanticClusterFormed(cluster) => {
                self.language_context.last_cluster = Some(cluster.label_hint.clone());
                self.language_context.total_clusters += 1;
                outputs.extend(self.correlate_language_with_runtime(&cluster));
            }
            BusEvent::RuntimeAnomalyDetected(anomaly) => {
                if anomaly.severity > 0.8 {
                    outputs.push(BusEvent::ShanwayUserMessage(ShanwayUserMessageEvent {
                        process_id: Some(anomaly.process_id),
                        message: format!(
                            "Kritische Laufzeitanomalie in {} erkannt: {}",
                            anomaly.process_name, anomaly.reason
                        ),
                        trust_score: anomaly.severity,
                        action_available: false,
                    }));
                }
            }
            _ => {}
        }
        for outgoing in &outputs {
            self.bus_publisher.publish(outgoing.clone());
        }
        outputs
    }

    fn update_process_context(&mut self, frame: &RuntimeSignalFrameEvent) {
        let context = self
            .active_processes
            .entry(frame.process_id)
            .or_insert(ProcessContext {
                pid: frame.process_id,
                name: frame.process_name.clone(),
                known_anchors: Vec::new(),
                unknown_patterns: Vec::new(),
                current_trust_score: 0.0,
                optimization_history: Vec::new(),
                frame_count: 0,
            });
        context.frame_count += 1;
        context.current_trust_score = (1.0 - (frame.entropy_stream as f32 / 8.0)).clamp(0.0, 1.0);
        context.known_anchors = frame.active_anchors.clone();
        if frame.entropy_stream >= 6.8 {
            context.unknown_patterns.push(RawPattern {
                anchor_id: deterministic_uuid(frame.process_id, context.frame_count),
                domain: "runtime".to_owned(),
                similarity: 0.82,
            });
        }
    }

    fn check_new_anchor_for_runtime_gain(&self, write: &VaultWriteEvent) -> Vec<BusEvent> {
        let mut outputs = Vec::new();
        for (pid, context) in &self.active_processes {
            if context
                .unknown_patterns
                .iter()
                .any(|pattern| pattern.matches_anchor(write))
            {
                outputs.push(BusEvent::RuntimeOptimizationAvailable(
                    RuntimeOptimizationEvent {
                        process_id: *pid,
                        anchor_id: write.anchor_id,
                        vault_match: write.anchor_id,
                        optimization_type: OptimizationType::CacheSubstitution,
                        estimated_gain_percent: (write.coverage_improvement * 100.0)
                            .clamp(1.0, 25.0),
                        confidence: write.trust_score,
                    },
                ));
            }
        }
        outputs
    }

    fn correlate_language_with_runtime(&self, cluster: &SemanticClusterEvent) -> Vec<BusEvent> {
        self.active_processes
            .iter()
            .map(|(pid, context)| {
                BusEvent::ShanwayUserMessage(ShanwayUserMessageEvent {
                    process_id: Some(*pid),
                    message: format!(
                        "Prozess '{}' korreliert mit Sprach-Cluster '{}' (Confidence {:.2}).",
                        context.name, cluster.label_hint, cluster.confidence
                    ),
                    trust_score: cluster.confidence,
                    action_available: cluster.confidence >= 0.65,
                })
            })
            .collect()
    }
}

fn deterministic_uuid(pid: u32, salt: u64) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(pid.to_le_bytes());
    hasher.update(salt.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

fn deterministic_u32(source: &str, content_hint: &str) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    hasher.update(content_hint.as_bytes());
    let digest = hasher.finalize();
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn uuid_to_vault_ref(anchor_id: &Uuid) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(anchor_id.as_bytes());
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest[..32]);
    output
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aef::{EnginePipeline, SignalType, VaultStore};
    use crate::inter_layer_bus::{InterLayerBus, VaultWriteEvent};
    use crate::vault_access::{RawAnchorSubmission, SubmissionSource, VaultAccessLayer};
    use std::sync::{Arc, RwLock};

    #[tokio::test]
    async fn runtime_optimizer_emits_when_anchor_known() {
        let bus = InterLayerBus::new(32);
        let vault = Arc::new(RwLock::new(VaultStore::default()));
        let pipeline = Arc::new(EnginePipeline::new());
        let access = Arc::new(VaultAccessLayer::new(
            Arc::clone(&vault),
            Arc::clone(&pipeline),
        ));
        let anchor_id = deterministic_uuid(41, 0);
        let submission = RawAnchorSubmission {
            anchor_id,
            signal_type: SignalType::Unknown,
            domain: "runtime".to_owned(),
            pi_positions: vec![3, 14],
            frequency_signature: vec![0.4, 0.6],
            fractal_dimension: 1.1,
            entropy_profile: 2.8,
            benford_score: 0.9,
            zipf_alpha: 1.1,
            coherence_index: 0.82,
            lossless_confirmed: true,
        };
        let _ = access
            .submit_anchor(submission, SubmissionSource::GitHubPR)
            .await
            .unwrap();
        let optimizer = RuntimeOptimizer::new(Arc::clone(&access), bus.publisher());
        let frame = RuntimeSignalFrameEvent {
            process_id: 41,
            process_name: "demo".to_owned(),
            timestamp: 0,
            cpu_per_anchor: HashMap::new(),
            memory_pattern: vec![1, 2, 3],
            frame_timing_ms: Some(16.0),
            active_anchors: vec![anchor_id],
            entropy_stream: 1.2,
        };
        let optimizations = optimizer.analyze_frame(frame).await;
        assert!(!optimizations.is_empty());
    }

    #[test]
    fn coordinator_promotes_runtime_gap() {
        let bus = InterLayerBus::new(32);
        let mut coordinator = ShanwayCoordinator::new(bus.publisher());
        let outputs =
            coordinator.handle_event(BusEvent::RuntimeSignalFrame(RuntimeSignalFrameEvent {
                process_id: 9,
                process_name: "game.exe".to_owned(),
                timestamp: 0,
                cpu_per_anchor: HashMap::new(),
                memory_pattern: vec![3, 5, 8],
                frame_timing_ms: Some(38.0),
                active_anchors: vec![Uuid::new_v4()],
                entropy_stream: 7.2,
            }));
        assert!(outputs
            .iter()
            .any(|event| matches!(event, BusEvent::VaultGapDetected(_))));
        let write_event = VaultWriteEvent {
            anchor_id: Uuid::new_v4(),
            domain: "runtime".to_owned(),
            trust_score: 0.81,
            coverage_improvement: 0.14,
        };
        let follow_up = coordinator.handle_event(BusEvent::VaultWrite(write_event));
        assert!(follow_up
            .iter()
            .any(|event| matches!(event, BusEvent::RuntimeOptimizationAvailable(_))));
    }

    #[test]
    fn privacy_boundary_blocks_private_contexts() {
        assert!(is_private_context("whatsapp_chat", ""));
        assert!(is_private_context("email_inbox", ""));
        assert!(is_private_context("", "password=abc123"));
        assert!(is_private_context("", "user@example.com"));
        assert!(!is_private_context("aether_vault", "anchor_data"));
        assert!(!is_private_context("game_renderer", "texture_load"));
    }

    #[test]
    fn collector_drops_private_process_events() {
        let bus = InterLayerBus::new(8);
        let publisher = bus.publisher();
        let mut collector = RuntimeSignalCollector::new(publisher);
        let mut subscriber = bus.subscriber();
        collector.attach_process(7, "whatsapp_chat");
        assert!(collector.sample_once(7).is_none());
        assert!(subscriber.try_recv().is_err());
    }
}
