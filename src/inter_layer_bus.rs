use crate::observation::{ObservationAction, QuarantineCategory};
use std::collections::HashMap;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum BusEvent {
    AnchorExtracted(AnchorExtractedEvent),
    AnchorCacheHit(AnchorCacheHitEvent),
    AnchorCacheMiss(AnchorCacheMissEvent),
    LosslessConfirmed(LosslessConfirmedEvent),
    RuntimeSignalFrame(RuntimeSignalFrameEvent),
    RuntimeAnomalyDetected(RuntimeAnomalyEvent),
    RuntimeOptimizationAvailable(RuntimeOptimizationEvent),
    ProcessStarted(ProcessStartedEvent),
    ProcessEnded(ProcessEndedEvent),
    LanguageAnchorExtracted(LanguageAnchorEvent),
    SemanticClusterFormed(SemanticClusterEvent),
    VaultGapDetectedByLanguage(VaultGapEvent),
    VaultGapDetected(VaultGapEvent),
    CrawlCompleted(CrawlCompletedEvent),
    FileRequestGenerated(FileRequestEvent),
    GapFilled(GapFilledEvent),
    VaultWrite(VaultWriteEvent),
    VaultSync(VaultSyncEvent),
    TrustScoreUpdated(TrustScoreEvent),
    ObservationEngineBlock(ObservationBlockEvent),
    ObservationEngineLearn(ObservationLearnEvent),
    ShanwayDecision(ShanwayDecisionEvent),
    ShanwayOptimizationApplied(ShanwayOptimizationEvent),
    ShanwayUserMessage(ShanwayUserMessageEvent),
}

#[derive(Debug, Clone)]
pub struct AnchorExtractedEvent {
    pub anchor_id: Uuid,
    pub domain: String,
    pub entropy: f64,
    pub symmetry: f64,
}

#[derive(Debug, Clone)]
pub struct AnchorCacheHitEvent {
    pub anchor_id: Uuid,
    pub vault_ref: [u8; 32],
    pub lookup_time_ms: f32,
}

#[derive(Debug, Clone)]
pub struct AnchorCacheMissEvent {
    pub anchor_id: Uuid,
    pub domain: String,
    pub novelty_score: f32,
}

#[derive(Debug, Clone)]
pub struct LosslessConfirmedEvent {
    pub anchor_id: Uuid,
    pub file_name: String,
    pub trust_score: f32,
    pub coverage: f32,
}

#[derive(Debug, Clone)]
pub struct RuntimeSignalFrameEvent {
    pub process_id: u32,
    pub process_name: String,
    pub timestamp: u64,
    pub cpu_per_anchor: HashMap<Uuid, f32>,
    pub memory_pattern: Vec<u64>,
    pub frame_timing_ms: Option<f32>,
    pub active_anchors: Vec<Uuid>,
    pub entropy_stream: f64,
}

#[derive(Debug, Clone)]
pub struct RuntimeAnomalyEvent {
    pub process_id: u32,
    pub process_name: String,
    pub severity: f32,
    pub reason: String,
    pub entropy_stream: f64,
}

#[derive(Debug, Clone)]
pub struct RuntimeOptimizationEvent {
    pub process_id: u32,
    pub anchor_id: Uuid,
    pub vault_match: Uuid,
    pub optimization_type: OptimizationType,
    pub estimated_gain_percent: f32,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizationType {
    CacheSubstitution,
    ExecutionReorder,
    MemoryPrefetch,
    DeltaCompression,
}

#[derive(Debug, Clone)]
pub struct ProcessStartedEvent {
    pub process_id: u32,
    pub process_name: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct ProcessEndedEvent {
    pub process_id: u32,
    pub process_name: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct LanguageAnchorEvent {
    pub anchor_id: Uuid,
    pub corpus: String,
    pub mutual_information: f32,
}

#[derive(Debug, Clone)]
pub struct SemanticClusterEvent {
    pub cluster_id: Uuid,
    pub label_hint: String,
    pub anchor_count: usize,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct VaultGapEvent {
    pub domain: String,
    pub gap_magnitude: f32,
    pub description: String,
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct CrawlCompletedEvent {
    pub source: String,
    pub new_anchor_count: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone)]
pub struct FileRequestEvent {
    pub domain: String,
    pub priority: f32,
    pub rationale: String,
}

#[derive(Debug, Clone)]
pub struct GapFilledEvent {
    pub domain: String,
    pub anchor_id: Uuid,
    pub improvement: f32,
}

#[derive(Debug, Clone)]
pub struct VaultWriteEvent {
    pub anchor_id: Uuid,
    pub domain: String,
    pub trust_score: f32,
    pub coverage_improvement: f32,
}

#[derive(Debug, Clone)]
pub struct VaultSyncEvent {
    pub anchors_synced: usize,
    pub anchors_rejected: usize,
    pub new_vault_size: usize,
    pub estimated_hit_rate_improvement: f32,
    pub estimated_compression_improvement: f32,
}

#[derive(Debug, Clone)]
pub struct TrustScoreEvent {
    pub subject: String,
    pub score: f32,
    pub flags: u64,
}

#[derive(Debug, Clone)]
pub struct ObservationBlockEvent {
    pub category: QuarantineCategory,
    pub confidence: f32,
    pub action: ObservationAction,
}

#[derive(Debug, Clone)]
pub struct ObservationLearnEvent {
    pub category: QuarantineCategory,
    pub is_new_pattern: bool,
}

#[derive(Debug, Clone)]
pub struct ShanwayDecisionEvent {
    pub process_id: Option<u32>,
    pub summary: String,
    pub confidence: f32,
    pub action_requested: bool,
}

#[derive(Debug, Clone)]
pub struct ShanwayOptimizationEvent {
    pub process_id: u32,
    pub optimization_type: OptimizationType,
    pub applied: bool,
    pub confidence: f32,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct ShanwayUserMessageEvent {
    pub process_id: Option<u32>,
    pub message: String,
    pub trust_score: f32,
    pub action_available: bool,
}

pub struct InterLayerBus {
    sender: broadcast::Sender<BusEvent>,
}

impl InterLayerBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(16));
        Self { sender }
    }

    pub fn publisher(&self) -> BusPublisher {
        BusPublisher {
            sender: self.sender.clone(),
        }
    }

    pub fn subscriber(&self) -> broadcast::Receiver<BusEvent> {
        self.sender.subscribe()
    }
}

#[derive(Clone)]
pub struct BusPublisher {
    sender: broadcast::Sender<BusEvent>,
}

impl BusPublisher {
    pub fn publish(&self, event: BusEvent) {
        let _ = self.sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_publishes_events() {
        let bus = InterLayerBus::new(32);
        let publisher = bus.publisher();
        let mut subscriber = bus.subscriber();
        let anchor_id = Uuid::new_v4();
        publisher.publish(BusEvent::AnchorExtracted(AnchorExtractedEvent {
            anchor_id,
            domain: "tests".to_owned(),
            entropy: 3.5,
            symmetry: 0.72,
        }));
        let event = subscriber.try_recv().expect("event missing");
        match event {
            BusEvent::AnchorExtracted(payload) => assert_eq!(payload.anchor_id, anchor_id),
            other => panic!("unexpected event: {other:?}"),
        }
    }
}
