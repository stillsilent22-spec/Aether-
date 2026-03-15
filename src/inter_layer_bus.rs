use crate::observation::{ObservationAction, QuarantineCategory};
use serde::{Deserialize, Serialize};
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
    VramPressureChanged(VramPressureEvent),
    TextureUploadRequested(TextureUploadRequestEvent),
    TextureUploadCompleted(TextureUploadResultEvent),
    ShaderCompileRequested(ShaderCompileRequestEvent),
    ShaderCacheHit(ShaderCacheHitEvent),
    VramOptimized(VramOptimizedEvent),
    VramEvictionRequired(VramEvictionEvent),
    FrameStarted(FrameStartedEvent),
    FrameCompleted(FrameCompletedEvent),
    FrameDropDetected(FrameDropEvent),
    RenderBottleneckDetected(BottleneckEvent),
    WorkflowAnchorHit(WorkflowHitEvent),
    WorkflowAnchorLearned(WorkflowLearnedEvent),
    WorkflowOptimizationExecuted(WorkflowOptEvent),
    CrossProgramVramReuse(CrossProgramReuseEvent),
    ShanwayVramDecision(VramDecisionEvent),
    PackRecommended(PackRecommendedEvent),
    PackDownloadConfirmed(PackDownloadEvent),
    PackInstalled(PackInstalledEvent),
    OfflineCachePrepared(OfflineCacheEvent),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VramPressureEvent {
    pub used_mb: f32,
    pub total_mb: f32,
    pub pressure_ratio: f32,
    pub pressure_level: VramPressureLevel,
    pub active_programs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VramPressureLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextureUploadRequestEvent {
    pub program_id: String,
    pub texture_label: String,
    pub byte_size: usize,
    pub expected_vram_mb: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextureUploadResultEvent {
    pub program_id: String,
    pub texture_label: String,
    pub handle: u64,
    pub uploaded_mb: f32,
    pub used_delta_path: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaderCompileRequestEvent {
    pub program_id: String,
    pub shader_hash: String,
    pub stage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaderCacheHitEvent {
    pub program_id: String,
    pub shader_hash: String,
    pub handle: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameStartedEvent {
    pub program_id: String,
    pub frame_index: u64,
    pub expected_fps: f32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameCompletedEvent {
    pub program_id: String,
    pub frame_index: u64,
    pub frame_time_ms: f32,
    pub presented: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameDropEvent {
    pub program_id: String,
    pub expected_fps: f32,
    pub actual_fps: f32,
    pub frame_time_ms: f32,
    pub suspected_cause: FrameDropCause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrameDropCause {
    VramPressure,
    ShaderCompileStall,
    TextureUploadStall,
    CpuBottleneck,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BottleneckEvent {
    pub program_id: String,
    pub bottleneck: String,
    pub severity: f32,
    pub frame_time_ms: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowHitEvent {
    pub anchor_hash: String,
    pub program_id: String,
    pub known_outcome: String,
    pub optimization_type: String,
    pub confidence: f32,
    pub hit_count: u32,
    pub expected_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowLearnedEvent {
    pub anchor_hash: String,
    pub program_id: String,
    pub context: String,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowOptEvent {
    pub anchor_hash: String,
    pub program_id: String,
    pub optimization_type: String,
    pub expected_gain_percent: f32,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProgramReuseEvent {
    pub anchor_hash: String,
    pub source_program: String,
    pub target_program: String,
    pub vram_saved_mb: f32,
    pub similarity: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VramDecisionEvent {
    pub decision_type: VramDecisionType,
    pub affected_program: String,
    pub reasoning: String,
    pub vram_delta_mb: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VramDecisionType {
    EvictTexture,
    PreloadTexture,
    DeferShaderCompile,
    ReallocateBudget,
    CrossProgramShare,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VramOptimizedEvent {
    pub texture_label: String,
    pub original_mb: f32,
    pub compressed_mb: f32,
    pub vault_hit_rate: f32,
    pub compression_ratio: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VramEvictionEvent {
    pub program_id: String,
    pub reclaimed_mb: f32,
    pub reason: String,
    pub evicted_labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackRecommendedEvent {
    pub pack_id: String,
    pub pack_name: String,
    pub domain: String,
    pub size_mb: f32,
    pub estimated_hit_rate_improvement: f32,
    pub cooldown_respected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackDownloadEvent {
    pub pack_id: String,
    pub confirmed_by_user: bool,
    pub started_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackInstalledEvent {
    pub pack_id: String,
    pub pack_name: String,
    pub installed_anchor_count: usize,
    pub hit_rate_delta: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineCacheEvent {
    pub activities: Vec<String>,
    pub cache_size_mb: f32,
    pub anchor_count: usize,
    pub coverage_by_activity: Vec<(String, f32)>,
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
    pub fn noop() -> Self {
        InterLayerBus::new(16).publisher()
    }

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
