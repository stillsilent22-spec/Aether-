use crate::inter_layer_bus::{
    BusEvent, BusPublisher, CrossProgramReuseEvent, WorkflowHitEvent, WorkflowLearnedEvent,
};
use crate::priority::LogarithmicPriority;
use crate::vault_access::VaultAccessLayer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowAnchor {
    pub anchor_hash: String,
    pub context: String,
    pub sequence_entropy: f32,
    pub timing_pattern: Vec<f32>,
    pub fractal_dimension: f32,
    pub dominant_period_ms: f32,
    pub outcome: WorkflowOutcome,
    pub duration_ms: u64,
    pub best_optimization: WorkflowOptimization,
    pub confidence: f32,
    pub hit_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowOutcome {
    Smooth,
    FrameDrop(f32),
    Stall(u64),
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowOptimization {
    PreloadAt(f32),
    EvictAt(f32),
    DeferShaderCompile,
    NoOptimizationNeeded,
}

#[derive(Debug, Clone)]
pub struct TimedEvent {
    pub timestamp_ms: u64,
    pub event_type: String,
    pub delta_from_prev_ms: u64,
}

pub struct WorkflowSignalCollector {
    active_workflows: HashMap<String, Vec<TimedEvent>>,
    vault: Arc<VaultAccessLayer>,
    bus: BusPublisher,
    idle_timeout_ms: u64,
}

impl WorkflowSignalCollector {
    pub fn new(vault: Arc<VaultAccessLayer>, bus: BusPublisher) -> Self {
        Self {
            active_workflows: HashMap::new(),
            vault,
            bus,
            idle_timeout_ms: 2_000,
        }
    }

    pub async fn ingest_event(&mut self, program_id: &str, event_type: &str, timestamp_ms: u64) {
        let idle_timeout_ms = self.idle_timeout_ms;
        let should_complete = {
            let events = self
                .active_workflows
                .entry(program_id.to_string())
                .or_default();
            let delta = events
                .last()
                .map(|entry| timestamp_ms.saturating_sub(entry.timestamp_ms))
                .unwrap_or(0);
            events.push(TimedEvent {
                timestamp_ms,
                event_type: event_type.to_string(),
                delta_from_prev_ms: delta,
            });
            Self::is_complete(events, idle_timeout_ms)
        };
        if should_complete {
            let completed = self.active_workflows.remove(program_id).unwrap_or_default();
            self.process_workflow(program_id, &completed).await;
        }
    }

    pub async fn complete_program(&mut self, program_id: &str) {
        let completed = self.active_workflows.remove(program_id).unwrap_or_default();
        self.process_workflow(program_id, &completed).await;
    }

    fn is_complete(events: &[TimedEvent], idle_timeout_ms: u64) -> bool {
        if let Some(last) = events.last() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|delta| delta.as_millis() as u64)
                .unwrap_or(0);
            now.saturating_sub(last.timestamp_ms) > idle_timeout_ms
        } else {
            false
        }
    }

    async fn process_workflow(&self, program_id: &str, events: &[TimedEvent]) {
        if events.is_empty() {
            return;
        }
        let anchor = self.extract_anchor(program_id, events);
        if let Some(mut known) = self.vault.lookup_workflow_anchor(&anchor.anchor_hash).await {
            let proactive =
                LogarithmicPriority::should_act_proactively(known.hit_count, known.confidence);
            known.confidence = LogarithmicPriority::compute(known.confidence, known.hit_count);
            self.bus
                .publish(BusEvent::WorkflowAnchorHit(WorkflowHitEvent {
                    anchor_hash: anchor.anchor_hash.clone(),
                    program_id: program_id.to_string(),
                    known_outcome: format!("{:?}", known.outcome),
                    optimization_type: format!("{:?}", known.best_optimization),
                    confidence: known.confidence,
                    hit_count: known.hit_count,
                    expected_duration_ms: known.duration_ms,
                }));
            if proactive {
                for similar in self.vault.find_similar_workflows(&anchor, 0.92).await {
                    if similar.context == anchor.context {
                        continue;
                    }
                    self.bus
                        .publish(BusEvent::CrossProgramVramReuse(CrossProgramReuseEvent {
                            anchor_hash: similar.anchor_hash.clone(),
                            source_program: similar.context.clone(),
                            target_program: program_id.to_string(),
                            vram_saved_mb: (similar.hit_count as f32 * 0.25).clamp(0.0, 64.0),
                            similarity: cosine_similarity(
                                &[anchor.sequence_entropy, anchor.fractal_dimension],
                                &[similar.sequence_entropy, similar.fractal_dimension],
                            ),
                        }));
                }
            }
        } else {
            self.vault.store_workflow_anchor(&anchor).await;
            self.bus
                .publish(BusEvent::WorkflowAnchorLearned(WorkflowLearnedEvent {
                    anchor_hash: anchor.anchor_hash.clone(),
                    program_id: program_id.to_string(),
                    context: anchor.context.clone(),
                    event_count: events.len(),
                }));
        }
    }

    fn extract_anchor(&self, program_id: &str, events: &[TimedEvent]) -> WorkflowAnchor {
        let entropy = self.sequence_entropy(events);
        let timing = self.normalized_timing(events);
        let fractal = self.timing_fractal_dimension(&timing);
        let duration = events
            .last()
            .map(|entry| entry.timestamp_ms)
            .unwrap_or(0)
            .saturating_sub(events.first().map(|entry| entry.timestamp_ms).unwrap_or(0));
        let sig = format!("{entropy:.3}|{fractal:.3}|{program_id}");
        let anchor_hash = format!("{:x}", md5::compute(sig.as_bytes()));
        WorkflowAnchor {
            anchor_hash,
            context: program_id.to_string(),
            sequence_entropy: entropy,
            timing_pattern: timing,
            fractal_dimension: fractal,
            dominant_period_ms: self.dominant_period(events),
            outcome: WorkflowOutcome::Completed,
            duration_ms: duration,
            best_optimization: WorkflowOptimization::NoOptimizationNeeded,
            confidence: 0.5,
            hit_count: 1,
        }
    }

    fn sequence_entropy(&self, events: &[TimedEvent]) -> f32 {
        if events.is_empty() {
            return 0.0;
        }
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for event in events {
            *counts.entry(event.event_type.as_str()).or_insert(0) += 1;
        }
        let total = events.len() as f32;
        -counts
            .values()
            .map(|count| {
                let probability = *count as f32 / total;
                probability * probability.log2()
            })
            .sum::<f32>()
    }

    fn normalized_timing(&self, events: &[TimedEvent]) -> Vec<f32> {
        let deltas: Vec<f32> = events
            .iter()
            .map(|event| event.delta_from_prev_ms as f32)
            .collect();
        let max = deltas.iter().copied().fold(0.0_f32, f32::max);
        if max < 1.0 {
            return deltas;
        }
        deltas.iter().map(|value| value / max).collect()
    }

    fn timing_fractal_dimension(&self, timing: &[f32]) -> f32 {
        if timing.len() < 2 {
            return 1.0;
        }
        let diffs: Vec<f32> = timing
            .windows(2)
            .map(|window| (window[1] - window[0]).abs())
            .collect();
        let length: f32 = diffs.iter().sum();
        let distance: f32 = diffs.iter().copied().fold(0.0_f32, f32::max);
        if distance < 1e-9 || length < 1e-9 {
            return 1.0;
        }
        let n = timing.len() as f32;
        n.log10() / ((distance / length) + n).log10()
    }

    fn dominant_period(&self, events: &[TimedEvent]) -> f32 {
        if events.len() < 2 {
            return 0.0;
        }
        let total: u64 = events.iter().map(|event| event.delta_from_prev_ms).sum();
        total as f32 / events.len() as f32
    }
}

fn cosine_similarity(left: &[f32], right: &[f32]) -> f32 {
    if left.len() != right.len() || left.is_empty() {
        return 0.0;
    }
    let dot: f32 = left.iter().zip(right.iter()).map(|(a, b)| a * b).sum();
    let norm_left: f32 = left.iter().map(|value| value * value).sum::<f32>().sqrt();
    let norm_right: f32 = right.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm_left < 1e-6 || norm_right < 1e-6 {
        return 0.0;
    }
    (dot / (norm_left * norm_right)).clamp(0.0, 1.0)
}
