use crate::inter_layer_bus::{BusEvent, BusPublisher, OfflineCacheEvent, ShanwayUserMessageEvent};
use crate::vault_access::VaultAccessLayer;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

pub struct OfflineCacheManager {
    vault: Arc<VaultAccessLayer>,
    cache_dir: PathBuf,
    bus: BusPublisher,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflinePrepRequest {
    pub planned_activities: Vec<String>,
    pub available_cache_mb: u64,
    pub target: CacheTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheTarget {
    LocalCache,
    ExternalDrive(PathBuf),
}

impl OfflineCacheManager {
    pub fn new(vault: Arc<VaultAccessLayer>, cache_dir: PathBuf, bus: BusPublisher) -> Self {
        Self { vault, cache_dir, bus }
    }

    pub async fn prepare_offline_cache(
        &self,
        request: OfflinePrepRequest,
        user_confirmed: bool,
    ) -> Result<(), String> {
        if !user_confirmed {
            return Err("UserConfirmationRequired".to_owned());
        }

        let mut total_anchors = 0usize;
        let mut coverage: Vec<(String, f32)> = Vec::new();
        for activity in &request.planned_activities {
            let anchors = self.find_anchors_for_activity(activity).await;
            let activity_coverage = if anchors.is_empty() {
                0.0
            } else {
                (anchors.len() as f32 / 100.0).min(1.0)
            };
            coverage.push((activity.clone(), activity_coverage));
            total_anchors += anchors.len();
            let cache_path = match &request.target {
                CacheTarget::LocalCache => self.cache_dir.clone(),
                CacheTarget::ExternalDrive(path) => path.clone(),
            };
            self.write_anchor_cache(&anchors, &cache_path, activity).await;
        }

        let cache_size_mb = total_anchors as f32 * 0.032;
        self.bus.publish(BusEvent::OfflineCachePrepared(OfflineCacheEvent {
            activities: request.planned_activities.clone(),
            cache_size_mb,
            anchor_count: total_anchors,
            coverage_by_activity: coverage.clone(),
        }));

        let coverage_str = coverage
            .iter()
            .map(|(activity, ratio)| format!("  {activity} -> {:.0}%", ratio * 100.0))
            .collect::<Vec<_>>()
            .join("\n");
        self.bus.publish(BusEvent::ShanwayUserMessage(ShanwayUserMessageEvent {
            process_id: None,
            message: format!(
                "Offline-Cache bereit fuer: {}\nAnker: {} | Groesse: ~{:.1} MB\n\nAbdeckung:\n{}",
                request.planned_activities.join(", "),
                total_anchors,
                cache_size_mb,
                coverage_str
            ),
            trust_score: 0.75,
            action_available: false,
        }));

        Ok(())
    }

    async fn find_anchors_for_activity(&self, activity: &str) -> Vec<String> {
        self.vault
            .find_anchors_by_domain(activity)
            .await
            .unwrap_or_default()
    }

    async fn write_anchor_cache(&self, anchors: &[String], cache_path: &PathBuf, label: &str) {
        let _ = tokio::fs::create_dir_all(cache_path).await;
        let cache_file = cache_path.join(format!("{label}.cache.json"));
        let content = serde_json::to_string_pretty(anchors).unwrap_or_else(|_| "[]".to_owned());
        let _ = tokio::fs::write(cache_file, content).await;
    }
}
