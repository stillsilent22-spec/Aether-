//! Local-only safety check for image attachments in a messenger client.
//! 
//! Architecture:
//! - `fingerprint.rs` computes a deterministic perceptual hash from image bytes.
//! - `zk_match.rs` compares only non-reversible structural fingerprints against a local set.
//! - `policy.rs` maps exact and near matches to `Allow`, `Suspicious`, or `Block`.
//! - `api.rs` exposes a narrow client-facing API with no network access and no content storage.
//! 
//! Privacy guarantees:
//! - Only perceptual hashes are derived from the input bytes.
//! - No semantic analysis of text or image meaning is performed.
//! - No raw bytes, images, messages, or hashes are sent to any server.
//! - No content is persisted; processing happens on the caller-provided bytes in memory.
//! - Optional audit records contain only timestamp and decision, never content or fingerprints.

use crate::fingerprint::{perceptual_hash, FingerprintError};
use crate::policy::{decide, SafetyConfig, SafetyDecision};
use crate::zk_match::{KnownBadSet, KnownBadSetError};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEntry {
    pub unix_timestamp_secs: u64,
    pub decision: SafetyDecision,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionCounts {
    pub allow: u64,
    pub suspicious: u64,
    pub block: u64,
}

#[derive(Debug, Default)]
pub struct AuditLog {
    enabled: bool,
    entries: Mutex<Vec<AuditEntry>>,
    counts: Mutex<DecisionCounts>,
}

impl AuditLog {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            entries: Mutex::new(Vec::new()),
            counts: Mutex::new(DecisionCounts::default()),
        }
    }

    pub fn snapshot(&self) -> Vec<AuditEntry> {
        self.entries.lock().expect("audit log poisoned").clone()
    }

    pub fn counts(&self) -> DecisionCounts {
        *self.counts.lock().expect("audit counts poisoned")
    }

    fn record(&self, decision: SafetyDecision) {
        let mut counts = self.counts.lock().expect("audit counts poisoned");
        match decision {
            SafetyDecision::Allow => counts.allow += 1,
            SafetyDecision::Suspicious => counts.suspicious += 1,
            SafetyDecision::Block => counts.block += 1,
        }
        drop(counts);

        if self.enabled {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            self.entries
                .lock()
                .expect("audit log poisoned")
                .push(AuditEntry {
                    unix_timestamp_secs: ts,
                    decision,
                });
        }
    }
}

#[derive(Clone)]
pub struct SafetyContext {
    pub known_bad_set: Arc<KnownBadSet>,
    pub config: SafetyConfig,
    pub audit_log: Option<Arc<AuditLog>>,
}

impl SafetyContext {
    pub fn new(known_bad_set: KnownBadSet, config: SafetyConfig) -> Self {
        Self {
            known_bad_set: Arc::new(known_bad_set),
            config,
            audit_log: None,
        }
    }

    pub fn with_audit_log(mut self, audit_log: Arc<AuditLog>) -> Self {
        self.audit_log = Some(audit_log);
        self
    }

    pub fn from_local_known_bad_path(
        path: &Path,
        config: SafetyConfig,
    ) -> Result<Self, KnownBadSetError> {
        Ok(Self::new(KnownBadSet::load_from_path(path)?, config))
    }
}

pub fn check_image(bytes: &[u8], ctx: &SafetyContext) -> SafetyDecision {
    let decision = match perceptual_hash(bytes) {
        Ok(fingerprint) => decide(fingerprint, &ctx.known_bad_set, ctx.config),
        Err(FingerprintError::EmptyInput | FingerprintError::DecodeFailed) => {
            SafetyDecision::Suspicious
        }
    };

    if let Some(audit_log) = &ctx.audit_log {
        audit_log.record(decision);
    }

    decision
}

pub fn check_outbound_image_attachment(bytes: &[u8], ctx: &SafetyContext) -> SafetyDecision {
    check_image(bytes, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::perceptual_hash;
    use image::{DynamicImage, ImageBuffer, ImageFormat, Rgba};
    use std::io::Cursor;

    fn image_bytes(seed: u8) -> Vec<u8> {
        let image = ImageBuffer::from_fn(32, 32, |x, y| {
            let value = seed.wrapping_add((x as u8).wrapping_mul(3)).wrapping_add((y as u8).wrapping_mul(5));
            Rgba([value, value.saturating_add(4), value.saturating_add(9), 255])
        });
        let dynamic = DynamicImage::ImageRgba8(image);
        let mut out = Cursor::new(Vec::new());
        dynamic
            .write_to(&mut out, ImageFormat::Png)
            .expect("png encode should succeed");
        out.into_inner()
    }

    #[test]
    fn api_blocks_exact_known_bad_hash() {
        let bad_image = image_bytes(7);
        let bad_hash = perceptual_hash(&bad_image).expect("hash should succeed");
        let ctx = SafetyContext::new(KnownBadSet::new([bad_hash]), SafetyConfig::default());
        assert_eq!(check_image(&bad_image, &ctx), SafetyDecision::Block);
    }

    #[test]
    fn api_audit_counts_are_anonymized() {
        let bad_image = image_bytes(11);
        let bad_hash = perceptual_hash(&bad_image).expect("hash should succeed");
        let audit = Arc::new(AuditLog::new(true));
        let ctx = SafetyContext::new(KnownBadSet::new([bad_hash]), SafetyConfig::default())
            .with_audit_log(Arc::clone(&audit));

        let decision = check_image(&bad_image, &ctx);
        assert_eq!(decision, SafetyDecision::Block);
        assert_eq!(audit.counts().block, 1);
        let entries = audit.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].decision, SafetyDecision::Block);
    }

    #[test]
    fn malformed_input_returns_suspicious_without_content_logging() {
        let ctx = SafetyContext::new(KnownBadSet::new([]), SafetyConfig::default());
        assert_eq!(check_image(b"not-an-image", &ctx), SafetyDecision::Suspicious);
    }

    #[test]
    fn outbound_attachment_check_uses_same_policy_boundary() {
        let bad_image = image_bytes(19);
        let bad_hash = perceptual_hash(&bad_image).expect("hash should succeed");
        let ctx = SafetyContext::new(KnownBadSet::new([bad_hash]), SafetyConfig::default());
        assert_eq!(
            check_outbound_image_attachment(&bad_image, &ctx),
            SafetyDecision::Block
        );
    }
}