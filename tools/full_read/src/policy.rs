use crate::fingerprint::ImageFingerprint;
use crate::zk_match::{match_fingerprint, KnownBadSet, MatchResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyDecision {
    Allow,
    Suspicious,
    Block,
}

#[derive(Debug, Clone, Copy)]
pub struct SafetyConfig {
    pub near_match_threshold: u32,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            near_match_threshold: 8,
        }
    }
}

pub fn decide(
    fingerprint: ImageFingerprint,
    known_bad_set: &KnownBadSet,
    config: SafetyConfig,
) -> SafetyDecision {
    match match_fingerprint(fingerprint, known_bad_set, config.near_match_threshold) {
        MatchResult::Exact => SafetyDecision::Block,
        MatchResult::Near { .. } => SafetyDecision::Suspicious,
        MatchResult::None => SafetyDecision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_blocks() {
        let set = KnownBadSet::new([42u128]);
        let decision = decide(42u128, &set, SafetyConfig::default());
        assert_eq!(decision, SafetyDecision::Block);
    }

    #[test]
    fn near_match_marks_suspicious() {
        let set = KnownBadSet::new([0b1111u128]);
        let decision = decide(
            0b1110u128,
            &set,
            SafetyConfig {
                near_match_threshold: 1,
            },
        );
        assert_eq!(decision, SafetyDecision::Suspicious);
    }

    #[test]
    fn unrelated_hash_allows() {
        let set = KnownBadSet::new([0u128]);
        let decision = decide(
            u128::MAX,
            &set,
            SafetyConfig {
                near_match_threshold: 2,
            },
        );
        assert_eq!(decision, SafetyDecision::Allow);
    }
}
