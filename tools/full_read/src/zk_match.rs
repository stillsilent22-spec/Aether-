use crate::fingerprint::ImageFingerprint;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownBadSetError {
    InvalidBinaryLength,
    Io,
}

#[derive(Debug, Clone)]
pub struct KnownBadSet {
    fingerprints: HashSet<ImageFingerprint>,
}

impl KnownBadSet {
    pub fn new<I>(fingerprints: I) -> Self
    where
        I: IntoIterator<Item = ImageFingerprint>,
    {
        Self {
            fingerprints: fingerprints.into_iter().collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    pub fn from_binary_blob(blob: &[u8]) -> Result<Self, KnownBadSetError> {
        if blob.len() % 16 != 0 {
            return Err(KnownBadSetError::InvalidBinaryLength);
        }

        let mut fingerprints = HashSet::new();
        for chunk in blob.chunks_exact(16) {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(chunk);
            fingerprints.insert(u128::from_le_bytes(bytes));
        }

        Ok(Self { fingerprints })
    }

    pub fn load_from_path(path: &Path) -> Result<Self, KnownBadSetError> {
        let blob = fs::read(path).map_err(|_| KnownBadSetError::Io)?;
        Self::from_binary_blob(&blob)
    }

    pub fn to_binary_blob(&self) -> Vec<u8> {
        let mut values = self.fingerprints.iter().copied().collect::<Vec<_>>();
        values.sort_unstable();
        let mut out = Vec::with_capacity(values.len() * 16);
        for value in values {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchResult {
    Exact,
    Near { distance: u32 },
    None,
}

pub fn hamming_distance(left: ImageFingerprint, right: ImageFingerprint) -> u32 {
    (left ^ right).count_ones()
}

pub fn match_fingerprint(
    fingerprint: ImageFingerprint,
    known_bad_set: &KnownBadSet,
    near_threshold: u32,
) -> MatchResult {
    if known_bad_set.fingerprints.contains(&fingerprint) {
        return MatchResult::Exact;
    }

    let mut best_distance: Option<u32> = None;
    for known in &known_bad_set.fingerprints {
        let distance = hamming_distance(fingerprint, *known);
        if distance <= near_threshold {
            best_distance = Some(best_distance.map_or(distance, |current| current.min(distance)));
        }
    }

    match best_distance {
        Some(distance) => MatchResult::Near { distance },
        None => MatchResult::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_counts_different_bits() {
        let left = 0b1011u128;
        let right = 0b1110u128;
        assert_eq!(hamming_distance(left, right), 2);
    }

    #[test]
    fn near_match_detects_threshold_hit() {
        let known = KnownBadSet::new([0b1111u128]);
        let result = match_fingerprint(0b1110u128, &known, 1);
        assert_eq!(result, MatchResult::Near { distance: 1 });
    }

    #[test]
    fn binary_blob_roundtrip_preserves_hashes() {
        let set = KnownBadSet::new([7u128, 9u128, 42u128]);
        let blob = set.to_binary_blob();
        let restored = KnownBadSet::from_binary_blob(&blob).expect("blob should decode");
        assert_eq!(restored.len(), 3);
        assert_eq!(match_fingerprint(42u128, &restored, 0), MatchResult::Exact);
    }
}
