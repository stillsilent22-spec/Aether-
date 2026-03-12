/// Logarithmische Prioritaetsfunktion fuer dynamische Shanway-Entscheidungen.
pub struct LogarithmicPriority;

impl LogarithmicPriority {
    const N_MAX: f32 = 100.0;
    const HEISENBERG_CEILING: f32 = 0.98;

    pub fn compute(base_confidence: f32, hit_count: u32) -> f32 {
        let base = base_confidence.clamp(0.0, 1.0);
        if hit_count == 0 {
            return 0.0;
        }
        let n = hit_count as f32;
        let boost = (1.0 + n).ln() / (1.0 + Self::N_MAX).ln();
        let exponent = (1.0 - base).clamp(0.25, 1.0);
        let raw = Self::HEISENBERG_CEILING * boost.powf(exponent);
        raw.min(Self::HEISENBERG_CEILING)
    }

    pub fn should_act_proactively(hit_count: u32, base_confidence: f32) -> bool {
        Self::compute(base_confidence, hit_count) >= 0.65
    }

    pub fn should_notify_user(hit_count: u32, base_confidence: f32) -> bool {
        Self::compute(base_confidence, hit_count) >= 0.80
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logarithmic_priority() {
        assert!(LogarithmicPriority::compute(0.65, 0) < 0.30);
        assert!(LogarithmicPriority::compute(0.65, 1) > 0.20);
        assert!(LogarithmicPriority::compute(0.65, 50) > 0.80);
        assert!(LogarithmicPriority::compute(0.65, 100) <= 0.98);
        assert!(LogarithmicPriority::compute(1.0, 1000) <= 0.98);
    }
}
