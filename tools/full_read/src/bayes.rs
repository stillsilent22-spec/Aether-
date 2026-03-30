//! Aether – Bayesian Belief Engine (pure Rust).
//!
//! Portiert bayes_engine.py: Posterior-Updates für Anchor-Coverage,
//! Graph-Phasen und Alarm-Konfidenz.

fn clamp(v: f64, lo: f64, hi: f64) -> f64 { v.clamp(lo, hi) }
fn clamp01(v: f64) -> f64 { clamp(v, 0.0, 1.0) }

/// Robuster binärer Posterior: P(H|E) via Bayes.
fn posterior(prior: f64, likelihood_true: f64, likelihood_false: f64) -> f64 {
    let p = clamp(prior, 1e-4, 1.0 - 1e-4);
    let lt = clamp(likelihood_true, 1e-4, 1.0 - 1e-4);
    let lf = clamp(likelihood_false, 1e-4, 1.0 - 1e-4);
    let num = lt * p;
    let den = num + lf * (1.0 - p);
    if den <= 1e-9 { return p; }
    clamp01(num / den)
}

// ── AnchorPoint ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AnchorPoint {
    pub x: f64,          // normiert [0,1]
    pub y: f64,          // normiert [0,1]
    pub confidence: f64, // [0,1]
    pub strength: f64,   // [0,1]
}

#[derive(Debug, Clone)]
pub struct PriorCell {
    pub x_norm: f64,
    pub y_norm: f64,
    pub count: f64,
}

// ── Graph-Snapshot ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GraphSnapshot {
    pub attractor_score: f64,  // [0,100]
    pub coherence_score: f64,  // [0,100]
    pub phase_label: String,
    pub region_count: usize,
}

// ── Ausgabe-Snapshot ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct BayesSnapshot {
    pub anchor_prior: f64,
    pub phase_attractor: f64,
    pub phase_emergent: f64,
    pub phase_shift: f64,
    pub alarm: f64,
    pub pattern: f64,
}

// ── Haupt-Engine ───────────────────────────────────────────────────────────

pub struct BayesEngine;

impl BayesEngine {
    pub fn new() -> Self { Self }

    /// Posterior ob aktuelle Anker die gelernten Priors bestätigen.
    pub fn anchor_prior_posterior(
        &self,
        prior_cells: &[PriorCell],
        anchors: &[AnchorPoint],
    ) -> f64 {
        if anchors.is_empty() || prior_cells.is_empty() { return 0.0; }
        let total_count: f64 = prior_cells.iter().map(|c| c.count).sum();
        let max_count: f64 = prior_cells.iter().map(|c| c.count).fold(1.0_f64, f64::max);
        let prior = clamp(total_count / (total_count + 48.0), 0.12, 0.96);

        let mut weighted_hits = 0.0f64;
        for anchor in anchors {
            // Nearest-cell-Hit mit einem Radius von 0.15
            let hit = prior_cells.iter().any(|cell| {
                let dx = cell.x_norm - anchor.x;
                let dy = cell.y_norm - anchor.y;
                (dx * dx + dy * dy).sqrt() < 0.15
            });
            if hit {
                let weight = anchor.confidence * anchor.strength;
                let cell_weight = prior_cells.iter()
                    .filter(|cell| {
                        let dx = cell.x_norm - anchor.x;
                        let dy = cell.y_norm - anchor.y;
                        (dx * dx + dy * dy).sqrt() < 0.15
                    })
                    .map(|c| c.count / max_count)
                    .fold(0.0_f64, f64::max);
                weighted_hits += weight * cell_weight;
            }
        }
        let evidence_ratio = weighted_hits / anchors.len() as f64;
        posterior(prior, clamp(evidence_ratio + 0.3, 0.0, 0.98), 0.15)
    }

    /// Posterior für Phase-Labels aus einem GraphSnapshot.
    pub fn phase_posteriors(&self, snap: &GraphSnapshot) -> (f64, f64, f64) {
        let a = snap.attractor_score / 100.0;
        let c = snap.coherence_score / 100.0;

        // P(Attractor | evidence)
        let p_attractor = posterior(0.35, clamp(a * 0.8 + c * 0.2, 0.05, 0.97), 0.20);
        // P(Emergent | evidence)
        let p_emergent = posterior(0.30, clamp(c * 0.6 + (1.0 - a) * 0.4, 0.05, 0.97), 0.25);
        // P(Phase-shift | evidence)
        let regions_factor = clamp(snap.region_count as f64 / 8.0, 0.0, 1.0);
        let p_shift = posterior(0.15, clamp(regions_factor * 0.7 + (1.0 - c) * 0.3, 0.05, 0.90), 0.10);

        (p_attractor, p_emergent, p_shift)
    }

    /// Alarm-Konfidenz: kombiniert Anker-Prior und Phase-Signale.
    pub fn alarm_confidence(
        &self,
        anchor_posterior: f64,
        phase_attractor: f64,
        phase_shift: f64,
    ) -> f64 {
        let base = anchor_posterior * 0.5 + phase_attractor * 0.3 + phase_shift * 0.2;
        clamp01(base)
    }

    /// Pattern-Score: Ähnlichkeit zwischen zwei Anker-Mengen.
    pub fn pattern_similarity(
        &self,
        anchors_a: &[AnchorPoint],
        anchors_b: &[AnchorPoint],
    ) -> f64 {
        if anchors_a.is_empty() || anchors_b.is_empty() { return 0.0; }
        let mut hits = 0usize;
        for a in anchors_a {
            let found = anchors_b.iter().any(|b| {
                let dx = a.x - b.x;
                let dy = a.y - b.y;
                (dx * dx + dy * dy).sqrt() < 0.12
            });
            if found { hits += 1; }
        }
        hits as f64 / anchors_a.len().max(anchors_b.len()) as f64
    }

    /// Vollständiger Update-Zyklus: liefert BayesSnapshot.
    pub fn update(
        &self,
        prior_cells: &[PriorCell],
        anchors: &[AnchorPoint],
        snap: &GraphSnapshot,
        prev_anchors: Option<&[AnchorPoint]>,
    ) -> BayesSnapshot {
        let anchor_prior = self.anchor_prior_posterior(prior_cells, anchors);
        let (pa, pe, ps) = self.phase_posteriors(snap);
        let alarm = self.alarm_confidence(anchor_prior, pa, ps);
        let pattern = prev_anchors
            .map(|prev| self.pattern_similarity(anchors, prev))
            .unwrap_or(0.0);

        BayesSnapshot {
            anchor_prior,
            phase_attractor: pa,
            phase_emergent: pe,
            phase_shift: ps,
            alarm,
            pattern,
        }
    }
}

impl Default for BayesEngine {
    fn default() -> Self { Self::new() }
}
