//! Aether – Ethics & Integrity Engine (pure Rust).
//!
//! Portiert ethics_engine.py: strukturelle Textintegrität ohne Semantik.
//! Zipf, Benford, Fraktal, Noether, Interferenz, Heisenberg, Ockham.

use std::collections::HashMap;

// ── Hilfsfunktionen ────────────────────────────────────────────────────────

fn clamp01(v: f64) -> f64 { v.clamp(0.0, 1.0) }

fn shannon_entropy_tokens(tokens: &[&str]) -> f64 {
    if tokens.is_empty() { return 0.0; }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for t in tokens { *counts.entry(t).or_insert(0) += 1; }
    let n = tokens.len() as f64;
    counts.values().map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

// ── Zipf-Konformität ───────────────────────────────────────────────────────

/// Misst ob die Wortfrequenzverteilung dem Zipf-Gesetz folgt.
/// Score 1.0 = perfekte Zipf-Konformität, 0.0 = keine.
pub fn zipf_score(words: &[&str]) -> f64 {
    if words.len() < 10 { return 0.7; }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for w in words { *counts.entry(w).or_insert(0) += 1; }
    let mut ranked: Vec<usize> = counts.values().copied().collect();
    ranked.sort_unstable_by(|a, b| b.cmp(a));
    ranked.truncate(50);
    if ranked.len() < 5 { return 0.7; }
    // Lineare Regression von log(rank) auf log(freq)
    let n = ranked.len() as f64;
    let log_ranks: Vec<f64> = (1..=ranked.len()).map(|i| (i as f64).ln()).collect();
    let log_freqs: Vec<f64> = ranked.iter().map(|&f| (f.max(1) as f64).ln()).collect();
    let mean_x = log_ranks.iter().sum::<f64>() / n;
    let mean_y = log_freqs.iter().sum::<f64>() / n;
    let num: f64 = log_ranks.iter().zip(log_freqs.iter())
        .map(|(x, y)| (x - mean_x) * (y - mean_y)).sum();
    let den: f64 = log_ranks.iter().map(|x| (x - mean_x).powi(2)).sum::<f64>().sqrt()
        * log_freqs.iter().map(|y| (y - mean_y).powi(2)).sum::<f64>().sqrt();
    if den.abs() < 1e-9 { return 0.7; }
    let slope = num / den;
    clamp01(1.0 - (slope.abs() - 1.0).abs() / 0.8)
}

// ── Benford-Score ──────────────────────────────────────────────────────────

/// Prüft ob führende Ziffern im Text dem Benford-Gesetz folgen.
pub fn benford_score(text: &str) -> f64 {
    let expected = [0.0, 0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046f64];
    let mut counts = [0usize; 10];
    let mut total = 0usize;
    for word in text.split_whitespace() {
        let digits: String = word.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() { continue; }
        let first = digits.chars().next().unwrap() as usize - '0' as usize;
        if first >= 1 && first <= 9 {
            counts[first] += 1;
            total += 1;
        }
    }
    if total < 20 { return 0.5; }
    let chi2: f64 = (1..=9).map(|d| {
        let obs = counts[d] as f64 / total as f64;
        let exp = expected[d];
        (obs - exp).powi(2) / exp
    }).sum();
    clamp01(1.0 - chi2 / 15.0)
}

// ── Fraktal-Score (Satzlängen-Varianz) ────────────────────────────────────

pub fn fraktal_score(sentences: &[&str]) -> f64 {
    let lengths: Vec<f64> = sentences.iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.split_whitespace().count() as f64)
        .collect();
    if lengths.len() < 3 { return 0.6; }
    let mean = lengths.iter().sum::<f64>() / lengths.len() as f64;
    let variance = lengths.iter().map(|l| (l - mean).powi(2)).sum::<f64>() / lengths.len() as f64;
    let std = variance.sqrt();
    if (5.0..=20.0).contains(&std) { return 1.0; }
    if std < 3.0 { return std / 3.0 * 0.5; }
    if std > 40.0 { return clamp01(1.0 - (std - 40.0) / 40.0) * 0.5; }
    if std < 5.0 { return (std - 3.0) / 2.0 * 0.5 + 0.5; }
    clamp01(1.0 - (std - 20.0) / 20.0) * 0.5 + 0.5
}

// ── Noether-Score (thematische Konsistenz) ─────────────────────────────────

pub fn noether_score(words: &[&str]) -> f64 {
    let filtered: Vec<&str> = words.iter().copied()
        .filter(|w| w.len() > 2)
        .collect();
    if filtered.len() < 20 { return 0.6; }
    let t = filtered.len() / 3;
    let first = &filtered[..t];
    let last = &filtered[filtered.len()-t..];
    let mut ca: HashMap<&str, usize> = HashMap::new();
    let mut cb: HashMap<&str, usize> = HashMap::new();
    for w in first { *ca.entry(w).or_insert(0) += 1; }
    for w in last { *cb.entry(w).or_insert(0) += 1; }
    // Vereinfachte Jaccard-Ähnlichkeit der Schlüsselwörter
    let ka: std::collections::HashSet<&&str> = ca.keys().collect();
    let kb: std::collections::HashSet<&&str> = cb.keys().collect();
    let inter = ka.intersection(&kb).count() as f64;
    let union = ka.union(&kb).count() as f64;
    let sim = if union > 0.0 { inter / union } else { 0.5 };
    clamp01(sim * 2.0)
}

// ── Strukturelle Textintegrität ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EthicsScore {
    pub score: f64,
    pub zipf: f64,
    pub benford: f64,
    pub fraktal: f64,
    pub noether: f64,
    pub heisenberg: f64,
}

// ── Heisenberg-Score (strukturelle Stabilität trotz lokaler Unsicherheit) ───

/// Misst strukturelle Stabilität über gleitende 8-Token-Fenster.
/// Hoher Score = Struktur ist stabil trotz lokaler Entropieschwankungen.
pub fn heisenberg_score(tokens: &[&str], entropy_mean: f64) -> f64 {
    if tokens.len() < 8 { return 0.7; }
    let window_size = 8usize;
    let window_entropies: Vec<f64> = tokens
        .windows(window_size)
        .map(|w| shannon_entropy_tokens(w))
        .collect();
    if window_entropies.is_empty() { return 0.7; }
    let mean = window_entropies.iter().sum::<f64>() / window_entropies.len() as f64;
    let variance = window_entropies.iter()
        .map(|e| (e - mean).powi(2))
        .sum::<f64>() / window_entropies.len() as f64;
    let observer_limit = entropy_mean * 0.15;
    clamp01(1.0 - (variance / (observer_limit + 1e-9)).min(1.0))
}

/// Hauptfunktion: misst strukturelle Textintegrität ohne Semantik.
/// entropy_mean: optionaler Entropie-Wert aus dem AEF-Fingerprint.
pub fn structural_text_integrity(text: &str, entropy_mean: Option<f64>) -> EthicsScore {
    if text.trim().is_empty() {
        return EthicsScore { score: 1.0, zipf: 1.0, benford: 0.5, fraktal: 1.0, noether: 1.0, heisenberg: 1.0 };
    }
    let words: Vec<&str> = text.split_whitespace().collect();
    let sentences: Vec<&str> = text.split(|c| c == '.' || c == '!' || c == '?')
        .filter(|s| !s.trim().is_empty()).collect();

    let z = zipf_score(&words);
    let b = benford_score(text);
    let f = fraktal_score(&sentences);
    let n = noether_score(&words);
    let h = heisenberg_score(&words, entropy_mean.unwrap_or(4.0));

    // Weights: Heisenberg added at 0.10; existing weights scaled by 0.90.
    let mut total = if (b - 0.5).abs() < 0.01 {
        z * 0.27 + f * 0.225 + n * 0.225 + h * 0.10 + 0.18
    } else {
        z * 0.225 + b * 0.135 + f * 0.18 + n * 0.18 + h * 0.10 + 0.18
    };

    if let Some(e) = entropy_mean {
        if e < 3.5 { total *= 0.85; }
        else if e > 7.0 { total *= 0.90; }
    }

    EthicsScore {
        score: clamp01(total),
        zipf: z,
        benford: b,
        fraktal: f,
        noether: n,
        heisenberg: h,
    }
}

// ── Code-Obfuskations-Score ────────────────────────────────────────────────

/// Gibt einen Verdachts-Score 0.0–1.0 zurück.
/// > 0.5 = strukturell auffällig (hohe Entropie, Base64-Dichte, eval-Dichte).
pub fn code_suspicion_score(code: &str) -> f64 {
    if code.is_empty() { return 0.0; }
    let bytes = code.as_bytes();
    // Byte-Entropie
    let entropy = {
        let mut counts = [0u64; 256];
        for &b in bytes { counts[b as usize] += 1; }
        let n = bytes.len() as f64;
        counts.iter().filter(|&&c| c > 0).map(|&c| {
            let p = c as f64 / n; -p * p.log2()
        }).sum::<f64>() / 8.0 // normiert auf [0,1]
    };
    // eval/exec Dichte
    let eval_count = code.matches("eval(").count() + code.matches("exec(").count();
    let eval_density = clamp01(eval_count as f64 / (code.len() as f64 / 100.0 + 1.0));
    // Hex-String-Anteil
    let hex_chars = bytes.iter().filter(|&&b| b"0123456789abcdefABCDEF".contains(&b)).count();
    let hex_ratio = hex_chars as f64 / bytes.len() as f64;

    clamp01(0.45 * entropy + 0.35 * eval_density + 0.20 * hex_ratio)
}

// Suppress dead-code warning for the helper (used transitively)
#[allow(dead_code)]
fn _use_shannon() { let _ = shannon_entropy_tokens(&[]); }
