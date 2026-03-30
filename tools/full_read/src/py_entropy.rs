//! Aether – Python-Bindings für Kern-Metriken (PyO3).
//!
//! Hochperformante Implementierungen von:
//!   - Shannon-Entropie (Byte-Ebene)
//!   - Token-Entropie
//!   - Zipf-Conformance-Score
//!   - Noether-Score (thematische Konsistenz)
//!
//! Entspricht `_byte_entropy`, `_token_entropy`, `_zipf`, `_noether`
//! aus `modules/ethics_engine.py`.
//!
//! Build:  maturin develop  (im Workspace-Root)
//! Import: `import aether_core_rs`

use pyo3::prelude::*;
use std::collections::HashMap;

/// Shannon-Entropie über alle Bytes (0..=255).
/// Rückgabe: 0.0 (komplett konstant) … 8.0 (uniform).
#[pyfunction]
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Shannon-Entropie über eine Token-Liste (String-Tokens).
/// Äquivalent zu `_token_entropy()` in ethics_engine.py.
#[pyfunction]
pub fn token_entropy(tokens: Vec<String>) -> f64 {
    if tokens.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for t in &tokens {
        *counts.entry(t.as_str()).or_insert(0) += 1;
    }
    let n = tokens.len() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Zipf-Conformance-Score aus sortierten Worthäufigkeiten (absteigend).
///
/// Gibt 0.0 (kein Zipf-Muster) … 1.0 (perfektes Zipf-Gesetz) zurück.
/// Verwendet lineare Regression über log(rank) vs log(freq).
///
/// Algorithmus:
///   ranked[i] = i-te häufigste Frequenz (1-basiert)
///   c = polyfit( log(1..n), log(ranked), deg=1 )
///   score = max(0, 1 - |c[0] + 1| / 0.8)   # idealer Steigung = −1
#[pyfunction]
pub fn zipf_score(ranked_freqs: Vec<u64>) -> f64 {
    let n = ranked_freqs.len();
    if n < 5 {
        return 0.7;
    }
    let capped: Vec<u64> = ranked_freqs.iter().copied().take(50).collect();
    let n = capped.len() as f64;
    let xs: Vec<f64> = (1..=capped.len() as u64)
        .map(|i| (i as f64).ln())
        .collect();
    let ys: Vec<f64> = capped
        .iter()
        .map(|&f| (f.max(1) as f64).ln())
        .collect();

    // Einfache lineare Regression (Steigung)
    let n_f = xs.len() as f64;
    let mx = xs.iter().sum::<f64>() / n_f;
    let my = ys.iter().sum::<f64>() / n_f;
    let num = xs.iter().zip(ys.iter()).map(|(x, y)| (x - mx) * (y - my)).sum::<f64>();
    let den = xs.iter().map(|x| (x - mx).powi(2)).sum::<f64>();
    if den.abs() < 1e-12 {
        return 0.7;
    }
    let slope = num / den;
    // Ideale Zipf-Steigung = −1.0
    let deviation = (slope.abs() - 1.0).abs();
    (1.0_f64 - deviation / 0.8).max(0.0).min(1.0)
}

/// Noether-Score: thematische Konsistenz eines Textes.
///
/// Vergleicht Wort-Häufigkeitsvektoren von Textanfang und Textende
/// mittels Kosinus-Ähnlichkeit.
///
/// words_start: Top-Wörter der ersten Texthälfte (Häufigkeit als Wert)
/// words_end:   Top-Wörter der zweiten Texthälfte (Häufigkeit als Wert)
///
/// Rückgabe: 0.0 (vollständig inkonsistenter Themenwechsel)
///        … 1.0 (thematisch stabil, hohe Konsistenz)
///
/// Formell:
///   N(T) = cos( v_Anfang, v_Ende ) × 2, clipped auf [0, 1]
///   cos(a, b) = (a · b) / (‖a‖ × ‖b‖)
#[pyfunction]
pub fn noether_score(words_start: HashMap<String, f64>, words_end: HashMap<String, f64>) -> f64 {
    if words_start.is_empty() || words_end.is_empty() {
        return 0.6;
    }
    let all_words: std::collections::HashSet<&str> = words_start
        .keys()
        .chain(words_end.keys())
        .map(|s| s.as_str())
        .collect();

    let dot: f64 = all_words
        .iter()
        .map(|&w| words_start.get(w).unwrap_or(&0.0) * words_end.get(w).unwrap_or(&0.0))
        .sum();
    let norm_a: f64 = words_start.values().map(|v| v * v).sum::<f64>().sqrt();
    let norm_b: f64 = words_end.values().map(|v| v * v).sum::<f64>().sqrt();
    if norm_a < 1e-12 || norm_b < 1e-12 {
        return 0.6;
    }
    let cosine = dot / (norm_a * norm_b);
    (cosine * 2.0).min(1.0).max(0.0)
}

/// Python-Modul-Registrierung.
#[pymodule]
pub fn register(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(byte_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(token_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(zipf_score, m)?)?;
    m.add_function(wrap_pyfunction!(noether_score, m)?)?;
    Ok(())
}
