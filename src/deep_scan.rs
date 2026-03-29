//! deep_scan.rs
// Deep Scan für Aether: Geometrie-, Font- und Binäranalyse von Dateien.
// Wird von der GUI genutzt, um zusätzliche Strukturmerkmale und Anker zu erkennen.
//
// Funktionen:
// - deep_scan_file: Führt einen Deep Scan auf einer Datei durch und liefert Analyse-Infos
//
use std::fs;
use std::io;
use std::path::Path;

/// Ergebnisstruktur für Deep Scan
pub struct DeepScanResult {
    pub anchor_count: usize,
    pub geometry_info: String,
    pub font_info: String,
    pub entropy: f32,
}

/// Führt einen Deep Scan auf einer Datei durch (Dummy-Implementierung)
pub fn deep_scan_file<P: AsRef<Path>>(file_path: P) -> io::Result<DeepScanResult> {
    let path = file_path.as_ref();
    let data = fs::read(path)?;
    // Dummy: Zähle Bytes > 128 als "Anker"
    let anchor_count = data.iter().filter(|b| **b > 128).count();
    let geometry_info = format!("{} bytes, {} unique", data.len(), data.iter().copied().collect::<std::collections::HashSet<_>>().len());
    let font_info = if path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase() == "ttf" { "TrueType Font".to_string() } else { "-".to_string() };
    // Shannon entropy: H(X) = -Σ p(x) * log2(p(x))
    let entropy = if data.is_empty() {
        0.0
    } else {
        let mut freq = [0u64; 256];
        for &b in &data { freq[b as usize] += 1; }
        let len = data.len() as f32;
        freq.iter().filter(|&&c| c > 0).fold(0.0f32, |acc, &c| {
            let p = c as f32 / len;
            acc - p * p.log2()
        })
    };
    Ok(DeepScanResult { anchor_count, geometry_info, font_info, entropy })
}
