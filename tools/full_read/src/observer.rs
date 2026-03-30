//! Aether – Observer Engine (pure Rust).
//!
//! Portiert observer_engine.py: passives Monitoring von Systemmetriken,
//! Anomalie-Erkennung und Event-Logging ohne externe Dependencies.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ── Metrik-Sample ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetricSample {
    pub timestamp: Instant,
    pub cpu_pct: f32,
    pub ram_pct: f32,
    pub value: f64, // generischer Zusatzwert
}

// ── Anomalie-Typ ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyKind {
    CpuSpike,
    RamPressure,
    ValueDrift,
    Stall,
}

#[derive(Debug, Clone)]
pub struct AnomalyEvent {
    pub kind: AnomalyKind,
    pub severity: f64,     // [0,1]
    pub detected_at: Instant,
    pub description: String,
}

// ── Observer ──────────────────────────────────────────────────────────────

pub struct Observer {
    window: VecDeque<MetricSample>,
    window_size: usize,
    last_event: Option<Instant>,
    cooldown: Duration,
    pub anomalies: Vec<AnomalyEvent>,
}

impl Observer {
    pub fn new(window_size: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size),
            window_size: window_size.max(4),
            last_event: None,
            cooldown: Duration::from_secs(5),
            anomalies: Vec::new(),
        }
    }

    /// Fügt einen neuen Sample hinzu und prüft auf Anomalien.
    pub fn push(&mut self, sample: MetricSample) {
        if self.window.len() >= self.window_size {
            self.window.pop_front();
        }
        self.window.push_back(sample);
        self.detect();
    }

    /// Mittlerer CPU-Prozentsatz im Fenster.
    pub fn mean_cpu(&self) -> f32 {
        if self.window.is_empty() { return 0.0; }
        self.window.iter().map(|s| s.cpu_pct).sum::<f32>() / self.window.len() as f32
    }

    /// Mittlerer RAM-Prozentsatz im Fenster.
    pub fn mean_ram(&self) -> f32 {
        if self.window.is_empty() { return 0.0; }
        self.window.iter().map(|s| s.ram_pct).sum::<f32>() / self.window.len() as f32
    }

    /// Standardabweichung des generischen Werts im Fenster.
    pub fn value_stddev(&self) -> f64 {
        if self.window.len() < 2 { return 0.0; }
        let n = self.window.len() as f64;
        let mean = self.window.iter().map(|s| s.value).sum::<f64>() / n;
        let var = self.window.iter().map(|s| (s.value - mean).powi(2)).sum::<f64>() / n;
        var.sqrt()
    }

    fn in_cooldown(&self) -> bool {
        self.last_event.map(|t| t.elapsed() < self.cooldown).unwrap_or(false)
    }

    fn emit(&mut self, event: AnomalyEvent) {
        self.last_event = Some(event.detected_at);
        self.anomalies.push(event);
        // Fenster auf max 200 Events begrenzen
        if self.anomalies.len() > 200 {
            self.anomalies.drain(..100);
        }
    }

    fn detect(&mut self) {
        if self.in_cooldown() || self.window.len() < 4 { return; }
        let now = Instant::now();

        // CPU-Spike: letzter Sample > 90% und deutlich über Mittel
        if let Some(last) = self.window.back() {
            let mean_cpu = self.mean_cpu();
            if last.cpu_pct > 90.0 && last.cpu_pct > mean_cpu * 1.4 {
                let sev = ((last.cpu_pct as f64 - 90.0) / 10.0).clamp(0.0, 1.0);
                self.emit(AnomalyEvent {
                    kind: AnomalyKind::CpuSpike,
                    severity: sev,
                    detected_at: now,
                    description: format!("CPU-Spike: {:.1}% (Mittel {:.1}%)", last.cpu_pct, mean_cpu),
                });
                return;
            }
            // RAM-Druck
            if last.ram_pct > 85.0 {
                let sev = ((last.ram_pct as f64 - 85.0) / 15.0).clamp(0.0, 1.0);
                self.emit(AnomalyEvent {
                    kind: AnomalyKind::RamPressure,
                    severity: sev,
                    detected_at: now,
                    description: format!("RAM-Druck: {:.1}%", last.ram_pct),
                });
                return;
            }
        }

        // Value-Drift: Stddev sehr hoch
        let std = self.value_stddev();
        if std > 25.0 {
            self.emit(AnomalyEvent {
                kind: AnomalyKind::ValueDrift,
                severity: (std / 50.0).clamp(0.0, 1.0),
                detected_at: now,
                description: format!("Value-Drift: σ={:.1}", std),
            });
        }
    }

    /// Gibt die letzten n Anomalien zurück.
    pub fn recent_anomalies(&self, n: usize) -> &[AnomalyEvent] {
        let len = self.anomalies.len();
        if len <= n { &self.anomalies } else { &self.anomalies[len - n..] }
    }

    /// Setzt den Anomalie-Puffer zurück.
    pub fn clear_anomalies(&mut self) {
        self.anomalies.clear();
    }
}

impl Default for Observer {
    fn default() -> Self { Self::new(32) }
}
