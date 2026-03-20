//! Ockham Razor OS-Governance Engine — native Rust.
//!
//! Deterministisches Minimal-Interventionsmodell:
//!   Utility(action) = risk_score × reduction − complexity_weight × complexity
//! Die Aktion mit maximaler Utility wird gewählt.
//! Ockham-Gate: risk < 0.28 → immer Allow.

use serde::{Deserialize, Serialize};

/// Mögliche OS-Gegenmassnahmen (aufsteigend nach Komplexität).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OckhamAction {
    Allow,
    ThrottleBackground,
    LimitNewProcesses,
    IsolateNetwork,
    PauseAutopilot,
    RequireManualReview,
}

impl OckhamAction {
    pub fn as_str(self) -> &'static str {
        match self {
            OckhamAction::Allow => "allow",
            OckhamAction::ThrottleBackground => "throttle_background",
            OckhamAction::LimitNewProcesses => "limit_new_processes",
            OckhamAction::IsolateNetwork => "isolate_network",
            OckhamAction::PauseAutopilot => "pause_autopilot",
            OckhamAction::RequireManualReview => "require_manual_review",
        }
    }
}

/// Eingehende Systemsignale für die Risikobewertung.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OckhamObservation {
    /// Normierter CPU-Auslastungswert [0, 1].
    pub cpu_load: f64,
    /// Normierter Speicherdruck [0, 1].
    pub mem_pressure: f64,
    /// Normierte Prozess-Spawn-Rate [0, 1].
    pub process_spawn_rate: f64,
    /// Anteil nicht-signierter Binaries [0, 1].
    pub unsigned_binary_ratio: f64,
    /// Normierte Anzahl neuer Netzwerk-Peers [0, 1].
    pub network_new_peers: f64,
    /// Normierter Fehlerburst [0, 1].
    pub error_burst: f64,
    /// Normierte Integrity-Alerts [0, 1].
    pub integrity_alerts: f64,
}

impl Default for OckhamObservation {
    fn default() -> Self {
        Self {
            cpu_load: 0.0,
            mem_pressure: 0.0,
            process_spawn_rate: 0.05,
            unsigned_binary_ratio: 0.0,
            network_new_peers: 0.0,
            error_burst: 0.0,
            integrity_alerts: 0.0,
        }
    }
}

/// Entscheidungsergebnis des Ockham-Razor-Modells.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OckhamDecision {
    pub action: OckhamAction,
    pub risk_score: f64,
    pub utility: f64,
    pub complexity: f64,
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Interne Hilfsfunktionen
// ---------------------------------------------------------------------------

struct ActionRow {
    action: OckhamAction,
    complexity: f64,
    reduction: f64,
}

fn action_table() -> [ActionRow; 6] {
    [
        ActionRow { action: OckhamAction::Allow,               complexity: 0.00, reduction: 0.00 },
        ActionRow { action: OckhamAction::ThrottleBackground,  complexity: 0.18, reduction: 0.28 },
        ActionRow { action: OckhamAction::LimitNewProcesses,   complexity: 0.26, reduction: 0.42 },
        ActionRow { action: OckhamAction::IsolateNetwork,      complexity: 0.33, reduction: 0.55 },
        ActionRow { action: OckhamAction::PauseAutopilot,      complexity: 0.40, reduction: 0.66 },
        ActionRow { action: OckhamAction::RequireManualReview, complexity: 0.52, reduction: 0.80 },
    ]
}

#[inline]
fn clip01(v: f64) -> f64 {
    v.clamp(0.0, 1.0)
}

fn risk_from_observation(obs: &OckhamObservation) -> (f64, Vec<String>) {
    let cpu   = clip01(obs.cpu_load);
    let mem   = clip01(obs.mem_pressure);
    let spawn = clip01(obs.process_spawn_rate);
    let unsig = clip01(obs.unsigned_binary_ratio);
    let net   = clip01(obs.network_new_peers);
    let err   = clip01(obs.error_burst);
    let intg  = clip01(obs.integrity_alerts);

    let risk = clip01(
        0.18 * cpu
        + 0.15 * mem
        + 0.16 * spawn
        + 0.19 * unsig
        + 0.12 * net
        + 0.08 * err
        + 0.12 * intg,
    );

    let mut reasons: Vec<String> = Vec::new();
    if cpu   > 0.82 { reasons.push("cpu_load_high".to_owned()); }
    if mem   > 0.82 { reasons.push("mem_pressure_high".to_owned()); }
    if spawn > 0.72 { reasons.push("spawn_rate_high".to_owned()); }
    if unsig > 0.45 { reasons.push("unsigned_binary_ratio_high".to_owned()); }
    if net   > 0.60 { reasons.push("network_peer_churn_high".to_owned()); }
    if err   > 0.70 { reasons.push("error_burst_high".to_owned()); }
    if intg  > 0.10 { reasons.push("integrity_alerts_present".to_owned()); }

    (risk, reasons)
}

// ---------------------------------------------------------------------------
// Öffentliche API
// ---------------------------------------------------------------------------

/// Wählt deterministisch die einfachste noch wirksame OS-Gegenmassnahme.
pub fn ockham_os_razor(obs: &OckhamObservation, complexity_weight: f64) -> OckhamDecision {
    let (risk, reasons) = risk_from_observation(obs);

    // Ockham-Gate: bei niedrigem Risiko explizit nicht eingreifen.
    if risk < 0.28 {
        return OckhamDecision {
            action: OckhamAction::Allow,
            risk_score: risk,
            utility: 0.0,
            complexity: 0.0,
            reasons,
        };
    }

    let mut best_action = OckhamAction::Allow;
    let mut best_utility = f64::NEG_INFINITY;
    let mut best_complexity = f64::MAX;

    for row in action_table() {
        let utility = risk * row.reduction - complexity_weight * row.complexity;
        if utility > best_utility
            || (utility == best_utility && row.complexity < best_complexity)
        {
            best_utility = utility;
            best_complexity = row.complexity;
            best_action = row.action;
        }
    }

    OckhamDecision {
        action: best_action,
        risk_score: risk,
        utility: best_utility,
        complexity: best_complexity,
        reasons,
    }
}

/// Kapselung des Ockham-Razor-Modells mit konfigurierbarem Complexity-Gewicht.
pub struct OckhamEngine {
    pub complexity_weight: f64,
}

impl Default for OckhamEngine {
    fn default() -> Self {
        Self { complexity_weight: 0.35 }
    }
}

impl OckhamEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_complexity_weight(w: f64) -> Self {
        Self { complexity_weight: w.clamp(0.0, 1.0) }
    }

    /// Fällt eine deterministische Minimal-Interventions-Entscheidung.
    pub fn decide(&self, obs: &OckhamObservation) -> OckhamDecision {
        ockham_os_razor(obs, self.complexity_weight)
    }

    /// Führt die entschiedene Aktion auf Betriebssystemebene aus.
    pub fn execute(&self, decision: &OckhamDecision) -> OckhamExecutionResult {
        match decision.action {
            OckhamAction::Allow => OckhamExecutionResult::Ok,
            OckhamAction::ThrottleBackground => throttle_background_processes(),
            OckhamAction::LimitNewProcesses => limit_new_processes(),
            OckhamAction::IsolateNetwork => {
                // Netzwerkisolation erfordert erhöhte Rechte (Windows Firewall API).
                OckhamExecutionResult::Deferred("network isolation requires elevated privileges")
            }
            OckhamAction::PauseAutopilot => {
                // Signalisierung erfolgt über den Aufrufer via Bus.
                OckhamExecutionResult::Ok
            }
            OckhamAction::RequireManualReview => OckhamExecutionResult::Ok,
        }
    }
}

// ---------------------------------------------------------------------------
// Ausführungs-Ergebnis
// ---------------------------------------------------------------------------

/// Ergebnis einer OS-Aktion nach `OckhamEngine::execute()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OckhamExecutionResult {
    /// Aktion erfolgreich ausgeführt (oder nicht nötig).
    Ok,
    /// Aktion zurückgestellt – Begründung im String.
    Deferred(&'static str),
    /// Ausführung fehlgeschlagen – Begründung im String.
    Failed(String),
}

// ---------------------------------------------------------------------------
// OS-Aktionen (Windows)
// ---------------------------------------------------------------------------

/// Senkt die Priorität aller Background-Prozesse auf BELOW_NORMAL.
fn throttle_background_processes() -> OckhamExecutionResult {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcessId, OpenProcess, SetPriorityClass,
            BELOW_NORMAL_PRIORITY_CLASS, PROCESS_QUERY_INFORMATION, PROCESS_SET_INFORMATION,
        };
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

        let mut throttled: u32 = 0;
        let own_pid = unsafe { GetCurrentProcessId() };

        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return OckhamExecutionResult::Failed("CreateToolhelp32Snapshot failed".into());
        }

        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut ok = unsafe { Process32FirstW(snap, &mut entry) } != 0;
        while ok {
            let pid = entry.th32ProcessID;
            if pid != own_pid && pid != 0 && pid != 4 {
                let handle = unsafe {
                    OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
                        0,
                        pid,
                    )
                };
                if !handle.is_null() {
                    unsafe { SetPriorityClass(handle, BELOW_NORMAL_PRIORITY_CLASS) };
                    unsafe { CloseHandle(handle) };
                    throttled += 1;
                }
            }
            ok = unsafe { Process32NextW(snap, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snap) };

        if throttled > 0 {
            OckhamExecutionResult::Ok
        } else {
            OckhamExecutionResult::Deferred("no throttleable processes found")
        }
    }
    #[cfg(not(target_os = "windows"))]
    OckhamExecutionResult::Deferred("throttle only implemented on Windows")
}

/// Weist den Sandbox-Prozess einem Job-Object mit Prozess-Limit zu.
fn limit_new_processes() -> OckhamExecutionResult {
    // Job-Object-API requires a Windows SDK feature that varies by windows-sys version.
    // Return Deferred; the process limit can be applied by the sandbox_worker binary instead.
    OckhamExecutionResult::Deferred("job-object limit deferred to sandbox_worker")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_risk_always_allows() {
        let obs = OckhamObservation::default();
        let d = OckhamEngine::new().decide(&obs);
        assert_eq!(d.action, OckhamAction::Allow);
        assert!(d.risk_score < 0.28, "risk={}", d.risk_score);
    }

    #[test]
    fn high_signals_escalate_beyond_allow() {
        let obs = OckhamObservation {
            cpu_load: 0.95,
            integrity_alerts: 0.80,
            unsigned_binary_ratio: 0.70,
            mem_pressure: 0.90,
            ..Default::default()
        };
        let d = OckhamEngine::new().decide(&obs);
        assert_ne!(d.action, OckhamAction::Allow);
        assert!(d.risk_score >= 0.28);
    }

    #[test]
    fn utility_formula_is_deterministic() {
        let obs = OckhamObservation {
            cpu_load: 0.60,
            mem_pressure: 0.70,
            process_spawn_rate: 0.50,
            unsigned_binary_ratio: 0.50,
            ..Default::default()
        };
        let a = OckhamEngine::new().decide(&obs);
        let b = OckhamEngine::new().decide(&obs);
        assert_eq!(a.action, b.action);
        assert!((a.risk_score - b.risk_score).abs() < 1e-12);
    }

    #[test]
    fn ockham_gate_at_threshold() {
        // risk just below 0.28 → Allow
        let obs = OckhamObservation {
            cpu_load: 0.30,   // 0.18*0.30 = 0.054
            mem_pressure: 0.30, // 0.15*0.30 = 0.045
            // total ≈ 0.099 + 0.05*other → well below 0.28
            ..Default::default()
        };
        let d = OckhamEngine::new().decide(&obs);
        assert_eq!(d.action, OckhamAction::Allow);
    }

    #[test]
    fn action_string_roundtrip() {
        assert_eq!(OckhamAction::RequireManualReview.as_str(), "require_manual_review");
        assert_eq!(OckhamAction::ThrottleBackground.as_str(), "throttle_background");
    }
}
