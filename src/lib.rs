pub mod aef;
pub mod ockham;

/// Gibt den Anwendungs-Stammpfad zurück — immer relativ zur laufenden `.exe`,
/// nicht zum aktuellen Arbeitsverzeichnis.
pub fn app_root() -> std::path::PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let mut candidate = exe.parent().map(|p| p.to_path_buf());
        while let Some(dir) = candidate {
            if dir.join("aether_pipeline.py").exists() {
                return dir;
            }
            candidate = dir.parent().map(|p| p.to_path_buf());
        }
        if let Ok(exe2) = std::env::current_exe() {
            if let Some(parent) = exe2.parent() {
                return parent.to_path_buf();
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// Shorthand: `app_root().join("data").join(rel)`
pub fn data_path(rel: &str) -> std::path::PathBuf {
    app_root().join("data").join(rel)
}

pub mod auth;
pub mod bus_ipc;
pub mod capsule;
pub mod delta_vault;
pub mod gfx;
pub mod iced_shell;
pub mod launcher_dashboard;
pub mod inter_layer_bus;
pub mod key_vault;
pub mod lab_boundary;
pub mod observation;
pub mod offline_cache;
pub mod pack;
pub mod policy_executor;
pub mod priority;
pub mod py_bridge;
pub mod public_ttd;
pub mod runtime_signal;
pub mod security;
pub mod fingerprint;
pub mod zk_match;
pub mod policy;
pub mod api;
pub mod network_guard;
pub mod orchestrator;
pub mod egl_policy;
pub mod symbiont_rpc;
pub mod state;
pub mod swarm_bootstrap;
pub mod swarm_loop;
pub mod vault_access;
pub mod workflow_anchor;
pub mod hardware;
pub mod ethics;
pub mod observer;
pub mod system_service;
