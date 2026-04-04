use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const SETTINGS_PATH: &str = "data/settings.json";
const STATUS_PATH: &str = "data/interbus/hybrid_status.json";
const BRIDGE_SCRIPT_PATH: &str = "modules/hybrid_bridge.py";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbiontSettings {
    pub enabled: bool,
    pub python_path: String,
    pub server_path: String,
    pub host: String,
    pub port: u16,
}

impl Default for SymbiontSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            python_path: "python".to_owned(),
            server_path: "aether-symbiont/server/symbiont_server.py".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 38571,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSettings {
    pub enabled: bool,
    pub python_path: String,
    pub poll_seconds: f64,
    pub symbiont: SymbiontSettings,
}

impl Default for HybridSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            python_path: "python".to_owned(),
            poll_seconds: 2.0,
            symbiont: SymbiontSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HybridStatus {
    pub bridge_running: bool,
    pub symbiont_running: bool,
    pub aethernet_running: bool,
    pub aethernet_receiver_port: u16,
    pub bridge_pid: i64,
    pub symbiont_pid: i64,
    pub symbiont_host: String,
    pub symbiont_port: u16,
    pub swarm_node_count: u64,
    pub swarm_pack_count: u64,
    pub swarm_consensus_count: u64,
    pub swarm_candidate_count: u64,
    pub swarm_summary: String,
    pub last_error: String,
    pub last_tick: String,
}

pub struct PythonBridgeManager {
    child: Option<Child>,
}

impl PythonBridgeManager {
    pub fn new() -> Self {
        Self { child: None }
    }

    pub fn is_running(&mut self) -> bool {
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(None) => return true,
                Ok(Some(_)) | Err(_) => {
                    self.child = None;
                }
            }
        }
        false
    }

    pub fn start(&mut self) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }

        let settings = load_hybrid_settings();
        if !settings.enabled {
            return Ok(());
        }

        let python = if settings.python_path.trim().is_empty() {
            "python"
        } else {
            settings.python_path.trim()
        };

        let script = Path::new(BRIDGE_SCRIPT_PATH);
        if !script.is_file() {
            return Err(format!("Bridge-Skript fehlt: {}", script.display()));
        }

        let mut cmd = Command::new(python);
        cmd.arg(BRIDGE_SCRIPT_PATH)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir(PathBuf::from("."));

        let child = cmd
            .spawn()
            .map_err(|err| format!("Python-Bridge konnte nicht gestartet werden: {err}"))?;
        self.child = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(mut child) = self.child.take() {
            child
                .kill()
                .map_err(|err| format!("Python-Bridge konnte nicht beendet werden: {err}"))?;
        }
        Ok(())
    }

    pub fn restart(&mut self) -> Result<(), String> {
        self.stop()?;
        self.start()
    }
}

pub fn load_hybrid_settings() -> HybridSettings {
    let default = HybridSettings::default();
    let raw = match fs::read_to_string(SETTINGS_PATH) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let parsed = match serde_json::from_str::<Value>(&raw) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let hybrid = match parsed.get("hybrid") {
        Some(v) => v,
        None => return default,
    };

    let mut settings = default;
    settings.enabled = hybrid
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(settings.enabled);
    settings.python_path = hybrid
        .get("python_path")
        .and_then(Value::as_str)
        .unwrap_or(&settings.python_path)
        .to_owned();
    settings.poll_seconds = hybrid
        .get("poll_seconds")
        .and_then(Value::as_f64)
        .unwrap_or(settings.poll_seconds)
        .clamp(0.5, 10.0);

    if let Some(sym) = hybrid.get("symbiont") {
        settings.symbiont.enabled = sym
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(settings.symbiont.enabled);
        settings.symbiont.python_path = sym
            .get("python_path")
            .and_then(Value::as_str)
            .unwrap_or(&settings.symbiont.python_path)
            .to_owned();
        settings.symbiont.server_path = sym
            .get("server_path")
            .and_then(Value::as_str)
            .unwrap_or(&settings.symbiont.server_path)
            .to_owned();
        settings.symbiont.host = sym
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or(&settings.symbiont.host)
            .to_owned();
        settings.symbiont.port = sym
            .get("port")
            .and_then(Value::as_u64)
            .unwrap_or(settings.symbiont.port as u64) as u16;
    }

    settings
}

pub fn write_hybrid_settings(settings: &HybridSettings) -> Result<(), String> {
    let mut root = match fs::read_to_string(SETTINGS_PATH) {
        Ok(raw) => serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| Value::Object(Map::new())),
        Err(_) => Value::Object(Map::new()),
    };

    if !root.is_object() {
        root = Value::Object(Map::new());
    }

    let hybrid_value = serde_json::json!({
        "enabled": settings.enabled,
        "python_path": settings.python_path,
        "poll_seconds": settings.poll_seconds,
        "symbiont": {
            "enabled": settings.symbiont.enabled,
            "python_path": settings.symbiont.python_path,
            "server_path": settings.symbiont.server_path,
            "host": settings.symbiont.host,
            "port": settings.symbiont.port,
        }
    });

    if let Some(obj) = root.as_object_mut() {
        obj.insert("hybrid".to_owned(), hybrid_value);
    }

    let data_dir = Path::new(SETTINGS_PATH)
        .parent()
        .ok_or_else(|| "Settings-Pfad ist ungueltig".to_owned())?;
    fs::create_dir_all(data_dir).map_err(|err| format!("Settings-Verzeichnis fehlt: {err}"))?;

    let content = serde_json::to_string_pretty(&root)
        .map_err(|err| format!("Settings konnten nicht serialisiert werden: {err}"))?;
    fs::write(SETTINGS_PATH, content).map_err(|err| format!("Settings konnten nicht geschrieben werden: {err}"))
}

pub fn set_symbiont_enabled(enabled: bool) -> Result<(), String> {
    let mut settings = load_hybrid_settings();
    settings.symbiont.enabled = enabled;
    write_hybrid_settings(&settings)
}

pub fn set_symbiont_endpoint(host: String, port: u16) -> Result<(), String> {
    let mut settings = load_hybrid_settings();
    settings.symbiont.host = host;
    settings.symbiont.port = port;
    write_hybrid_settings(&settings)
}

pub fn read_hybrid_status() -> Option<HybridStatus> {
    let raw = fs::read_to_string(STATUS_PATH).ok()?;
    serde_json::from_str::<HybridStatus>(&raw).ok()
}
