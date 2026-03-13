use crate::auth::UserRecord;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityFinding {
    pub event_type: String,
    pub severity: String,
    pub message: String,
    #[serde(default)]
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecuritySnapshot {
    pub node_id: String,
    pub mode: String,
    pub trust_state: String,
    pub maze_state: String,
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<SecurityFinding>,
    #[serde(default)]
    pub self_metrics: BTreeMap<String, Value>,
    pub checked_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityAuditEvent {
    pub ts: String,
    pub reason: String,
    pub node_id: String,
    pub mode: String,
    pub trust_state: String,
    pub maze_state: String,
    pub summary: String,
}

pub struct SecurityMonitor {
    project_root: PathBuf,
    audit_path: PathBuf,
}

impl SecurityMonitor {
    const CORE_FILES: [(&'static str, &'static str); 7] = [
        ("cargo", "Cargo.toml"),
        ("main", "src/main.rs"),
        ("app", "src/app.rs"),
        ("auth", "src/auth.rs"),
        ("bus", "src/inter_layer_bus.rs"),
        ("runtime_signal", "src/runtime_signal.rs"),
        ("priority", "src/priority.rs"),
    ];

    pub fn new(project_root: impl Into<PathBuf>) -> Self {
        let project_root = project_root.into();
        Self {
            audit_path: project_root
                .join("data")
                .join("rust_shell")
                .join("security_audit.jsonl"),
            project_root,
        }
    }

    pub fn evaluate(
        &self,
        user: Option<&UserRecord>,
        register_count: usize,
        has_active_file: bool,
        relay_enabled: bool,
        public_ttd_enabled: bool,
    ) -> SecuritySnapshot {
        let checked_at = Utc::now().to_rfc3339();
        let mode = user
            .and_then(|item| item.user_settings.get("security_mode"))
            .cloned()
            .unwrap_or_else(|| "local".to_owned());

        let mut manifest = Vec::new();
        let mut missing_files = Vec::new();
        let mut findings = Vec::new();
        let mut present_core_files = 0usize;
        for (label, relative) in Self::CORE_FILES {
            let path = self.project_root.join(relative);
            if path.is_file() {
                present_core_files += 1;
                manifest.push(format!("{label}:{}", sha256_path(&path)));
            } else {
                missing_files.push(relative.to_owned());
                findings.push(SecurityFinding {
                    event_type: "CORE_FILE_MISSING".to_owned(),
                    severity: "critical".to_owned(),
                    message: format!("Kernpfad fehlt: {relative}"),
                    details: BTreeMap::from([
                        ("label".to_owned(), json!(label)),
                        ("path".to_owned(), json!(relative)),
                    ]),
                });
            }
        }
        let runtime_exe = std::env::current_exe().ok().filter(|path| path.is_file());
        if present_core_files == 0 {
            if let Some(exe) = runtime_exe.as_ref() {
                findings.clear();
                manifest.push(format!("runtime_exe:{}", sha256_path(exe)));
                findings.push(SecurityFinding {
                    event_type: "PACKAGED_RUNTIME".to_owned(),
                    severity: "info".to_owned(),
                    message: "Keine Quellpfade gefunden, daher wird die laufende EXE bewertet."
                        .to_owned(),
                    details: BTreeMap::from([(
                        "executable".to_owned(),
                        json!(exe.to_string_lossy().to_string()),
                    )]),
                });
                missing_files.clear();
            }
        }

        let privacy_boundary_ok = if present_core_files == 0 {
            true
        } else {
            self.privacy_boundary_present()
        };
        if privacy_boundary_ok && present_core_files > 0 {
            findings.push(SecurityFinding {
                event_type: "PRIVACY_BOUNDARY_OK".to_owned(),
                severity: "info".to_owned(),
                message: "Runtime-Privacy-Boundary gefunden.".to_owned(),
                details: BTreeMap::new(),
            });
        } else if !privacy_boundary_ok {
            findings.push(SecurityFinding {
                event_type: "PRIVACY_BOUNDARY_MISSING".to_owned(),
                severity: "critical".to_owned(),
                message: "Runtime-Privacy-Boundary ist im Rust-Pfad nicht vollstaendig erkennbar."
                    .to_owned(),
                details: BTreeMap::from([("path".to_owned(), json!("src/runtime_signal.rs"))]),
            });
        }

        let node_id = sha256_hex(manifest.join("|").as_bytes());
        let trust_state = if (!missing_files.is_empty() && present_core_files > 0)
            || !privacy_boundary_ok
            || (present_core_files == 0 && runtime_exe.is_none())
        {
            "LOCK"
        } else if mode.eq_ignore_ascii_case("dev") {
            "DEV"
        } else {
            "LOCAL_OK"
        };
        let maze_state = if mode.eq_ignore_ascii_case("dev") {
            "DEV_INSPECTION"
        } else if has_active_file {
            "ACTIVE_SCAN"
        } else {
            "PASSIVE"
        };

        let summary = if trust_state == "LOCK" {
            if present_core_files == 0 && runtime_exe.is_none() {
                "Security-Lock: weder Quellpfade noch laufende EXE konnten bewertet werden."
                    .to_owned()
            } else {
                format!(
                    "Security-Lock: {} Kernpfade fehlen oder Privacy-Boundary unvollstaendig.",
                    missing_files.len()
                )
            }
        } else {
            format!(
                "Rust-Shell lokal intakt | Mode {} | Register {} | Relay {} | Public-TTD {}",
                mode,
                register_count,
                if relay_enabled { "an" } else { "aus" },
                if public_ttd_enabled { "an" } else { "aus" }
            )
        };

        let self_metrics = BTreeMap::from([
            ("register_count".to_owned(), json!(register_count)),
            ("active_file".to_owned(), json!(has_active_file)),
            ("relay_enabled".to_owned(), json!(relay_enabled)),
            ("public_ttd_enabled".to_owned(), json!(public_ttd_enabled)),
            ("missing_core_files".to_owned(), json!(missing_files.len())),
            ("present_core_files".to_owned(), json!(present_core_files)),
            ("user_present".to_owned(), json!(user.is_some())),
        ]);

        SecuritySnapshot {
            node_id,
            mode,
            trust_state: trust_state.to_owned(),
            maze_state: maze_state.to_owned(),
            summary,
            findings,
            self_metrics,
            checked_at,
        }
    }

    pub fn append_audit(&self, snapshot: &SecuritySnapshot, reason: &str) -> Result<(), String> {
        if let Some(parent) = self.audit_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("Security-Audit-Verzeichnis fehlt: {err}"))?;
        }
        let event = SecurityAuditEvent {
            ts: Utc::now().to_rfc3339(),
            reason: reason.to_owned(),
            node_id: snapshot.node_id.clone(),
            mode: snapshot.mode.clone(),
            trust_state: snapshot.trust_state.clone(),
            maze_state: snapshot.maze_state.clone(),
            summary: snapshot.summary.clone(),
        };
        let line = serde_json::to_string(&event)
            .map_err(|err| format!("Security-Audit konnte nicht serialisiert werden: {err}"))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)
            .map_err(|err| format!("Security-Audit konnte nicht geoeffnet werden: {err}"))?;
        writeln!(file, "{line}")
            .map_err(|err| format!("Security-Audit konnte nicht geschrieben werden: {err}"))?;
        Ok(())
    }

    pub fn load_recent_audit(&self, limit: usize) -> Vec<SecurityAuditEvent> {
        let Ok(raw) = fs::read_to_string(&self.audit_path) else {
            return Vec::new();
        };
        let mut events = raw
            .lines()
            .filter_map(|line| serde_json::from_str::<SecurityAuditEvent>(line).ok())
            .collect::<Vec<_>>();
        if events.len() > limit {
            events.drain(0..events.len().saturating_sub(limit));
        }
        events.reverse();
        events
    }

    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    fn privacy_boundary_present(&self) -> bool {
        let path = self.project_root.join("src").join("runtime_signal.rs");
        let Ok(raw) = fs::read_to_string(path) else {
            return false;
        };
        raw.contains("pub fn is_private_context")
            && raw.contains("contains_email_pattern")
            && raw.contains("contains_password_field_pattern")
    }
}

fn sha256_path(path: &Path) -> String {
    let Ok(bytes) = fs::read(path) else {
        return sha256_hex(path.to_string_lossy().as_bytes());
    };
    sha256_hex(&bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
