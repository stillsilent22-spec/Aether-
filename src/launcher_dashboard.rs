// ============================================================================
// Launcher Dashboard: Unified Service Management & Build Task Orchestration
// ============================================================================
// Centralized dashboard for all Aether services (Symbiont, Rust-UI,
// VSCode Extension) with real-time status, logs, and build task controls.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Service status indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Idle,        // Not running
    Starting,    // Transition state
    Running,     // Active process
    Stopping,    // Shutting down
    Error,       // Last operation failed
    Disabled,    // Service unavailable on this platform
}

impl ServiceStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ServiceStatus::Idle => "Idle",
            ServiceStatus::Starting => "Starting...",
            ServiceStatus::Running => "Running",
            ServiceStatus::Stopping => "Stopping...",
            ServiceStatus::Error => "Error",
            ServiceStatus::Disabled => "Disabled",
        }
    }

    pub fn color_rgb(&self) -> (f32, f32, f32) {
        match self {
            ServiceStatus::Idle => (0.7, 0.7, 0.7),           // Gray
            ServiceStatus::Starting => (1.0, 0.8, 0.0),       // Orange
            ServiceStatus::Running => (0.0, 1.0, 0.0),        // Green
            ServiceStatus::Stopping => (1.0, 0.6, 0.0),       // Orange-red
            ServiceStatus::Error => (1.0, 0.0, 0.0),          // Red
            ServiceStatus::Disabled => (0.5, 0.5, 0.5),       // Dark gray
        }
    }
}

/// Info about a managed service
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub status: ServiceStatus,
    pub process_id: Option<u32>,
    pub last_error: String,
    pub uptime_secs: u64,
    pub log_lines: Vec<String>,
    pub log_fresh: bool,
    pub port: Option<u16>,
    pub stop_allowed_in_settings_only: bool,
}

impl ServiceInfo {
    pub fn new(id: impl Into<String>, name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: desc.into(),
            status: ServiceStatus::Idle,
            process_id: None,
            last_error: String::new(),
            uptime_secs: 0,
            log_lines: Vec::new(),
            log_fresh: false,
            port: None,
            stop_allowed_in_settings_only: false,
        }
    }
}

/// Launcher display modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherMode {
    Services,       // Service status & control
    BuildTasks,     // Compile/build operations
    Logs,           // Real-time log viewer
    Configuration,  // Settings & environment
}

impl LauncherMode {
    pub fn label(&self) -> &'static str {
        match self {
            LauncherMode::Services => "Services",
            LauncherMode::BuildTasks => "Build Tasks",
            LauncherMode::Logs => "Logs",
            LauncherMode::Configuration => "Configuration",
        }
    }
}

/// Build task descriptor
#[derive(Debug, Clone)]
pub struct BuildTask {
    pub id: String,
    pub name: String,
    pub description: String,
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub running: bool,
    pub last_exit_code: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct BuildTaskResult {
    pub task_id: String,
    pub task_name: String,
    pub exit_code: i32,
    pub stdout_tail: Vec<String>,
    pub stderr_tail: Vec<String>,
}

/// Launcher state manager
pub struct LauncherState {
    pub services: HashMap<String, ServiceInfo>,
    pub mode: LauncherMode,
    pub build_tasks: Vec<BuildTask>,
    pub unified_log: Vec<(u64, String)>, // (timestamp_ms, log_line)
    pub log_autoscroll: bool,
    pub platform_info: String,
    active_processes: HashMap<String, Child>,
    service_started_ms: HashMap<String, u64>,
    service_log_paths: HashMap<String, PathBuf>,
}

impl LauncherState {
    pub fn new() -> Self {
        let mut services = HashMap::new();

        // Symbiont Server
        services.insert(
            "symbiont".to_string(),
            ServiceInfo {
                id: "symbiont".to_string(),
                name: "Symbiont Server".to_string(),
                description:
                    "Python JSON-RPC Symbiont with event streaming & hybrid bridge".to_string(),
                status: ServiceStatus::Idle,
                process_id: None,
                last_error: String::new(),
                uptime_secs: 0,
                log_lines: Vec::new(),
                log_fresh: false,
                port: Some(38571),
                stop_allowed_in_settings_only: false,
            },
        );

        // Iced Shell (Rust UI)
        services.insert(
            "iced".to_string(),
            ServiceInfo {
                id: "iced".to_string(),
                name: "Aether Iced Shell".to_string(),
                description: "Rust/Iced main UI (currently running)".to_string(),
                status: ServiceStatus::Running,
                process_id: std::process::id().into(),
                last_error: String::new(),
                uptime_secs: 0,
                log_lines: Vec::new(),
                log_fresh: false,
                port: None,
                stop_allowed_in_settings_only: false,
            },
        );

        // VSCode Extension
        services.insert(
            "vscode".to_string(),
            ServiceInfo {
                id: "vscode".to_string(),
                name: "VSCode Extension".to_string(),
                description: "Symbiont chat integration for VS Code".to_string(),
                status: ServiceStatus::Idle,
                process_id: None,
                last_error: String::new(),
                uptime_secs: 0,
                log_lines: Vec::new(),
                log_fresh: false,
                port: None,
                stop_allowed_in_settings_only: false,
            },
        );

        // Local Aether System Service
        services.insert(
            "aether_system".to_string(),
            ServiceInfo {
                id: "aether_system".to_string(),
                name: "Aether System Service".to_string(),
                description: "Local Windows/Linux API daemon for invariant analysis; network gossip is handled by the overlay manager.".to_string(),
                status: ServiceStatus::Idle,
                process_id: None,
                last_error: String::new(),
                uptime_secs: 0,
                log_lines: Vec::new(),
                log_fresh: false,
                port: Some(40011),
                stop_allowed_in_settings_only: true,
            },
        );

        // Overlay / DHT manager for Yggdrasil gossip
        services.insert(
            "aether_overlay".to_string(),
            ServiceInfo {
                id: "aether_overlay".to_string(),
                name: "Aether Overlay Network".to_string(),
                description: "Headless network manager for Yggdrasil overlay and DHT gossip connectivity.".to_string(),
                status: ServiceStatus::Idle,
                process_id: None,
                last_error: String::new(),
                uptime_secs: 0,
                log_lines: Vec::new(),
                log_fresh: false,
                port: None,
                stop_allowed_in_settings_only: true,
            },
        );

        let build_tasks = vec![
            BuildTask {
                id: "cargo-check".to_string(),
                name: "Cargo Check".to_string(),
                description: "Validate Rust binaries without building".to_string(),
                command: "cargo".to_string(),
                args: vec!["check".to_string(), "--all".to_string()],
                working_dir: None,
                running: false,
                last_exit_code: None,
            },
            BuildTask {
                id: "cargo-build".to_string(),
                name: "Cargo Build (Debug)".to_string(),
                description: "Build Rust binaries in debug mode".to_string(),
                command: "cargo".to_string(),
                args: vec!["build".to_string(), "--all".to_string()],
                working_dir: None,
                running: false,
                last_exit_code: None,
            },
            BuildTask {
                id: "cargo-release".to_string(),
                name: "Cargo Build (Release)".to_string(),
                description: "Build optimized release binaries".to_string(),
                command: "cargo".to_string(),
                args: vec!["build".to_string(), "--release".to_string(), "--all".to_string()],
                working_dir: None,
                running: false,
                last_exit_code: None,
            },
            BuildTask {
                id: "npm-compile".to_string(),
                name: "NPM Compile (Symbiont)".to_string(),
                description: "Compile Symbiont TypeScript/Node components".to_string(),
                command: "npm".to_string(),
                args: vec!["run".to_string(), "compile".to_string()],
                working_dir: Some(PathBuf::from("aether-symbiont")),
                running: false,
                last_exit_code: None,
            },
            BuildTask {
                id: "pytest".to_string(),
                name: "Python Tests".to_string(),
                description: "Run pytest on Python modules".to_string(),
                command: "pytest".to_string(),
                args: vec!["tests/".to_string(), "-v".to_string()],
                working_dir: None,
                running: false,
                last_exit_code: None,
            },
        ];

        let platform_info = format!(
            "OS: {}, Arch: {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );

        Self {
            services,
            mode: LauncherMode::Services,
            build_tasks,
            unified_log: Vec::new(),
            log_autoscroll: true,
            platform_info,
            active_processes: HashMap::new(),
            service_started_ms: HashMap::new(),
            service_log_paths: HashMap::new(),
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn root_dir() -> PathBuf {
        PathBuf::from(".")
    }

    fn launcher_log_dir() -> PathBuf {
        Self::root_dir().join("logs").join("launcher")
    }

    fn tail_lines(text: &str, limit: usize) -> Vec<String> {
        text.lines()
            .rev()
            .take(limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn service_log_path(service_id: &str) -> PathBuf {
        Self::launcher_log_dir().join(format!("{service_id}.log"))
    }

    fn prepare_service_log(service_id: &str) -> Result<(PathBuf, std::fs::File), String> {
        let dir = Self::launcher_log_dir();
        fs::create_dir_all(&dir)
            .map_err(|err| format!("Launcher log directory could not be created: {err}"))?;
        let path = Self::service_log_path(service_id);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| format!("Service log could not be opened: {err}"))?;
        Ok((path, file))
    }

    fn refresh_service_logs(&mut self) {
        let ids: Vec<String> = self.services.keys().cloned().collect();
        for id in ids {
            let log_path = self
                .service_log_paths
                .get(&id)
                .cloned()
                .unwrap_or_else(|| Self::service_log_path(&id));
            if let Ok(raw) = fs::read_to_string(&log_path) {
                let tail = Self::tail_lines(&raw, 20);
                if let Some(service) = self.services.get_mut(&id) {
                    let prev_last = service.log_lines.last().cloned();
                    let new_last = tail.last().cloned();
                    service.log_fresh = new_last.is_some() && new_last != prev_last;
                    service.log_lines = tail;
                }
            } else if let Some(service) = self.services.get_mut(&id) {
                service.log_fresh = false;
            }
        }
    }

    fn update_service_status(&mut self, service_id: &str, status: ServiceStatus, pid: Option<u32>) {
        if let Some(service) = self.services.get_mut(service_id) {
            service.status = status;
            service.process_id = pid;
            if status == ServiceStatus::Idle {
                service.uptime_secs = 0;
            }
        }
    }

    pub fn poll_processes(&mut self) {
        let mut finished: Vec<(String, Option<i32>)> = Vec::new();
        for (id, child) in &mut self.active_processes {
            match child.try_wait() {
                Ok(Some(status)) => finished.push((id.clone(), status.code())),
                Ok(None) => {
                    if let Some(start_ms) = self.service_started_ms.get(id).copied() {
                        let uptime = (Self::now_ms().saturating_sub(start_ms)) / 1000;
                        if let Some(service) = self.services.get_mut(id) {
                            service.uptime_secs = uptime;
                            service.status = ServiceStatus::Running;
                        }
                    }
                }
                Err(err) => {
                    finished.push((id.clone(), Some(-1)));
                    if let Some(service) = self.services.get_mut(id) {
                        service.last_error = format!("Process status check failed: {err}");
                    }
                }
            }
        }

        for (id, code) in finished {
            self.active_processes.remove(&id);
            self.service_started_ms.remove(&id);
            self.update_service_status(&id, ServiceStatus::Idle, None);
            self.log(format!("[SERVICE:{id}] exited with code {}", code.unwrap_or(-1)));
        }
        self.refresh_service_logs();
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        let timestamp = Self::now_ms();
        self.unified_log.push((timestamp, msg.into()));
        if self.unified_log.len() > 5000 {
            self.unified_log.drain(0..1000);
        }
    }

    /// Attempt to start a service
    pub fn start_service(&mut self, service_id: &str) -> Result<(), String> {
        self.poll_processes();

        let service_name = self
            .services
            .get(service_id)
            .ok_or_else(|| format!("Service {} not found", service_id))?
            .name
            .clone();

        if self.active_processes.contains_key(service_id) {
            return Err(format!("{} already running", service_name));
        }

        if service_id == "iced" {
            return Err("The currently running Iced shell cannot be started from inside itself".to_owned());
        }

        self.update_service_status(service_id, ServiceStatus::Starting, None);
        self.log(format!("[{}] Starting...", service_name));

        let root = Self::root_dir();
        let (log_path, log_file) = Self::prepare_service_log(service_id)?;
        let stderr_file = log_file
            .try_clone()
            .map_err(|err| format!("Service log clone failed: {err}"))?;
        let mut cmd = match service_id {
            "symbiont" => {
                let settings = crate::py_bridge::load_hybrid_settings();
                let python = if settings.symbiont.python_path.trim().is_empty() {
                    "python".to_owned()
                } else {
                    settings.symbiont.python_path.clone()
                };
                if let Some(service) = self.services.get_mut(service_id) {
                    service.port = Some(settings.symbiont.port);
                }
                let mut c = Command::new(python);
                c.arg(&settings.symbiont.server_path)
                    .arg("--tcp-host")
                    .arg(&settings.symbiont.host)
                    .arg("--tcp-port")
                    .arg(settings.symbiont.port.to_string())
                    .current_dir(&root)
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log_file))
                    .stderr(Stdio::from(stderr_file));
                c
            }
            "vscode" => {
                let mut c = Command::new("code");
                c.arg(".")
                    .arg("--extensionDevelopmentPath")
                    .arg("aether-symbiont")
                    .current_dir(&root)
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log_file))
                    .stderr(Stdio::from(stderr_file));
                c
            }
            "aether_system" => {
                let executable_name = if cfg!(windows) {
                    "aether_system_service.exe"
                } else {
                    "aether_system_service"
                };
                let service_path = root.join("tools").join(executable_name);
                let mut c = Command::new(service_path);
                c.arg("--port").arg("40011")
                    .current_dir(&root)
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log_file))
                    .stderr(Stdio::from(stderr_file));
                c
            }
            "aether_overlay" => {
                let python = "python";
                let mut c = Command::new(python);
                c.arg("daemon_headless.py")
                    .arg("--interval")
                    .arg("10")
                    .current_dir(&root)
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log_file))
                    .stderr(Stdio::from(stderr_file));
                c
            }
            _ => {
                self.update_service_status(service_id, ServiceStatus::Idle, None);
                return Err(format!("{} cannot be started from launcher", service_name));
            }
        };

        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id();
                self.active_processes.insert(service_id.to_owned(), child);
                self.service_started_ms
                    .insert(service_id.to_owned(), Self::now_ms());
                self.service_log_paths.insert(service_id.to_owned(), log_path);
                self.update_service_status(service_id, ServiceStatus::Running, Some(pid));
                self.log(format!("[{}] Started (pid={pid})", service_name));
                Ok(())
            }
            Err(err) => {
                self.update_service_status(service_id, ServiceStatus::Error, None);
                if let Some(service) = self.services.get_mut(service_id) {
                    service.last_error = err.to_string();
                }
                Err(format!("{} failed to start: {err}", service_name))
            }
        }
    }

    /// Stop a running service
    pub fn stop_service(&mut self, service_id: &str, allow_settings_override: bool) -> Result<(), String> {
        self.poll_processes();
        let service_name = self
            .services
            .get(service_id)
            .ok_or_else(|| format!("Service {} not found", service_id))?
            .name
            .clone();

        if service_id == "iced" {
            return Err("The running Iced shell cannot be stopped from this UI".to_owned());
        }

        if let Some(service) = self.services.get(service_id) {
            if service.stop_allowed_in_settings_only && !allow_settings_override {
                return Err(format!(
                    "{} may only be stopped from the settings screen.",
                    service_name
                ));
            }
        }

        self.update_service_status(service_id, ServiceStatus::Stopping, None);
        self.log(format!("[{}] Stopping...", service_name));

        let mut child = self
            .active_processes
            .remove(service_id)
            .ok_or_else(|| format!("{} is not running", service_name))?;

        if let Err(err) = child.kill() {
            self.update_service_status(service_id, ServiceStatus::Error, None);
            if let Some(service) = self.services.get_mut(service_id) {
                service.last_error = err.to_string();
            }
            return Err(format!("{} could not be stopped: {err}", service_name));
        }
        let _ = child.wait();

        self.service_started_ms.remove(service_id);
        self.update_service_status(service_id, ServiceStatus::Idle, None);
        self.log(format!("[{}] Stopped", service_name));
        self.refresh_service_logs();
        Ok(())
    }

    pub fn build_task(&self, task_id: &str) -> Option<BuildTask> {
        self.build_tasks.iter().find(|task| task.id == task_id).cloned()
    }

    pub fn mark_build_task_running(&mut self, task_id: &str) -> Result<String, String> {
        // Limit the mutable borrow scope to avoid double mutable borrow
        let task_name;
        {
            let task = self
                .build_tasks
                .iter_mut()
                .find(|task| task.id == task_id)
                .ok_or_else(|| format!("Task {} not found", task_id))?;
            if task.running {
                return Err(format!("Task {} already running", task.name));
            }
            task_name = task.name.clone();
            task.running = true;
            task.last_exit_code = None;
        }
        self.log(format!("[BUILD] Starting: {}", task_name));
        Ok(task_name)
    }

    pub fn finish_build_task(&mut self, result: &BuildTaskResult) {
        if let Some(task) = self.build_tasks.iter_mut().find(|task| task.id == result.task_id) {
            task.running = false;
            task.last_exit_code = Some(result.exit_code);
        }

        if result.exit_code == 0 {
            self.log(format!("[BUILD] Completed: {} (exit=0)", result.task_name));
        } else {
            self.log(format!("[BUILD] Failed: {} (exit={})", result.task_name, result.exit_code));
        }

        for line in &result.stdout_tail {
            if !line.trim().is_empty() {
                self.log(format!("[BUILD:stdout] {line}"));
            }
        }
        for line in &result.stderr_tail {
            if !line.trim().is_empty() {
                self.log(format!("[BUILD:stderr] {line}"));
            }
        }
    }

    pub fn fail_build_task(&mut self, task_id: &str, error: &str) {
        if let Some(task) = self.build_tasks.iter_mut().find(|task| task.id == task_id) {
            task.running = false;
            task.last_exit_code = Some(-1);
        }
        self.log(format!("[BUILD] Launch failed for {task_id}: {error}"));
    }

    pub fn get_service(&self, id: &str) -> Option<&ServiceInfo> {
        self.services.get(id)
    }

    pub fn get_service_mut(&mut self, id: &str) -> Option<&mut ServiceInfo> {
        self.services.get_mut(id)
    }

    pub fn all_services(&self) -> Vec<&ServiceInfo> {
        self.services.values().collect()
    }

    pub fn recent_logs(&self, limit: usize) -> Vec<(u64, String)> {
        let start = if self.unified_log.len() > limit {
            self.unified_log.len() - limit
        } else {
            0
        };
        self.unified_log[start..].to_vec()
    }
}

impl Default for LauncherState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn run_build_task(task: BuildTask) -> Result<BuildTaskResult, String> {
    let mut cmd = Command::new(&task.command);
    cmd.args(&task.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(dir) = task.working_dir.clone() {
        if dir.is_absolute() {
            cmd.current_dir(dir);
        } else {
            cmd.current_dir(PathBuf::from(".").join(dir));
        }
    } else {
        cmd.current_dir(PathBuf::from("."));
    }

    let output = cmd
        .output()
        .map_err(|err| format!("Build task '{}' failed to start: {err}", task.name))?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout_tail = LauncherState::tail_lines(&String::from_utf8_lossy(&output.stdout), 5);
    let stderr_tail = LauncherState::tail_lines(&String::from_utf8_lossy(&output.stderr), 5);

    Ok(BuildTaskResult {
        task_id: task.id,
        task_name: task.name,
        exit_code,
        stdout_tail,
        stderr_tail,
    })
}
