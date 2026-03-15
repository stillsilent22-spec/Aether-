use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

#[derive(Debug, Clone, Default)]
pub struct EmbeddedBrowserEvent {
    pub kind: String,
    pub url: String,
    pub title: String,
    pub message: String,
    pub secure: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BrowserHostRect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

impl BrowserHostRect {
    pub fn normalized(self) -> Self {
        Self {
            x: self.x.max(0),
            y: self.y.max(0),
            width: self.width.max(320),
            height: self.height.max(180),
        }
    }
}

pub struct EmbeddedBrowser {
    python_command: Option<String>,
    script_path: Option<PathBuf>,
    stdin: Option<Arc<Mutex<ChildStdin>>>,
    rx: Option<mpsc::Receiver<EmbeddedBrowserEvent>>,
    child: Option<Child>,
    host: NativeBrowserHost,
    visible: bool,
    docked: bool,
}

impl EmbeddedBrowser {
    pub fn new() -> Self {
        let root = find_repo_root();
        let script_path = root
            .as_ref()
            .map(|path| path.join("browser_dock_bridge.py"))
            .filter(|path| path.is_file());
        Self {
            python_command: detect_python_command(),
            script_path,
            stdin: None,
            rx: None,
            child: None,
            host: NativeBrowserHost::default(),
            visible: false,
            docked: false,
        }
    }

    pub fn available(&self) -> bool {
        self.python_command.is_some() && self.script_path.is_some()
    }

    pub fn ensure_started(&mut self) -> Result<(), String> {
        if self.child.is_some() {
            return Ok(());
        }
        let python_command = self.python_command.clone().ok_or_else(|| {
            "Kein lokaler Python-Interpreter fuer den Browser gefunden.".to_owned()
        })?;
        let script_path = self
            .script_path
            .clone()
            .ok_or_else(|| "browser_dock_bridge.py wurde nicht gefunden.".to_owned())?;
        let root = script_path
            .parent()
            .ok_or_else(|| "Ungueltiger Browser-Bridge-Pfad.".to_owned())?
            .to_path_buf();

        let mut command = Command::new(python_command);
        command
            .arg(script_path.as_os_str())
            .arg("https://duckduckgo.com/")
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|err| format!("Browser-Bridge konnte nicht gestartet werden: {err}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "Browser-Bridge liefert keinen stdin-Kanal.".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "Browser-Bridge liefert keinen stdout-Kanal.".to_owned())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "Browser-Bridge liefert keinen stderr-Kanal.".to_owned())?;

        let (tx, rx) = mpsc::channel::<EmbeddedBrowserEvent>();
        spawn_stdout_reader(stdout, tx.clone());
        spawn_stderr_reader(stderr, tx);

        self.stdin = Some(Arc::new(Mutex::new(stdin)));
        self.rx = Some(rx);
        self.child = Some(child);
        Ok(())
    }

    pub fn navigate(&mut self, url: &str) -> Result<(), String> {
        self.ensure_started()?;
        self.send_command(json!({"cmd": "navigate", "url": url}))
    }

    pub fn search_duckduckgo(&mut self, query: &str) -> Result<(), String> {
        self.ensure_started()?;
        self.send_command(json!({"cmd": "search", "query": query}))
    }

    pub fn show_docked(&mut self, window_title: &str, rect: BrowserHostRect) -> Result<(), String> {
        self.ensure_started()?;
        let rect = rect.normalized();
        let host_handle = self.host.ensure(window_title, rect)?;
        self.send_command(json!({
            "cmd": "dock",
            "host_handle": host_handle,
            "width": rect.width,
            "height": rect.height
        }))?;
        self.visible = true;
        self.docked = true;
        self.host.show();
        Ok(())
    }

    pub fn sync_bounds(&mut self, rect: BrowserHostRect) -> Result<(), String> {
        if !self.docked {
            return Ok(());
        }
        let rect = rect.normalized();
        self.host.update(rect)?;
        self.send_command(json!({
            "cmd": "bounds",
            "width": rect.width,
            "height": rect.height
        }))?;
        Ok(())
    }

    pub fn hide(&mut self) {
        if !self.visible {
            return;
        }
        let _ = self.send_command(json!({"cmd": "hide"}));
        self.host.hide();
        self.visible = false;
    }

    pub fn show(&mut self) {
        if self.visible {
            return;
        }
        let _ = self.send_command(json!({"cmd": "show"}));
        self.host.show();
        self.visible = true;
    }

    pub fn poll_events(&mut self, limit: usize) -> Vec<EmbeddedBrowserEvent> {
        let mut items = Vec::new();
        let Some(rx) = &self.rx else {
            return items;
        };
        for _ in 0..limit.max(1) {
            match rx.try_recv() {
                Ok(item) => items.push(item),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        items
    }

    fn send_command(&mut self, payload: Value) -> Result<(), String> {
        let Some(stdin) = &self.stdin else {
            return Err("Browser-Bridge ist nicht aktiv.".to_owned());
        };
        let mut writer = stdin
            .lock()
            .map_err(|_| "Browser-Bridge ist gerade blockiert.".to_owned())?;
        writeln!(writer, "{}", payload)
            .map_err(|err| format!("Browser-Befehl konnte nicht gesendet werden: {err}"))?;
        writer
            .flush()
            .map_err(|err| format!("Browser-Befehl konnte nicht geflusht werden: {err}"))?;
        Ok(())
    }
}

impl Drop for EmbeddedBrowser {
    fn drop(&mut self) {
        let _ = self.send_command(json!({"cmd": "stop"}));
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_stdout_reader(stdout: std::process::ChildStdout, tx: mpsc::Sender<EmbeddedBrowserEvent>) {
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let Ok(line) = line else {
                break;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event = serde_json::from_str::<Value>(trimmed)
                .ok()
                .map(parse_event)
                .unwrap_or_else(|| EmbeddedBrowserEvent {
                    kind: "error".to_owned(),
                    message: format!("Browser-Bridge sendete unlesbaren Text: {trimmed}"),
                    ..EmbeddedBrowserEvent::default()
                });
            let _ = tx.send(event);
        }
    });
}

fn spawn_stderr_reader(stderr: std::process::ChildStderr, tx: mpsc::Sender<EmbeddedBrowserEvent>) {
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let Ok(line) = line else {
                break;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let _ = tx.send(EmbeddedBrowserEvent {
                kind: "stderr".to_owned(),
                message: trimmed.to_owned(),
                ..EmbeddedBrowserEvent::default()
            });
        }
    });
}

fn parse_event(value: Value) -> EmbeddedBrowserEvent {
    EmbeddedBrowserEvent {
        kind: value
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        url: value
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        title: value
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        message: value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        secure: value
            .get("secure")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn detect_python_command() -> Option<String> {
    if let Ok(value) = std::env::var("AETHER_PYTHON") {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    let preferred =
        PathBuf::from(r"C:\Users\kalle\AppData\Local\Programs\Python\Python312\python.exe");
    if preferred.is_file() {
        return Some(preferred.to_string_lossy().to_string());
    }
    if command_exists("python") {
        return Some("python".to_owned());
    }
    None
}

fn command_exists(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn find_repo_root() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        candidates.push(current_exe);
    }
    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir);
    }
    for candidate in candidates {
        let mut path = if candidate.is_file() {
            candidate
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or(candidate)
        } else {
            candidate
        };
        loop {
            if path.join("modules").join("browser_engine.py").is_file()
                && path.join("browser_dock_bridge.py").is_file()
            {
                return Some(path.clone());
            }
            if !path.pop() {
                break;
            }
        }
    }
    None
}

#[derive(Default)]
struct NativeBrowserHost {
    #[cfg(target_os = "windows")]
    parent_hwnd: windows_sys::Win32::Foundation::HWND,
    #[cfg(target_os = "windows")]
    host_hwnd: windows_sys::Win32::Foundation::HWND,
}

impl NativeBrowserHost {
    fn ensure(&mut self, window_title: &str, rect: BrowserHostRect) -> Result<isize, String> {
        #[cfg(target_os = "windows")]
        {
            let parent = find_main_window(window_title)
                .ok_or_else(|| "Aether-Hauptfenster wurde noch nicht gefunden.".to_owned())?;
            if self.parent_hwnd != parent || self.host_hwnd.is_null() {
                self.destroy();
                self.parent_hwnd = parent;
                self.host_hwnd = create_host_window(parent, rect)?;
            } else {
                move_host_window(self.host_hwnd, rect)?;
            }
            show_host_window(self.host_hwnd, true);
            return Ok(self.host_hwnd as isize);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (window_title, rect);
            Err("Eingebetteter Browser ist nur unter Windows implementiert.".to_owned())
        }
    }

    fn update(&mut self, rect: BrowserHostRect) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            if self.host_hwnd.is_null() {
                return Ok(());
            }
            move_host_window(self.host_hwnd, rect)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = rect;
            Ok(())
        }
    }

    fn show(&self) {
        #[cfg(target_os = "windows")]
        if !self.host_hwnd.is_null() {
            show_host_window(self.host_hwnd, true);
        }
    }

    fn hide(&self) {
        #[cfg(target_os = "windows")]
        if !self.host_hwnd.is_null() {
            show_host_window(self.host_hwnd, false);
        }
    }

    fn destroy(&mut self) {
        #[cfg(target_os = "windows")]
        if !self.host_hwnd.is_null() {
            unsafe {
                let _ = windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow(self.host_hwnd);
            }
            self.host_hwnd = std::ptr::null_mut();
        }
    }
}

impl Drop for NativeBrowserHost {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn create_host_window(
    parent: windows_sys::Win32::Foundation::HWND,
    rect: BrowserHostRect,
) -> Result<windows_sys::Win32::Foundation::HWND, String> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_VISIBLE,
    };

    let class_name = wide_null("STATIC");
    let window_name = wide_null("AetherBrowserHost");
    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            window_name.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
            rect.x,
            rect.y,
            rect.width,
            rect.height,
            parent,
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return Err("Browser-Hostfenster konnte nicht erstellt werden.".to_owned());
    }
    Ok(hwnd)
}

#[cfg(target_os = "windows")]
fn move_host_window(
    hwnd: windows_sys::Win32::Foundation::HWND,
    rect: BrowserHostRect,
) -> Result<(), String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::MoveWindow;

    let ok = unsafe { MoveWindow(hwnd, rect.x, rect.y, rect.width, rect.height, 1) };
    if ok == 0 {
        return Err("Browser-Hostfenster konnte nicht verschoben werden.".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn show_host_window(hwnd: windows_sys::Win32::Foundation::HWND, visible: bool) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE, SW_SHOW};

    unsafe {
        let _ = ShowWindow(hwnd, if visible { SW_SHOW } else { SW_HIDE });
    }
}

#[cfg(target_os = "windows")]
fn find_main_window(title: &str) -> Option<windows_sys::Win32::Foundation::HWND> {
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
    };

    struct FindContext {
        pid: u32,
        title: String,
        result: HWND,
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let context = &mut *(lparam as *mut FindContext);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid != context.pid {
            return 1;
        }
        let text_len = GetWindowTextLengthW(hwnd);
        if text_len <= 0 {
            return 1;
        }
        let mut buffer = vec![0u16; text_len as usize + 1];
        let written = GetWindowTextW(hwnd, buffer.as_mut_ptr(), text_len + 1);
        if written <= 0 {
            return 1;
        }
        let value = String::from_utf16_lossy(&buffer[..written as usize]);
        if value == context.title {
            context.result = hwnd;
            return 0;
        }
        1
    }

    let mut context = FindContext {
        pid: unsafe { GetCurrentProcessId() },
        title: title.to_owned(),
        result: std::ptr::null_mut(),
    };
    unsafe {
        let _ = EnumWindows(Some(enum_proc), &mut context as *mut _ as isize);
    }
    (!context.result.is_null()).then_some(context.result)
}
