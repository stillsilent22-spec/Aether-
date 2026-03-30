//! Aether – Hardware-Profiler (pure Rust, keine externen Deps).
//!
//! Erkennt CPU, RAM, Disk-Typ und leitet daraus das optimale
//! RuntimeProfile ab. Wird beim Start einmalig aufgerufen.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskKind { Nvme, Ssd, Hdd, Unknown }

#[derive(Debug, Clone)]
pub struct HardwareProfile {
    pub cpu_cores_logical: usize,
    pub cpu_cores_physical: usize,
    pub cpu_freq_mhz: f64,
    pub ram_total_mb: u64,
    pub ram_available_mb: u64,
    pub disk_kind: DiskKind,
    pub is_old_hardware: bool,
}

impl HardwareProfile {
    /// Erkennt das empfohlene RuntimeProfile für die iced_shell.
    /// Legacy = sehr alte Hardware (≤2 Kerne, <2 GHz, <2 GB RAM, HDD)
    /// LowPower = schwache Hardware (≤4 Kerne ODER <4 GB RAM ODER HDD)
    /// Auto = alles andere
    pub fn recommended_profile(&self) -> RecommendedProfile {
        if self.is_old_hardware {
            return RecommendedProfile::Legacy;
        }
        let weak = self.cpu_cores_logical <= 4
            || self.ram_total_mb < 4096
            || self.disk_kind == DiskKind::Hdd;
        if weak { RecommendedProfile::LowPower } else { RecommendedProfile::Auto }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedProfile { Auto, LowPower, Legacy }

/// Haupteinstieg: erkennt Hardware plattformübergreifend (Windows / Linux).
/// Schlägt nie fehl — liefert im Fehlerfall konservative Defaults.
pub fn detect() -> HardwareProfile {
    let cores_logical = detect_logical_cores();
    let cores_physical = (cores_logical / 2).max(1);
    let freq_mhz = detect_cpu_freq_mhz();
    let (ram_total, ram_avail) = detect_ram_mb();
    let disk = detect_disk_kind();

    let mut old_score = 0u32;
    // Only penalise when values are actually known (non-zero means detected)
    if ram_total > 0 && ram_total < 2048 { old_score += 2; }
    if freq_mhz > 0.0 && freq_mhz < 2000.0 { old_score += 2; }
    if disk == DiskKind::Hdd { old_score += 1; }
    if cores_logical <= 2 { old_score += 1; }

    HardwareProfile {
        cpu_cores_logical: cores_logical,
        cpu_cores_physical: cores_physical,
        cpu_freq_mhz: freq_mhz,
        ram_total_mb: ram_total,
        ram_available_mb: ram_avail,
        disk_kind: disk,
        is_old_hardware: old_score >= 2,
    }
}

// ── CPU ────────────────────────────────────────────────────────────────────

fn detect_logical_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn detect_cpu_freq_mhz() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in text.lines() {
                if line.starts_with("cpu MHz") {
                    if let Some(val) = line.split(':').nth(1) {
                        if let Ok(f) = val.trim().parse::<f64>() {
                            return f;
                        }
                    }
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(mhz) = read_cpu_mhz_windows() {
            return mhz as f64;
        }
    }
    0.0
}

#[cfg(target_os = "windows")]
fn read_cpu_mhz_windows() -> Option<u32> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    unsafe {
        let path: Vec<u16> = OsStr::new(
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
        ).encode_wide().chain(Some(0)).collect();
        let value: Vec<u16> = OsStr::new("~MHz").encode_wide().chain(Some(0)).collect();
        let mut hkey = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return None;
        }
        let mut data = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let mut kind = 0u32;
        let result = RegQueryValueExW(
            hkey, value.as_ptr(), std::ptr::null_mut(),
            &mut kind, &mut data as *mut u32 as *mut u8, &mut size,
        );
        RegCloseKey(hkey);
        if result == 0 { Some(data) } else { None }
    }
}

// ── RAM ────────────────────────────────────────────────────────────────────

fn detect_ram_mb() -> (u64, u64) {
    #[cfg(target_os = "windows")]
    {
        return detect_ram_windows();
    }
    #[cfg(target_os = "linux")]
    {
        return detect_ram_linux();
    }
    #[allow(unreachable_code)]
    // Fallback for unsupported platforms (macOS, BSD, etc.):
    // Returns (0, 0) — detect() treats 0 as "unknown" and skips the low-RAM score.
    (0, 0)
}

#[cfg(target_os = "windows")]
fn detect_ram_windows() -> (u64, u64) {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    unsafe {
        let mut status: MEMORYSTATUSEX = std::mem::zeroed();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut status) != 0 {
            let total = status.ullTotalPhys / (1024 * 1024);
            let avail = status.ullAvailPhys / (1024 * 1024);
            return (total, avail);
        }
    }
    (0, 0)
}

#[cfg(target_os = "linux")]
fn detect_ram_linux() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in text.lines() {
        if line.starts_with("MemTotal:") {
            total = parse_meminfo_kb(line) / 1024;
        } else if line.starts_with("MemAvailable:") {
            avail = parse_meminfo_kb(line) / 1024;
        }
    }
    (total, avail)
}

#[cfg(target_os = "linux")]
fn parse_meminfo_kb(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

// ── Disk ───────────────────────────────────────────────────────────────────

fn detect_disk_kind() -> DiskKind {
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                let rota = entry.path().join("queue/rotational");
                if let Ok(val) = std::fs::read_to_string(&rota) {
                    return match val.trim() {
                        "1" => DiskKind::Hdd,
                        _ => DiskKind::Ssd,
                    };
                }
            }
        }
    }
    // Windows: konservativ Unknown annehmen (PowerShell-Aufruf bewusst vermieden)
    DiskKind::Unknown
}
