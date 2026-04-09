//! Aether – Hardware-Profiler (pure Rust, keine externen Deps).
//!
//! Erkennt CPU, RAM, Disk-Typ, OS-Plattform und leitet daraus das optimale
//! RuntimeProfile und den emergierten Netzwerk-Tier ab.
//! Wird beim Start einmalig aufgerufen; schreibt data/interbus/hw_capability.json.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskKind { Nvme, Ssd, Hdd, Unknown }

/// Betriebssystem-Plattform (für Fallback-Logik).
/// Windows 9x/2000/XP können moderne Rust-Binaries nicht ausführen —
/// aber Linux-Embedded (RPi), alte Kernel und XP via Crosscompile sind real.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsPlatform {
    /// Windows 95 / 98 / ME (NT-Kernel 4.x oder Win9x-Kernel — kann diese Binary eigentlich nicht starten)
    Win9x,
    /// Windows 2000 (NT 5.0)
    Win2000,
    /// Windows XP / Server 2003 (NT 5.1 / 5.2)
    WinXP,
    /// Windows Vista / 7 / Server 2008 (NT 6.0 / 6.1)
    WinVista7,
    /// Windows 8 / 8.1 / 10 / 11 (NT 6.2+)
    WinModern,
    /// Linux Kernel < 4.0 (alte Embedded-Systeme, RPi 1/2 mit altem Kernel)
    LinuxLegacy,
    /// Linux Kernel ≥ 4.0, kein RPi
    LinuxModern,
    /// Raspberry Pi (alle Modelle, erkannt über /proc/cpuinfo)
    RaspberryPi,
    /// macOS / BSD / unbekannt
    Unknown,
}

/// Netzwerk-Tier: was dieses Gerät im Aether-Swarm leisten kann.
/// Emergent — wird aus Hardware + OS abgeleitet, nie manuell gesetzt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkTier {
    /// Nur lokale Analyse. Kein Netzwerk (Win9x, RPi Zero, <256 MB RAM).
    LocalOnly       = 0,
    /// LAN UDP-Beacon: passive Ankündigungen und Empfang, kein volles P2P.
    LanBeacon       = 1,
    /// Vollständiges LAN-P2P: Gossip, Leader-Election, Peer-Exchange.
    LanP2P          = 2,
    /// Yggdrasil IPv6-Overlay: geräteübergreifendes P2P über das Internet.
    YggdrasilP2P    = 3,
    /// Voller DHT-Teilnehmer: Kademlia-ähnliche Peer-Tabelle, Relay-Knoten.
    FullDht         = 4,
}

impl NetworkTier {
    pub fn rank(self) -> u8 { self as u8 }

    pub fn label(self) -> &'static str {
        match self {
            Self::LocalOnly    => "LocalOnly",
            Self::LanBeacon    => "LanBeacon",
            Self::LanP2P       => "LanP2P",
            Self::YggdrasilP2P => "YggdrasilP2P",
            Self::FullDht      => "FullDht",
        }
    }

    pub fn description_de(self) -> &'static str {
        match self {
            Self::LocalOnly    => "Vault-first lokal — lernt offline, noch kein Netzbetrieb.",
            Self::LanBeacon    => "Vault-first + LAN-Beacon — lokal lernen, im LAN sichtbar.",
            Self::LanP2P       => "LAN-P2P aktiv — Gossip + Leader-Election.",
            Self::YggdrasilP2P => "Yggdrasil bereit — geräteübergreifend P2P.",
            Self::FullDht      => "Voller DHT — Relay + Kademlia-Teilnahme.",
        }
    }

    /// Welche Features sind bei diesem Tier freigeschaltet?
    pub fn features(self) -> (&'static str, bool, bool, bool, bool) {
        // (label, lan_beacon, lan_p2p, yggdrasil, dht)
        match self {
            Self::LocalOnly    => ("LocalOnly",    false, false, false, false),
            Self::LanBeacon    => ("LanBeacon",    true,  false, false, false),
            Self::LanP2P       => ("LanP2P",       true,  true,  false, false),
            Self::YggdrasilP2P => ("YggdrasilP2P", true,  true,  true,  false),
            Self::FullDht      => ("FullDht",      true,  true,  true,  true),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HardwareProfile {
    pub cpu_cores_logical: usize,
    pub cpu_cores_physical: usize,
    pub cpu_freq_mhz: f64,
    pub ram_total_mb: u64,
    pub ram_available_mb: u64,
    pub disk_kind: DiskKind,
    pub is_old_hardware: bool,
    pub is_raspberry_pi: bool,
    pub os_platform: OsPlatform,
    pub network_tier: NetworkTier,
}

impl HardwareProfile {
    /// Erkennt das empfohlene RuntimeProfile für die iced_shell.
    /// Legacy = mehrere starke Alterssignale gleichzeitig.
    /// LowPower = mindestens zwei schwache Signale gleichzeitig.
    /// Auto = alles andere. Ein einzelner Engpass (z.B. nur 2 Kerne) reicht nicht,
    /// um ein modernes System pauschal in einen Sparmodus zu zwingen.
    pub fn recommended_profile(&self) -> RecommendedProfile {
        let modern_os = matches!(self.os_platform, OsPlatform::WinModern | OsPlatform::LinuxModern);
        let generous_memory = self.ram_total_mb >= 8192;
        let very_low_memory = self.ram_total_mb > 0 && self.ram_total_mb < 2048;
        let low_memory = self.ram_total_mb > 0 && self.ram_total_mb < 4096;
        let very_low_available_memory = self.ram_available_mb > 0 && self.ram_available_mb < 1024;

        if self.network_tier == NetworkTier::LocalOnly {
            return RecommendedProfile::Legacy;
        }

        let mut legacy_signals = 0u8;
        if self.cpu_cores_logical <= 2 {
            legacy_signals += 1;
        }
        if self.cpu_freq_mhz > 0.0 && self.cpu_freq_mhz < 1600.0 {
            legacy_signals += 1;
        }
        if very_low_memory {
            legacy_signals += 1;
        }
        if self.disk_kind == DiskKind::Hdd {
            legacy_signals += 1;
        }
        if matches!(
            self.os_platform,
            OsPlatform::Win9x
                | OsPlatform::Win2000
                | OsPlatform::WinXP
                | OsPlatform::LinuxLegacy
                | OsPlatform::RaspberryPi
        ) {
            legacy_signals += 1;
        }

        if legacy_signals >= 3 || (very_low_memory && self.cpu_cores_logical <= 2) {
            return RecommendedProfile::Legacy;
        }

        if modern_os && generous_memory && self.cpu_cores_logical >= 2 && !very_low_available_memory {
            return RecommendedProfile::Auto;
        }

        let mut low_power_signals = 0u8;
        if self.cpu_cores_logical <= 4 {
            low_power_signals += 1;
        }
        if low_memory {
            low_power_signals += 1;
        }
        if self.disk_kind == DiskKind::Hdd {
            low_power_signals += 1;
        }
        if self.is_old_hardware {
            low_power_signals += 1;
        }
        if self.network_tier == NetworkTier::LanBeacon {
            low_power_signals += 1;
        }
        if very_low_available_memory {
            low_power_signals += 1;
        }

        if low_power_signals >= 2 {
            RecommendedProfile::LowPower
        } else {
            RecommendedProfile::Auto
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedProfile { Auto, LowPower, Legacy }

/// Ableitung des Netzwerk-Tiers aus Hardware + OS-Plattform.
/// Rein deterministisch, keine externen Deps.
fn derive_network_tier(
    os: &OsPlatform,
    cores: usize,
    ram_mb: u64,
    is_raspberry_pi: bool,
    is_old: bool,
) -> NetworkTier {
    let modern_os = matches!(os, OsPlatform::WinModern | OsPlatform::LinuxModern);

    // ── Raspberry Pi ───────────────────────────────────────────────────────
    if is_raspberry_pi {
        // RPi Zero / RPi 1: 1 Kern, ≤512 MB RAM
        if cores <= 1 || ram_mb < 512 {
            return NetworkTier::LanBeacon;
        }
        // RPi 2 / RPi 3: 4 Kerne, ≤1 GB RAM
        if cores <= 4 && ram_mb < 1024 {
            return NetworkTier::LanP2P;
        }
        // RPi 3B+ / RPi 4 / RPi 5: ≥4 Kerne, ≥1 GB RAM
        if ram_mb >= 2048 {
            return NetworkTier::YggdrasilP2P; // RPi 4/5 nur wenn genug RAM
        }
        return NetworkTier::LanP2P;
    }

    // ── Windows 9x / 2000 ─────────────────────────────────────────────────
    // (Kann diese Binary eigentlich nicht ausführen, aber defensiver Fallback)
    match os {
        OsPlatform::Win9x => return NetworkTier::LocalOnly,
        OsPlatform::Win2000 => return NetworkTier::LanBeacon,

        // ── Windows XP ────────────────────────────────────────────────────
        OsPlatform::WinXP => {
            if ram_mb < 512 { return NetworkTier::LanBeacon; }
            return NetworkTier::LanP2P;
        }

        // ── Windows Vista / 7 ─────────────────────────────────────────────
        OsPlatform::WinVista7 => {
            if ram_mb < 1024 { return NetworkTier::LanP2P; }
            // Vista/7 kann Yggdrasil nicht selbst ausführen (kein WinTun ≥ NT6.1 fix),
            // daher bleibt diese Klasse bei LAN-P2P. Die lokale Vault-/Lernlogik läuft
            // trotzdem voll weiter und kann später auf moderner Hardware übernommen werden.
            return NetworkTier::LanP2P;
        }

        // ── Linux legacy (Kernel < 4.0) ───────────────────────────────────
        OsPlatform::LinuxLegacy => {
            if ram_mb < 256 { return NetworkTier::LocalOnly; }
            if ram_mb < 512 { return NetworkTier::LanBeacon; }
            return NetworkTier::LanP2P;
        }

        _ => {} // WinModern, LinuxModern, Unknown → weiter unten
    }

    // ── Generisch nach Hardware-Score ─────────────────────────────────────
    if modern_os {
        if ram_mb > 0 && ram_mb < 2048 {
            return if cores <= 2 {
                NetworkTier::LanBeacon
            } else {
                NetworkTier::LanP2P
            };
        }
        if ram_mb >= 8192 {
            return if cores >= 4 {
                NetworkTier::FullDht
            } else if cores >= 2 {
                NetworkTier::YggdrasilP2P
            } else {
                NetworkTier::LanP2P
            };
        }
        if ram_mb >= 4096 {
            return if cores >= 2 {
                NetworkTier::YggdrasilP2P
            } else {
                NetworkTier::LanP2P
            };
        }
    }

    if is_old {
        return if ram_mb >= 2048 {
            NetworkTier::LanP2P
        } else {
            NetworkTier::LanBeacon
        };
    }
    if ram_mb < 1024 || cores <= 2 {
        return NetworkTier::LanP2P;
    }
    if ram_mb < 4096 || cores <= 4 {
        return NetworkTier::YggdrasilP2P;
    }
    NetworkTier::FullDht
}

/// Haupteinstieg: erkennt Hardware plattformübergreifend (Windows / Linux).
/// Schlägt nie fehl — liefert im Fehlerfall konservative Defaults.
pub fn detect() -> HardwareProfile {
    let cores_logical = detect_logical_cores();
    let cores_physical = (cores_logical / 2).max(1);
    let freq_mhz = detect_cpu_freq_mhz();
    let (ram_total, ram_avail) = detect_ram_mb();
    let disk = detect_disk_kind();
    let is_raspberry_pi = detect_raspberry_pi();
    let os_platform = detect_os_platform();

    let mut old_score = 0u32;
    // Only penalise when values are actually known (non-zero means detected)
    if ram_total > 0 && ram_total < 2048 { old_score += 2; }
    if freq_mhz > 0.0 && freq_mhz < 1600.0 { old_score += 1; }
    if disk == DiskKind::Hdd { old_score += 1; }
    if cores_logical <= 2 && ram_total > 0 && ram_total < 4096 { old_score += 1; }
    if matches!(os_platform, OsPlatform::Win9x | OsPlatform::Win2000 | OsPlatform::WinXP | OsPlatform::LinuxLegacy | OsPlatform::RaspberryPi) {
        old_score += 2;
    }
    let is_old = old_score >= 3;

    let network_tier = derive_network_tier(
        &os_platform, cores_logical, ram_total, is_raspberry_pi, is_old,
    );

    HardwareProfile {
        cpu_cores_logical: cores_logical,
        cpu_cores_physical: cores_physical,
        cpu_freq_mhz: freq_mhz,
        ram_total_mb: ram_total,
        ram_available_mb: ram_avail,
        disk_kind: disk,
        is_old_hardware: is_old,
        is_raspberry_pi,
        os_platform,
        network_tier,
    }
}

/// Schreibt data/interbus/hw_capability.json (liest Python swarm_p2p.py).
/// Schlägt nie fehl — Fehler werden still ignoriert.
pub fn write_capability_json(profile: &HardwareProfile) {
    let (tier_label, lan_beacon, lan_p2p, yggdrasil, dht) =
        profile.network_tier.features();

    let os_label = match &profile.os_platform {
        OsPlatform::Win9x       => "Win9x",
        OsPlatform::Win2000     => "Win2000",
        OsPlatform::WinXP       => "WinXP",
        OsPlatform::WinVista7   => "WinVista7",
        OsPlatform::WinModern   => "WinModern",
        OsPlatform::LinuxLegacy => "LinuxLegacy",
        OsPlatform::LinuxModern => "LinuxModern",
        OsPlatform::RaspberryPi => "RaspberryPi",
        OsPlatform::Unknown     => "Unknown",
    };

    let note = profile.network_tier.description_de();

    let json = format!(
        "{{\n  \"os_platform\": \"{os_label}\",\n  \"network_tier\": \"{tier_label}\",\n  \"native_network_tier\": \"{tier_label}\",\n  \"tier_rank\": {rank},\n  \"native_tier_rank\": {rank},\n  \"cpu_cores\": {cores},\n  \"ram_mb\": {ram},\n  \"ram_available_mb\": {ram_available},\n  \"is_raspberry_pi\": {rpi},\n  \"vault_bootstrap_only\": {vault_only},\n  \"lan_beacon\": {lb},\n  \"lan_p2p\": {lp},\n  \"yggdrasil\": {ygg},\n  \"dht\": {dht_v},\n  \"runtime\": \"rust-shell\",\n  \"shell_capable\": true,\n  \"progressive_network_unlock\": false,\n  \"note\": \"{note}\"\n}}",
        os_label  = os_label,
        tier_label = tier_label,
        rank      = profile.network_tier.rank(),
        cores     = profile.cpu_cores_logical,
        ram       = profile.ram_total_mb,
        ram_available = profile.ram_available_mb,
        rpi       = profile.is_raspberry_pi,
        vault_only = matches!(profile.network_tier, NetworkTier::LocalOnly | NetworkTier::LanBeacon),
        lb        = lan_beacon,
        lp        = lan_p2p,
        ygg       = yggdrasil,
        dht_v     = dht,
        note      = note,
    );

    let _ = std::fs::create_dir_all(crate::app_root().join("data").join("interbus"));
    let path = crate::data_path("interbus/hw_capability.json");
    let _ = std::fs::write(&path, json);
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

// ── Raspberry Pi ───────────────────────────────────────────────────────────

/// Erkennt Raspberry Pi über /proc/cpuinfo (Linux only).
/// Sucht nach "Raspberry Pi" im Model-Feld oder "BCM" im Hardware-Feld.
fn detect_raspberry_pi() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in text.lines() {
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("model") && lower.contains("raspberry") {
                    return true;
                }
                if lower.starts_with("hardware") && (lower.contains("bcm") || lower.contains("raspberry")) {
                    return true;
                }
            }
        }
        // Neuere RPi Kernels: device-tree model
        if let Ok(model) = std::fs::read_to_string("/proc/device-tree/model") {
            if model.to_ascii_lowercase().contains("raspberry") {
                return true;
            }
        }
    }
    false
}

// ── OS Platform ────────────────────────────────────────────────────────────

/// Erkennt die OS-Plattform für die Netzwerk-Tier-Ableitung.
fn detect_os_platform() -> OsPlatform {
    #[cfg(target_os = "windows")]
    {
        return detect_os_windows();
    }
    #[cfg(target_os = "linux")]
    {
        return detect_os_linux();
    }
    #[allow(unreachable_code)]
    OsPlatform::Unknown
}

/// Windows: Liest NT-Version aus Registry und klassifiziert.
/// NT 4.x → Win9x-Ära (oder NT4 Server — selten)
/// NT 5.0 → Win2000
/// NT 5.1/5.2 → WinXP/2003
/// NT 6.0/6.1 → Vista/7
/// NT 6.2+ → Win8/10/11
#[cfg(target_os = "windows")]
fn detect_os_windows() -> OsPlatform {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
        HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    let ver_str = unsafe {
        let path: Vec<u16> = OsStr::new(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        ).encode_wide().chain(Some(0)).collect();
        let value: Vec<u16> = OsStr::new("CurrentVersion")
            .encode_wide().chain(Some(0)).collect();
        let mut hkey = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return OsPlatform::Unknown;
        }
        let mut buf = [0u16; 64];
        let mut size = (buf.len() * 2) as u32;
        let mut kind = 0u32;
        let ret = RegQueryValueExW(
            hkey, value.as_ptr(), std::ptr::null_mut(),
            &mut kind, buf.as_mut_ptr() as *mut u8, &mut size,
        );
        RegCloseKey(hkey);
        if ret != 0 || kind != REG_SZ { return OsPlatform::Unknown; }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    };

    // ver_str looks like "4.0", "5.0", "5.1", "6.0", "6.1", "6.2", "6.3", "10.0"
    let parts: Vec<u32> = ver_str.split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    let major = parts.first().copied().unwrap_or(0);
    let minor = parts.get(1).copied().unwrap_or(0);

    match (major, minor) {
        (4, _)         => OsPlatform::Win9x,      // NT4 / Win98 emulation
        (5, 0)         => OsPlatform::Win2000,
        (5, 1) | (5, 2) => OsPlatform::WinXP,
        (6, 0) | (6, 1) => OsPlatform::WinVista7,
        (6, _) | (10, _) => OsPlatform::WinModern,
        _              => OsPlatform::WinModern,
    }
}

/// Linux: Liest Kernel-Version aus /proc/version und klassifiziert.
/// < 4.0 → LinuxLegacy; ≥ 4.0 → LinuxModern (außer wenn RPi schon gesetzt)
#[cfg(target_os = "linux")]
fn detect_os_linux() -> OsPlatform {
    // Raspberry Pi bekommt eigene Platfortm-Kennzeichnung
    if detect_raspberry_pi() {
        return OsPlatform::RaspberryPi;
    }
    // Kernel-Version aus /proc/version: "Linux version 5.15.0-..."
    if let Ok(text) = std::fs::read_to_string("/proc/version") {
        for token in text.split_whitespace() {
            // Token sieht aus wie "5.15.0-102-generic"
            let parts: Vec<u32> = token.split('.')
                .filter_map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok())
                .collect();
            if let Some(&major) = parts.first() {
                if major > 0 || parts.len() >= 2 {
                    return if major < 4 { OsPlatform::LinuxLegacy } else { OsPlatform::LinuxModern };
                }
            }
        }
    }
    OsPlatform::LinuxModern // safe default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_two_core_system_with_plenty_of_ram_stays_auto() {
        let profile = HardwareProfile {
            cpu_cores_logical: 2,
            cpu_cores_physical: 2,
            cpu_freq_mhz: 2400.0,
            ram_total_mb: 16_384,
            ram_available_mb: 9_216,
            disk_kind: DiskKind::Unknown,
            is_old_hardware: false,
            is_raspberry_pi: false,
            os_platform: OsPlatform::WinModern,
            network_tier: derive_network_tier(&OsPlatform::WinModern, 2, 16_384, false, false),
        };

        assert_eq!(profile.network_tier, NetworkTier::YggdrasilP2P);
        assert_eq!(profile.recommended_profile(), RecommendedProfile::Auto);
    }

    #[test]
    fn local_only_devices_remain_legacy() {
        let profile = HardwareProfile {
            cpu_cores_logical: 1,
            cpu_cores_physical: 1,
            cpu_freq_mhz: 1100.0,
            ram_total_mb: 512,
            ram_available_mb: 256,
            disk_kind: DiskKind::Hdd,
            is_old_hardware: true,
            is_raspberry_pi: false,
            os_platform: OsPlatform::LinuxLegacy,
            network_tier: NetworkTier::LocalOnly,
        };

        assert_eq!(profile.recommended_profile(), RecommendedProfile::Legacy);
    }

    #[test]
    fn vista7_never_claims_yggdrasil_locally() {
        let tier = derive_network_tier(&OsPlatform::WinVista7, 4, 4_096, false, true);
        assert_eq!(tier, NetworkTier::LanP2P);
    }
}

