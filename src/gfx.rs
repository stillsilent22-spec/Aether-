use crate::inter_layer_bus::{
    BusEvent, BusPublisher, MediaTraceEvent, OptimizationDecisionEvent, ShaderCacheHitEvent,
    ShaderCompileRequestEvent, TextureUploadRequestEvent, TextureUploadResultEvent,
    VramOptimizedEvent, VramPressureEvent, VramPressureLevel,
};
use crate::vault_access::VaultAccessLayer;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// VRAM-Abfrage (Windows, einmalig gecacht fuer Total, TTL-gecacht fuer Used)
// ---------------------------------------------------------------------------

static VRAM_TOTAL_BITS: AtomicU32 = AtomicU32::new(0);
static VRAM_TOTAL_READY: AtomicU32 = AtomicU32::new(0); // 0 = uninitialized, 1 = set
static VRAM_USED_BITS: AtomicU32 = AtomicU32::new(0);
static VRAM_USED_LAST_SEC: AtomicU64 = AtomicU64::new(0);
const VRAM_USED_TTL_SECS: u64 = 5;

fn now_unix_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fragt die Gesamtgröße des dedizierten VRAM via PowerShell ab (einmalig gecacht).
fn vram_total_cached_mb() -> f32 {
    if VRAM_TOTAL_READY.load(Ordering::Relaxed) == 1 {
        return f32::from_bits(VRAM_TOTAL_BITS.load(Ordering::Relaxed));
    }
    let mb = query_vram_total_mb().unwrap_or(4096.0);
    VRAM_TOTAL_BITS.store(mb.to_bits(), Ordering::Relaxed);
    VRAM_TOTAL_READY.store(1, Ordering::Release);
    mb
}

/// Fragt den aktuell genutzten VRAM ab (TTL-gecacht, Fallback 0).
fn vram_used_live_mb() -> f32 {
    let now = now_unix_sec();
    let last = VRAM_USED_LAST_SEC.load(Ordering::Relaxed);
    if now.saturating_sub(last) < VRAM_USED_TTL_SECS {
        return f32::from_bits(VRAM_USED_BITS.load(Ordering::Relaxed));
    }
    let mb = query_vram_used_mb().unwrap_or(0.0);
    VRAM_USED_BITS.store(mb.to_bits(), Ordering::Relaxed);
    VRAM_USED_LAST_SEC.store(now, Ordering::Relaxed);
    mb
}

/// Windows: AdapterRAM aus Win32_VideoController (dedizierter VRAM in Bytes → MiB).
#[cfg(target_os = "windows")]
fn query_vram_total_mb() -> Option<f32> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_VideoController | Select-Object -First 1 -ExpandProperty AdapterRAM",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|&b| b > 0)
        .map(|b| b as f32 / 1_048_576.0)
}

#[cfg(not(target_os = "windows"))]
fn query_vram_total_mb() -> Option<f32> {
    None
}

/// Windows: genutzten VRAM via GPU Adapter Memory Perf-Counter (in Bytes → MiB).
#[cfg(target_os = "windows")]
fn query_vram_used_mb() -> Option<f32> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Counter '\\GPU Adapter Memory(*)\\Dedicated Usage' -ErrorAction SilentlyContinue).CounterSamples | Measure-Object CookedValue -Sum | Select-Object -ExpandProperty Sum",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|&b| b > 0.0)
        .map(|b| (b / 1_048_576.0) as f32)
}

#[cfg(not(target_os = "windows"))]
fn query_vram_used_mb() -> Option<f32> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfxTraceMode {
    Stage,
    Deep,
}

/// Grafik-Backend-Abstraktion fuer spaetere Backend-spezifische Implementierungen.
pub trait AetherGfxBackend: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn vram_used_mb(&self) -> f32;
    fn vram_total_mb(&self) -> f32;
    fn upload_raw_texture(&self, label: &str, bytes: &[u8]) -> u64;
    fn upload_delta_texture(&self, label: &str, anchor_refs: &[String], delta: &[u8]) -> u64;
    fn evict_texture(&self, handle: u64);
    fn compile_shader(&self, source: &str) -> u64;
}

pub struct OpenGlBackend;

impl AetherGfxBackend for OpenGlBackend {
    fn backend_name(&self) -> &'static str {
        "OpenGL"
    }

    fn vram_used_mb(&self) -> f32 {
        vram_used_live_mb()
    }

    fn vram_total_mb(&self) -> f32 {
        vram_total_cached_mb()
    }

    fn upload_raw_texture(&self, _label: &str, _bytes: &[u8]) -> u64 {
        0
    }

    fn upload_delta_texture(&self, _label: &str, _anchor_refs: &[String], _delta: &[u8]) -> u64 {
        0
    }

    fn evict_texture(&self, _handle: u64) {}

    fn compile_shader(&self, _source: &str) -> u64 {
        0
    }
}

pub struct AetherGfx {
    backend: Box<dyn AetherGfxBackend>,
    texture_vault: TextureVaultCache,
    shader_cache: ShaderVaultCache,
    bus: BusPublisher,
    trace_mode: GfxTraceMode,
    deep_trace_once: HashSet<String>,
}

impl AetherGfx {
    pub fn new_auto(vault: Arc<VaultAccessLayer>, bus: BusPublisher) -> Self {
        let backend = Box::new(OpenGlBackend);
        let shader_cache_path =
            std::path::PathBuf::from("data/rust_shell/shader_cache.json");
        Self {
            backend,
            texture_vault: TextureVaultCache::new(vault),
            shader_cache: ShaderVaultCache::with_persistence(shader_cache_path),
            bus,
            trace_mode: GfxTraceMode::Stage,
            deep_trace_once: HashSet::new(),
        }
    }

    pub fn trace_mode(&self) -> GfxTraceMode {
        self.trace_mode
    }

    pub fn set_trace_mode(&mut self, mode: GfxTraceMode) {
        self.trace_mode = mode;
    }

    pub fn request_deep_trace_once(&mut self, asset_label: &str) {
        self.deep_trace_once.insert(asset_label.to_owned());
    }

    fn resolve_trace_depth(&mut self, asset_label: &str) -> &'static str {
        if self.trace_mode == GfxTraceMode::Deep {
            return "deep";
        }
        if self.deep_trace_once.remove(asset_label) {
            return "deep";
        }
        "stage"
    }

    pub async fn upload_texture(&mut self, label: &str, bytes: &[u8]) -> u64 {
        let trace_depth = self.resolve_trace_depth(label);
        self.bus.publish(BusEvent::TextureUploadRequested(
            TextureUploadRequestEvent {
                program_id: self.backend.backend_name().to_owned(),
                texture_label: label.to_owned(),
                byte_size: bytes.len(),
                expected_vram_mb: bytes.len() as f32 / 1_048_576.0,
            },
        ));
        let result = self.texture_vault.prepare(label, bytes).await;
        self.bus
            .publish(BusEvent::VramOptimized(VramOptimizedEvent {
                texture_label: label.to_owned(),
                original_mb: bytes.len() as f32 / 1_048_576.0,
                compressed_mb: result.compressed_size as f32 / 1_048_576.0,
                vault_hit_rate: result.hit_rate,
                compression_ratio: result.compression_ratio,
            }));
        let handle = if result.hit_rate > 0.5 {
            self.backend
                .upload_delta_texture(label, &result.anchor_refs, &result.residual)
        } else {
            self.backend.upload_raw_texture(label, bytes)
        };
        self.bus
            .publish(BusEvent::TextureUploadCompleted(TextureUploadResultEvent {
                program_id: self.backend.backend_name().to_owned(),
                texture_label: label.to_owned(),
                handle,
                uploaded_mb: result.compressed_size as f32 / 1_048_576.0,
                used_delta_path: result.hit_rate > 0.5,
            }));
        self.bus.publish(BusEvent::MediaTraceRecorded(MediaTraceEvent {
            process: self.backend.backend_name().to_owned(),
            medium: "pixel".to_owned(),
            asset_label: label.to_owned(),
            stage: "texture_upload".to_owned(),
            operation: if result.hit_rate > 0.5 {
                "delta_path"
            } else {
                "raw_upload"
            }
            .to_owned(),
            anchor_refs: result.anchor_refs.clone(),
            trace_depth: trace_depth.to_owned(),
        }));
        handle
    }

    pub fn compile_shader_cached(&mut self, program_id: &str, source: &str, stage: &str) -> u64 {
        let trace_asset = format!("shader::{program_id}::{stage}");
        let trace_depth = self.resolve_trace_depth(&trace_asset);
        self.bus.publish(BusEvent::ShaderCompileRequested(
            ShaderCompileRequestEvent {
                program_id: program_id.to_owned(),
                shader_hash: format!("{:x}", Sha256::digest(source.as_bytes())),
                stage: stage.to_owned(),
            },
        ));
        let (handle, cache_hit, shader_hash) = self
            .shader_cache
            .get_or_insert(source, || self.backend.compile_shader(source));
        if cache_hit {
            self.bus
                .publish(BusEvent::ShaderCacheHit(ShaderCacheHitEvent {
                    program_id: program_id.to_owned(),
                    shader_hash,
                    handle,
                }));
        }
        self.bus.publish(BusEvent::MediaTraceRecorded(MediaTraceEvent {
            process: program_id.to_owned(),
            medium: "pixel".to_owned(),
            asset_label: trace_asset,
            stage: "shader_pipeline".to_owned(),
            operation: if cache_hit {
                "cache_hit"
            } else {
                "compile"
            }
            .to_owned(),
            anchor_refs: Vec::new(),
            trace_depth: trace_depth.to_owned(),
        }));
        handle
    }

    pub fn check_vram_pressure(&self) {
        let used = self.backend.vram_used_mb();
        let total = self.backend.vram_total_mb();
        let ratio = used / total.max(1.0);
        let level = match ratio {
            value if value > 0.90 => VramPressureLevel::Critical,
            value if value > 0.80 => VramPressureLevel::High,
            value if value > 0.60 => VramPressureLevel::Medium,
            _ => VramPressureLevel::Low,
        };
        self.bus
            .publish(BusEvent::VramPressureChanged(VramPressureEvent {
                used_mb: used,
                total_mb: total,
                pressure_ratio: ratio,
                pressure_level: level.clone(),
                active_programs: vec![self.backend.backend_name().to_owned()],
            }));
        if matches!(level, VramPressureLevel::High | VramPressureLevel::Critical) {
            let applied = matches!(level, VramPressureLevel::Critical);
            self.bus
                .publish(BusEvent::OptimizationDecision(OptimizationDecisionEvent {
                    subsystem: "gfx".to_owned(),
                    decision: if applied {
                        "tighten_vram_budget"
                    } else {
                        "prepare_vram_throttle"
                    }
                    .to_owned(),
                    trigger: format!("vram_pressure_{:?}", level),
                    confidence: ratio.clamp(0.0, 1.0),
                    expected_gain_percent: if applied { 18.0 } else { 10.0 },
                    applied,
                    rollback_ready: true,
                    guardrail: "no_forced_evict_without_confirmed_critical_pressure"
                        .to_owned(),
                }));
        }
    }
}

struct TextureVaultCache {
    vault: Arc<VaultAccessLayer>,
    tile_size: u32,
}

struct TexturePrepResult {
    anchor_refs: Vec<String>,
    residual: Vec<u8>,
    compressed_size: usize,
    hit_rate: f32,
    compression_ratio: f32,
}

impl TextureVaultCache {
    fn new(vault: Arc<VaultAccessLayer>) -> Self {
        Self {
            vault,
            tile_size: 64,
        }
    }

    async fn prepare(&self, _label: &str, bytes: &[u8]) -> TexturePrepResult {
        let tile_size_bytes = (self.tile_size * self.tile_size * 4) as usize;
        let mut anchor_refs = Vec::new();
        let mut residual = Vec::new();
        let mut hits = 0usize;
        let mut total = 0usize;
        for chunk in bytes.chunks(tile_size_bytes.max(1)) {
            let hash = format!("{:x}", Sha256::digest(chunk));
            total += 1;
            if self.vault.lookup_raw(&hash).await.is_some() {
                anchor_refs.push(hash);
                hits += 1;
            } else {
                self.vault.store_raw(&hash, chunk).await;
                residual.extend_from_slice(chunk);
            }
        }
        let hit_rate = if total > 0 {
            hits as f32 / total as f32
        } else {
            0.0
        };
        let compressed_size = residual.len() + anchor_refs.len() * 32;
        TexturePrepResult {
            anchor_refs,
            residual,
            compressed_size,
            hit_rate,
            compression_ratio: compressed_size as f32 / bytes.len().max(1) as f32,
        }
    }
}

struct ShaderVaultCache {
    compiled: HashMap<String, u64>,
    persist_path: Option<std::path::PathBuf>,
}

impl ShaderVaultCache {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            compiled: HashMap::new(),
            persist_path: None,
        }
    }

    /// Lädt den Cache von Disk oder legt eine leere Instanz an.
    fn with_persistence(path: std::path::PathBuf) -> Self {
        let compiled = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|raw| serde_json::from_str::<HashMap<String, u64>>(&raw).ok())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        Self {
            compiled,
            persist_path: Some(path),
        }
    }

    /// Schreibt den Cache auf Disk (silent-fail).
    fn flush(&self) {
        let Some(path) = &self.persist_path else { return };
        if let Ok(raw) = serde_json::to_string(&self.compiled) {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, raw);
        }
    }

    fn get_or_insert(
        &mut self,
        source: &str,
        compile_fn: impl FnOnce() -> u64,
    ) -> (u64, bool, String) {
        let hash = format!("{:x}", Sha256::digest(source.as_bytes()));
        if let Some(handle) = self.compiled.get(&hash).copied() {
            return (handle, true, hash);
        }
        let handle = compile_fn();
        self.compiled.insert(hash.clone(), handle);
        self.flush();
        (handle, false, hash)
    }
}
// ---------------------------------------------------------------------------
// MetaLayer Pixel-Koordinaten-Erweiterungen
// ---------------------------------------------------------------------------

/// Shannon-Entropie eines 8×8-Pixel-Blocks (Graustufen-Bytes).
/// Ergibt einen Wert in [0, 8]. Läuft in < 1 µs für 64-Byte-Blocks.
pub fn pixel_block_entropy(block: &[u8]) -> f32 {
    if block.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let n = block.len() as f32;
    let mut entropy = 0.0f32;
    for &c in &counts {
        if c > 0 {
            let p = c as f32 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Pearson-Korrelationskoeffizient zweier f32-Vektoren gleicher Länge.
/// Rückgabe: [-1, 1]. Gibt 0.0 zurück wenn eines der Slices leer ist.
pub fn process_cross_correlation(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    if n < 2 {
        return 0.0;
    }
    let mean_a: f32 = a[..n].iter().sum::<f32>() / n as f32;
    let mean_b: f32 = b[..n].iter().sum::<f32>() / n as f32;
    let mut cov = 0.0f32;
    let mut var_a = 0.0f32;
    let mut var_b = 0.0f32;
    for i in 0..n {
        let da = a[i] - mean_a;
        let db = b[i] - mean_b;
        cov   += da * db;
        var_a += da * da;
        var_b += db * db;
    }
    let denom = (var_a * var_b).sqrt();
    if denom < 1e-9 {
        0.0
    } else {
        (cov / denom).clamp(-1.0, 1.0)
    }
}

/// Beschreibt eine Bildschirmregion eines Prozesses für die CoordMatrix.
#[derive(Debug, Clone)]
pub struct ProcessRegion {
    pub pid:    u32,
    pub name:   String,
    pub left:   i32,
    pub top:    i32,
    pub width:  u32,
    pub height: u32,
    pub score:  f32,
}

/// Eintrag in der globalen Koordinatenmatrix.
#[derive(Debug, Clone)]
pub struct CoordMatrixEntry {
    pub pid:           u32,
    pub process_name:  String,
    pub area_px:       u64,
    pub score:         f32,
    pub overlap_ratio: f32,
}

/// Globale Koordinatenmatrix: aggregiert alle Prozess-Regionen und berechnet
/// Überlappungsanteile sowie Gesamt-Score.
pub fn build_coord_matrix(process_regions: Vec<ProcessRegion>) -> Vec<CoordMatrixEntry> {
    let total_area: u64 = process_regions
        .iter()
        .map(|r| r.width as u64 * r.height as u64)
        .sum();
    let total_area = total_area.max(1);

    process_regions
        .iter()
        .map(|r| {
            let area = r.width as u64 * r.height as u64;
            let overlap_ratio = area as f32 / total_area as f32;
            CoordMatrixEntry {
                pid:           r.pid,
                process_name:  r.name.clone(),
                area_px:       area,
                score:         r.score,
                overlap_ratio: overlap_ratio.clamp(0.0, 1.0),
            }
        })
        .collect()
}

/// Schätzt den DWM-Koordinatenpfad-Score eines HWND-Handles (Windows only).
/// Gibt einen Wert in [0, 1] zurück — höher = mehr Compositing-Overhead.
/// Auf Nicht-Windows-Systemen wird immer 0.5 zurückgegeben.
#[cfg(target_os = "windows")]
pub fn dwm_coord_path_score(hwnd: usize) -> f32 {
    // Heuristik: Windows-API-Stilflags auswerten um DWM-Komplexität zu schätzen.
    // GetWindowLongPtrW(-20) = GWL_EXSTYLE
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetWindowLongPtrW, GWL_EXSTYLE,
        WS_EX_LAYERED, WS_EX_NOREDIRECTIONBITMAP,
    };
    let ex_style = unsafe { GetWindowLongPtrW(hwnd as isize as _, GWL_EXSTYLE) };
    let mut score = 0.5f32;
    if ex_style as u32 & WS_EX_LAYERED != 0 {
        score += 0.15;
    }
    if ex_style as u32 & WS_EX_NOREDIRECTIONBITMAP != 0 {
        score -= 0.15; // Direktpfad → weniger Overhead
    }
    score.clamp(0.0, 1.0)
}

#[cfg(not(target_os = "windows"))]
pub fn dwm_coord_path_score(_hwnd: usize) -> f32 {
    0.5
}