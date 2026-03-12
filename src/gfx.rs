use crate::inter_layer_bus::{
    BusEvent, BusPublisher, ShaderCacheHitEvent, ShaderCompileRequestEvent, TextureUploadRequestEvent,
    TextureUploadResultEvent, VramOptimizedEvent, VramPressureEvent, VramPressureLevel,
};
use crate::vault_access::VaultAccessLayer;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

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
        0.0
    }

    fn vram_total_mb(&self) -> f32 {
        4096.0
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
}

impl AetherGfx {
    pub fn new_auto(vault: Arc<VaultAccessLayer>, bus: BusPublisher) -> Self {
        let backend = Box::new(OpenGlBackend);
        Self {
            backend,
            texture_vault: TextureVaultCache::new(vault),
            shader_cache: ShaderVaultCache::new(),
            bus,
        }
    }

    pub async fn upload_texture(&mut self, label: &str, bytes: &[u8]) -> u64 {
        self.bus.publish(BusEvent::TextureUploadRequested(TextureUploadRequestEvent {
            program_id: self.backend.backend_name().to_owned(),
            texture_label: label.to_owned(),
            byte_size: bytes.len(),
            expected_vram_mb: bytes.len() as f32 / 1_048_576.0,
        }));
        let result = self.texture_vault.prepare(label, bytes).await;
        self.bus.publish(BusEvent::VramOptimized(VramOptimizedEvent {
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
        self.bus.publish(BusEvent::TextureUploadCompleted(TextureUploadResultEvent {
            program_id: self.backend.backend_name().to_owned(),
            texture_label: label.to_owned(),
            handle,
            uploaded_mb: result.compressed_size as f32 / 1_048_576.0,
            used_delta_path: result.hit_rate > 0.5,
        }));
        handle
    }

    pub fn compile_shader_cached(&mut self, program_id: &str, source: &str, stage: &str) -> u64 {
        self.bus.publish(BusEvent::ShaderCompileRequested(ShaderCompileRequestEvent {
            program_id: program_id.to_owned(),
            shader_hash: format!("{:x}", Sha256::digest(source.as_bytes())),
            stage: stage.to_owned(),
        }));
        let (handle, cache_hit, shader_hash) = self.shader_cache.get_or_insert(source, || self.backend.compile_shader(source));
        if cache_hit {
            self.bus.publish(BusEvent::ShaderCacheHit(ShaderCacheHitEvent {
                program_id: program_id.to_owned(),
                shader_hash,
                handle,
            }));
        }
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
        self.bus.publish(BusEvent::VramPressureChanged(VramPressureEvent {
            used_mb: used,
            total_mb: total,
            pressure_ratio: ratio,
            pressure_level: level,
            active_programs: vec![self.backend.backend_name().to_owned()],
        }));
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
        Self { vault, tile_size: 64 }
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
}

impl ShaderVaultCache {
    fn new() -> Self {
        Self {
            compiled: HashMap::new(),
        }
    }

    fn get_or_insert(&mut self, source: &str, compile_fn: impl FnOnce() -> u64) -> (u64, bool, String) {
        let hash = format!("{:x}", Sha256::digest(source.as_bytes()));
        if let Some(handle) = self.compiled.get(&hash).copied() {
            return (handle, true, hash);
        }
        let handle = compile_fn();
        self.compiled.insert(hash.clone(), handle);
        (handle, false, hash)
    }
}
