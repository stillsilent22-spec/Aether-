use aether_rust_shell::observation::{ClassifyResponse, QuarantineCategory};
use rusqlite::{params, Connection};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
enum WorkerCommand {
    Init,
    Integrity,
    Status,
    Store {
        category: QuarantineCategory,
        anchor_hash_hex: String,
        confidence: f32,
        engine_flags: u64,
        feature_vector: [f32; 16],
    },
    Classify {
        feature_vector: [f32; 16],
    },
}

#[derive(Debug, Serialize)]
struct WorkerStatus {
    online: bool,
    integrity_ok: bool,
    record_count: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let db_path = PathBuf::from("data")
        .join("rust_shell")
        .join("quarantine")
        .join("quarantine.db");
    let command = parse_command(&args)?;
    apply_sandbox_restrictions();
    let store = QuarantineVaultStore::open(&db_path)?;

    match command {
        WorkerCommand::Init => {
            store.verify_integrity()?;
            println!("sandbox_worker bereit");
        }
        WorkerCommand::Integrity => {
            store.verify_integrity()?;
            println!("integrity ok");
        }
        WorkerCommand::Status => {
            let status = WorkerStatus {
                online: true,
                integrity_ok: store.verify_integrity().is_ok(),
                record_count: store.record_count()?,
            };
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        WorkerCommand::Store {
            category,
            anchor_hash_hex,
            confidence,
            engine_flags,
            feature_vector,
        } => {
            store.store_anchor(
                category,
                &anchor_hash_hex,
                &feature_vector,
                confidence,
                engine_flags,
            )?;
            println!("stored");
        }
        WorkerCommand::Classify { feature_vector } => {
            let response = store.classify(&feature_vector)?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
    }
    Ok(())
}

struct QuarantineVaultStore {
    conn: Connection,
    root: PathBuf,
}

impl QuarantineVaultStore {
    fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS quarantine_anchors (
                anchor_hash TEXT PRIMARY KEY,
                category INTEGER NOT NULL,
                feature_vector TEXT NOT NULL,
                confidence REAL NOT NULL,
                engine_flags INTEGER NOT NULL,
                stored_at INTEGER NOT NULL
            );",
        )?;
        Ok(Self {
            conn,
            root: path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        })
    }

    fn store_anchor(
        &self,
        category: QuarantineCategory,
        anchor_hash_hex: &str,
        feature_vector: &[f32; 16],
        confidence: f32,
        engine_flags: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let vector_json = serde_json::to_string(feature_vector)?;
        self.conn.execute(
            "INSERT OR IGNORE INTO quarantine_anchors
             (anchor_hash, category, feature_vector, confidence, engine_flags, stored_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                anchor_hash_hex,
                category as u8,
                vector_json,
                confidence,
                engine_flags,
                unix_timestamp() as i64
            ],
        )?;
        self.write_manifest()?;
        Ok(())
    }

    fn classify(
        &self,
        feature_vector: &[f32; 16],
    ) -> Result<ClassifyResponse, Box<dyn std::error::Error>> {
        let mut stmt = self
            .conn
            .prepare("SELECT category, feature_vector FROM quarantine_anchors")?;
        let rows = stmt.query_map([], |row| {
            let category: u8 = row.get(0)?;
            let vector_json: String = row.get(1)?;
            Ok((category, vector_json))
        })?;
        let mut best_category = QuarantineCategory::Unknown;
        let mut best_confidence = 0.0f32;
        let mut match_count = 0u32;
        for row in rows {
            let (category, vector_json) = row?;
            let stored: [f32; 16] = serde_json::from_str(&vector_json)?;
            let similarity = cosine_similarity(&stored, feature_vector);
            if similarity >= 0.85 {
                match_count += 1;
                if similarity > best_confidence {
                    best_confidence = similarity;
                    best_category = match category {
                        0x01 => QuarantineCategory::Hatespeech,
                        0x02 => QuarantineCategory::Malware,
                        0x03 => QuarantineCategory::Propaganda,
                        0x04 => QuarantineCategory::Disinfo,
                        _ => QuarantineCategory::Unknown,
                    };
                }
            }
        }
        Ok(ClassifyResponse {
            known: match_count > 0,
            category: if match_count > 0 {
                best_category
            } else {
                QuarantineCategory::Unknown
            },
            confidence: best_confidence,
            match_count,
        })
    }

    fn verify_integrity(&self) -> Result<(), Box<dyn std::error::Error>> {
        let current = self.current_merkle_root()?;
        let path = self.root.join("manifest.json");
        if !path.exists() {
            fs::write(
                &path,
                serde_json::to_string_pretty(&serde_json::json!({
                    "merkle_root_hex": current,
                    "updated_at": unix_timestamp(),
                }))?,
            )?;
            return Ok(());
        }
        let raw = fs::read_to_string(path)?;
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        let stored = value
            .get("merkle_root_hex")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned();
        if stored != current {
            return Err("quarantine integrity mismatch".into());
        }
        Ok(())
    }

    fn write_manifest(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.root.join("manifest.json");
        let raw = serde_json::to_string_pretty(&serde_json::json!({
            "merkle_root_hex": self.current_merkle_root()?,
            "updated_at": unix_timestamp(),
        }))?;
        fs::write(path, raw)?;
        Ok(())
    }

    fn current_merkle_root(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT anchor_hash, category, confidence, stored_at FROM quarantine_anchors ORDER BY anchor_hash",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u8>(1)?,
                row.get::<_, f32>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut hasher = Sha256::new();
        for row in rows {
            let (anchor_hash, category, confidence, stored_at) = row?;
            hasher.update(anchor_hash.as_bytes());
            hasher.update([category]);
            hasher.update(confidence.to_le_bytes());
            hasher.update(stored_at.to_le_bytes());
        }
        Ok(hex_encode(&hasher.finalize()))
    }

    fn record_count(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM quarantine_anchors", [], |row| {
                    row.get(0)
                })?;
        Ok(count.max(0) as usize)
    }
}

fn parse_command(args: &[String]) -> Result<WorkerCommand, Box<dyn std::error::Error>> {
    let command = args.get(1).map(|value| value.as_str()).unwrap_or("init");
    match command {
        "init" => Ok(WorkerCommand::Init),
        "integrity" => Ok(WorkerCommand::Integrity),
        "status" => Ok(WorkerCommand::Status),
        "store" => {
            let category = parse_category(flag_value(args, "--category").unwrap_or("unknown"))?;
            let anchor_hash_hex = flag_value(args, "--hash").unwrap_or_default().to_owned();
            let confidence = flag_value(args, "--confidence")
                .unwrap_or("0.7")
                .parse::<f32>()
                .unwrap_or(0.7);
            let engine_flags = flag_value(args, "--engine-flags")
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap_or(0);
            let feature_vector = parse_vector(flag_value(args, "--features").unwrap_or_default())?;
            Ok(WorkerCommand::Store {
                category,
                anchor_hash_hex,
                confidence,
                engine_flags,
                feature_vector,
            })
        }
        "classify" => Ok(WorkerCommand::Classify {
            feature_vector: parse_vector(flag_value(args, "--features").unwrap_or_default())?,
        }),
        _ => Err("unknown sandbox_worker command".into()),
    }
}

fn parse_category(raw: &str) -> Result<QuarantineCategory, Box<dyn std::error::Error>> {
    Ok(match raw.to_ascii_lowercase().as_str() {
        "hatespeech" => QuarantineCategory::Hatespeech,
        "malware" => QuarantineCategory::Malware,
        "propaganda" => QuarantineCategory::Propaganda,
        "disinfo" => QuarantineCategory::Disinfo,
        _ => QuarantineCategory::Unknown,
    })
}

fn parse_vector(raw: &str) -> Result<[f32; 16], Box<dyn std::error::Error>> {
    let mut output = [0.0f32; 16];
    for (index, value) in raw
        .split(',')
        .filter(|value| !value.is_empty())
        .take(16)
        .enumerate()
    {
        output[index] = value.trim().parse::<f32>()?;
    }
    Ok(output)
}

fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

fn apply_sandbox_restrictions() {
    // Platzhalter fuer spaetere seccomp/Job-Object-Haertung.
}

fn cosine_similarity(left: &[f32; 16], right: &[f32; 16]) -> f32 {
    let mut dot = 0.0f32;
    let mut left_norm = 0.0f32;
    let mut right_norm = 0.0f32;
    for index in 0..16 {
        dot += left[index] * right[index];
        left_norm += left[index] * left[index];
        right_norm += right[index] * right[index];
    }
    if left_norm == 0.0 || right_norm == 0.0 {
        return 0.0;
    }
    (dot / (left_norm.sqrt() * right_norm.sqrt())).clamp(0.0, 1.0)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}
