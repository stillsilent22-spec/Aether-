//! backup.rs
// Backup-Logik für Aether: Automatisches Kopieren von Dateien vor Analyse.
// Wird von der GUI genutzt, um vor jeder Analyse ein Backup im Backup-Ordner anzulegen.
//
// Funktionen:
// - backup_file: Kopiert eine Datei nach C:/AetherBackup (mit Datums-Unterordner)
// - backup_enabled: Globale Option, ob Backup aktiv ist (GUI-Checkbox)

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use chrono::Local;

/// Legt ein Backup der Datei im Backup-Ordner an (C:/AetherBackup/YYYY-MM-DD/).
pub fn backup_file<P: AsRef<Path>>(src: P) -> io::Result<PathBuf> {
    let src_path = src.as_ref();
    let date_folder = format!("C:/AetherBackup/{}", Local::now().format("%Y-%m-%d"));
    let backup_dir = Path::new(&date_folder);
    fs::create_dir_all(backup_dir)?;
    let mut dest = backup_dir.join(src_path.file_name().unwrap_or_default());
    if dest.exists() {
        let timestamp = Local::now().format("%H%M%S");
        let stem = src_path.file_stem().unwrap_or_default().to_string_lossy();
        let ext = src_path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
        dest = backup_dir.join(format!("{}_{}{}", stem, timestamp, ext));
    }
    fs::copy(src_path, &dest)?;
    Ok(dest)
}
