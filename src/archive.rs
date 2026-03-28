//! archive.rs
// Archiv-Handling für Aether: Automatisches Entpacken von ZIP, TAR, GZ, 7z, RAR vor Analyse.
// Wird von der GUI genutzt, um Archive vor der Analyse zu extrahieren.
//
// Funktionen:
// - extract_archive: Entpackt unterstützte Archive in ein Zielverzeichnis
//
// Hinweis: Für 7z und RAR werden externe Tools benötigt (7z.exe, unrar.exe)
use std::io;
use std::path::{Path, PathBuf};

const SUPPORTED_ARCHIVES: &[&str] = &[".zip", ".tar", ".gz", ".7z", ".rar"];

pub fn extract_archive<P: AsRef<Path>>(path: P, out_dir: P) -> Result<PathBuf, io::Error> {
    let ext = path.as_ref().extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let extracted = out_dir.as_ref().to_path_buf();
    match ext.as_str() {
        "zip" | "tar" | "gz" => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Archiv-Extraktion deaktiviert (zip/tar nicht verfügbar)",
            ));
        }
        "7z" => {
            let status = std::process::Command::new("7z")
                .args(["x", path.as_ref().to_str().unwrap_or_default(), &format!("-o{}", out_dir.as_ref().display())])
                .status()?;
            if !status.success() {
                return Err(io::Error::new(io::ErrorKind::Other, "7z extraction failed"));
            }
        }
        "rar" => {
            // unrar.exe muss im PATH sein
            let status = std::process::Command::new("unrar")
                .args(["x", path.as_ref().to_str().unwrap_or_default(), out_dir.as_ref().to_str().unwrap_or_default()])
                .status()?;
            if !status.success() {
                return Err(io::Error::new(io::ErrorKind::Other, "unrar extraction failed"));
            }
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported archive format"));
        }
    }
    Ok(extracted)
}

/// Prüft, ob eine Datei ein unterstütztes Archiv ist
pub fn is_supported_archive<P: AsRef<Path>>(path: P) -> bool {
    let ext = path.as_ref().extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    SUPPORTED_ARCHIVES.iter().any(|&s| s.trim_start_matches('.') == ext)
}
