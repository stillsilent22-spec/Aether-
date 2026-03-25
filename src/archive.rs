//! archive.rs
// Archiv-Handling für Aether: Automatisches Entpacken von ZIP, TAR, GZ, 7z, RAR vor Analyse.
// Wird von der GUI genutzt, um Archive vor der Analyse zu extrahieren.
//
// Funktionen:
// - extract_archive: Entpackt unterstützte Archive in ein Zielverzeichnis
//
// Hinweis: Für 7z und RAR werden externe Tools benötigt (7z.exe, unrar.exe)

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Unterstützte Archivformate
const SUPPORTED_ARCHIVES: &[&str] = &[".zip", ".tar", ".gz", ".7z", ".rar"];

/// Entpackt ein Archiv in das angegebene Zielverzeichnis.
pub fn extract_archive<P: AsRef<Path>>(archive_path: P, out_dir: P) -> io::Result<Vec<PathBuf>> {
    let path = archive_path.as_ref();
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let mut extracted = Vec::new();
    match ext.as_str() {
        "zip" => {
            let file = fs::File::open(path)?;
            let mut archive = zip::ZipArchive::new(file)?;
            for i in 0..archive.len() {
                let mut file = archive.by_index(i)?;
                let outpath = out_dir.as_ref().join(file.name());
                if file.is_dir() {
                    fs::create_dir_all(&outpath)?;
                } else {
                    if let Some(p) = outpath.parent() {
                        fs::create_dir_all(p)?;
                    }
                    let mut outfile = fs::File::create(&outpath)?;
                    std::io::copy(&mut file, &mut outfile)?;
                }
                extracted.push(outpath);
            }
        }
        "tar" | "gz" => {
            let file = fs::File::open(path)?;
            let mut archive = tar::Archive::new(file);
            archive.unpack(out_dir.as_ref())?;
            // Sammle extrahierte Pfade nicht einzeln
        }
        "7z" => {
            // 7z.exe muss im PATH sein
            let status = std::process::Command::new("7z")
                .args(["x", path.to_str().unwrap(), format!"-o{}", out_dir.as_ref().display().to_string()])
                .status()?;
            if !status.success() {
                return Err(io::Error::new(io::ErrorKind::Other, "7z extraction failed"));
            }
        }
        "rar" => {
            // unrar.exe muss im PATH sein
            let status = std::process::Command::new("unrar")
                .args(["x", path.to_str().unwrap(), out_dir.as_ref().to_str().unwrap()])
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
