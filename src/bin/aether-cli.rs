use aether_rust_shell::aef::{EnginePipeline, VaultStore};
use aether_rust_shell::vault_access::{sync_public_vault, PublicAnchorRecord, VaultAccessLayer};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Debug, Serialize)]
struct PipelineReport {
    checked_files: usize,
    approved: usize,
    rejected: usize,
    threshold: f32,
    details: Vec<ReportEntry>,
}

#[derive(Debug, Serialize)]
struct ReportEntry {
    path: String,
    anchor_id: String,
    approved: bool,
    trust_score: f32,
    rejection_reason: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let vault = Arc::new(RwLock::new(VaultStore::load_default().unwrap_or_default()));
    let pipeline = Arc::new(EnginePipeline::new());
    let access = VaultAccessLayer::new(Arc::clone(&vault), Arc::clone(&pipeline));

    match args[1].as_str() {
        "verify-anchor" => {
            let Some(path) = args.get(2) else {
                eprintln!("verify-anchor braucht einen Pfad.");
                std::process::exit(1);
            };
            let result = verify_anchor(Path::new(path), &access)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if !result.approved {
                std::process::exit(2);
            }
        }
        "verify-signatures" => {
            let Some(root) = args.get(2) else {
                eprintln!("verify-signatures braucht ein Verzeichnis.");
                std::process::exit(1);
            };
            let files = walk_json_files(Path::new(root));
            let mut failures = 0usize;
            for file in files {
                let raw = fs::read_to_string(&file)?;
                let record: PublicAnchorRecord = serde_json::from_str(&raw)?;
                if access.verify_record_signature(&record).is_err() {
                    failures += 1;
                    eprintln!("Signatur ungueltig: {}", file.display());
                }
            }
            if failures > 0 {
                std::process::exit(2);
            }
        }
        "pipeline-check" => {
            let threshold = parse_threshold(&args).unwrap_or(0.65);
            let root = PathBuf::from("vault").join("anchors");
            let report = pipeline_check(&root, &access, threshold)?;
            fs::write(
                "shanway-report.json",
                serde_json::to_string_pretty(&report)?,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.rejected > 0 {
                std::process::exit(2);
            }
        }
        "sync-vault" => {
            let repo_root = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let since = args
                .get(3)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            let result = sync_public_vault(&access, &repo_root, since).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        other => {
            eprintln!("Unbekanntes Kommando: {other}");
            print_usage();
            std::process::exit(1);
        }
    }

    Ok(())
}

fn verify_anchor(
    path: &Path,
    access_layer: &VaultAccessLayer,
) -> Result<aether_rust_shell::vault_access::VerificationResult, Box<dyn std::error::Error>> {
    let record: PublicAnchorRecord = serde_json::from_str(&fs::read_to_string(path)?)?;
    Ok(access_layer.verify_anchor_record(&record)?)
}

fn pipeline_check(
    root: &Path,
    access_layer: &VaultAccessLayer,
    threshold: f32,
) -> Result<PipelineReport, Box<dyn std::error::Error>> {
    let files = walk_json_files(root);
    let mut report = PipelineReport {
        checked_files: 0,
        approved: 0,
        rejected: 0,
        threshold,
        details: Vec::new(),
    };
    for file in files {
        let raw = fs::read_to_string(&file)?;
        let record: PublicAnchorRecord = serde_json::from_str(&raw)?;
        let result = access_layer.verify_anchor_record(&record)?;
        let approved = result.approved && result.trust_score >= threshold;
        report.checked_files += 1;
        if approved {
            report.approved += 1;
        } else {
            report.rejected += 1;
        }
        report.details.push(ReportEntry {
            path: file.display().to_string(),
            anchor_id: record.anchor_id.to_string(),
            approved,
            trust_score: result.trust_score,
            rejection_reason: if approved {
                None
            } else {
                result.rejection_reason
            },
        });
    }
    Ok(report)
}

fn parse_threshold(args: &[String]) -> Option<f32> {
    args.windows(2)
        .find(|pair| pair[0] == "--threshold")
        .and_then(|pair| pair[1].parse::<f32>().ok())
}

fn walk_json_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walk_json_files(&path));
            } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
                files.push(path);
            }
        }
    }
    files
}

fn print_usage() {
    eprintln!(
        "Aether CLI\n\
         Kommandos:\n\
         - verify-anchor <path>\n\
         - verify-signatures <dir>\n\
         - pipeline-check [--threshold <float>]\n\
         - sync-vault [repo_root] [since_vault_version]"
    );
}
