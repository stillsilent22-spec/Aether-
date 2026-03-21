use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct SwarmStartupStatus {
    pub node_initialized: bool,
    pub node_count: usize,
    pub new_pack_count: usize,
    pub summary: String,
}

pub fn probe_swarm_startup() -> SwarmStartupStatus {
    let node_secret_path = Path::new("keys").join("node_secret.key");
    let nodes_dir = Path::new("data").join("swarm").join("nodes");
    let anchors_dir = Path::new("data").join("anchors");

    if !node_secret_path.exists() {
        return SwarmStartupStatus {
            node_initialized: false,
            node_count: count_json_files(&nodes_dir),
            new_pack_count: 0,
            summary: "Node nicht initialisiert. Ausfuehren: python node_init.py".to_owned(),
        };
    }

    let known_before = pack_stems(&anchors_dir);
    let pull_result = try_git_pull();
    let known_after = pack_stems(&anchors_dir);
    let node_count = count_json_files(&nodes_dir);
    let new_pack_count = known_after.difference(&known_before).count();

    let summary = match pull_result {
        Some(Ok(())) => format!("Swarm bereit: {node_count} Node(s) | {new_pack_count} neue Pack(s)"),
        Some(Err(err)) => format!("Swarm lokal: {node_count} Node(s) | Git-Pull uebersprungen: {err}"),
        None => format!("Swarm lokal: {node_count} Node(s) | Git-Repo nicht aktiv"),
    };

    SwarmStartupStatus {
        node_initialized: true,
        node_count,
        new_pack_count,
        summary,
    }
}

fn try_git_pull() -> Option<Result<(), String>> {
    if !Path::new(".git").exists() {
        return None;
    }

    let output = Command::new("git")
        .args(["pull", "--ff-only", "origin", "master"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|err| format!("git nicht verfuegbar: {err}"));

    Some(match output {
        Ok(result) if result.status.success() => Ok(()),
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr).trim().to_owned();
            if stderr.is_empty() {
                Err(format!("Exit-Code {}", result.status))
            } else {
                Err(stderr)
            }
        }
        Err(err) => Err(err),
    })
}

fn pack_stems(dir: &Path) -> BTreeSet<String> {
    let mut stems = BTreeSet::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return stems;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("pack") {
            if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
                stems.insert(stem.to_owned());
            }
        }
    }
    stems
}

fn count_json_files(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
        .count()
}