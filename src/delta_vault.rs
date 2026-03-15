use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug)]
pub enum DeltaError {
    Io(String),
    Crypto(String),
    Format(String),
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(value) => write!(f, "{value}"),
            Self::Crypto(value) => write!(f, "{value}"),
            Self::Format(value) => write!(f, "{value}"),
        }
    }
}

impl std::error::Error for DeltaError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedDeltaRecord {
    anchor_id: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

pub struct LocalDeltaVault {
    path: PathBuf,
    encryption_key: [u8; 32],
}

impl LocalDeltaVault {
    pub fn from_password(password: &str) -> Self {
        let root = default_local_root();
        let _ = fs::create_dir_all(root.join("vault"));
        let _ = fs::create_dir_all(root.join("deltas"));
        let _ = fs::create_dir_all(root.join("keys"));
        Self {
            path: root.join("deltas"),
            encryption_key: derive_key(password),
        }
    }

    pub fn with_root(root: PathBuf, password: &str) -> Self {
        let _ = fs::create_dir_all(&root);
        let _ = fs::create_dir_all(root.join("deltas"));
        let _ = fs::create_dir_all(root.join("keys"));
        Self {
            path: root.join("deltas"),
            encryption_key: derive_key(password),
        }
    }

    pub fn store_delta(&self, anchor_id: Uuid, delta: &[u8]) -> Result<(), DeltaError> {
        fs::create_dir_all(&self.path).map_err(|err| DeltaError::Io(err.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|err| DeltaError::Crypto(err.to_string()))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut plaintext = delta.to_vec();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|err| DeltaError::Crypto(err.to_string()))?;
        plaintext.zeroize();
        let payload = EncryptedDeltaRecord {
            anchor_id: anchor_id.to_string(),
            nonce_b64: BASE64.encode(nonce),
            ciphertext_b64: BASE64.encode(ciphertext),
        };
        let raw = serde_json::to_string_pretty(&payload)
            .map_err(|err| DeltaError::Format(err.to_string()))?;
        fs::write(self.path.join(format!("{anchor_id}.delta.enc")), raw)
            .map_err(|err| DeltaError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn load_delta(&self, anchor_id: Uuid) -> Result<Vec<u8>, DeltaError> {
        let raw = fs::read_to_string(self.path.join(format!("{anchor_id}.delta.enc")))
            .map_err(|err| DeltaError::Io(err.to_string()))?;
        let payload: EncryptedDeltaRecord =
            serde_json::from_str(&raw).map_err(|err| DeltaError::Format(err.to_string()))?;
        let nonce = BASE64
            .decode(payload.nonce_b64)
            .map_err(|err| DeltaError::Format(err.to_string()))?;
        let ciphertext = BASE64
            .decode(payload.ciphertext_b64)
            .map_err(|err| DeltaError::Format(err.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|err| DeltaError::Crypto(err.to_string()))?;
        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|err| DeltaError::Crypto(err.to_string()))
    }

    pub fn ensure_gitignore_rules(repo_root: &Path) -> Result<(), DeltaError> {
        let path = repo_root.join(".gitignore");
        let mut content = if path.exists() {
            fs::read_to_string(&path).map_err(|err| DeltaError::Io(err.to_string()))?
        } else {
            String::new()
        };
        let required = ["deltas/", "keys/", "*.delta", "*.delta.enc", "*.key"];
        let mut changed = false;
        for rule in required {
            if !content.lines().any(|line| line.trim() == rule) {
                if !content.ends_with('\n') && !content.is_empty() {
                    content.push('\n');
                }
                content.push_str(rule);
                content.push('\n');
                changed = true;
            }
        }
        if changed {
            fs::write(path, content).map_err(|err| DeltaError::Io(err.to_string()))?;
        }
        Ok(())
    }
}

fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(b"|aether|local-delta-vault|v1");
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest[..32]);
    output
}

fn default_local_root() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home).join(".aether")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_vault_roundtrip_works() {
        let root = PathBuf::from("target").join("delta_vault_test");
        let _ = fs::remove_dir_all(&root);
        let vault = LocalDeltaVault::with_root(root, "topsecret-password");
        let anchor_id = Uuid::new_v4();
        let delta = b"delta-payload";
        vault.store_delta(anchor_id, delta).unwrap();
        let restored = vault.load_delta(anchor_id).unwrap();
        assert_eq!(restored, delta);
    }
}
