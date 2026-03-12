use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    pub salt_hex: String,
    pub password_hash_hex: String,
    pub created_at_epoch: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct StoredUsers {
    users: Vec<UserRecord>,
}

#[derive(Debug, Clone)]
pub struct AuthStore {
    path: PathBuf,
    users: Vec<UserRecord>,
}

impl AuthStore {
    pub fn load_default() -> Self {
        let path = PathBuf::from("data").join("rust_shell").join("users.json");
        Self::load_from(path)
    }

    pub fn load_from(path: PathBuf) -> Self {
        let users = load_users(&path).unwrap_or_default();
        Self { path, users }
    }

    pub fn register(&mut self, username: &str, password: &str) -> Result<(), String> {
        let normalized = normalize_username(username)?;
        validate_password(password)?;
        if self
            .users
            .iter()
            .any(|user| user.username.eq_ignore_ascii_case(&normalized))
        {
            return Err("Nutzername existiert bereits.".to_owned());
        }
        let now = now_epoch();
        let salt_hex = make_salt(&normalized, now);
        let password_hash_hex = hash_password(&normalized, &salt_hex, password);
        self.users.push(UserRecord {
            username: normalized,
            salt_hex,
            password_hash_hex,
            created_at_epoch: now,
        });
        self.save()?;
        Ok(())
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Result<UserRecord, String> {
        let normalized = normalize_username(username)?;
        let user = self
            .users
            .iter()
            .find(|candidate| candidate.username.eq_ignore_ascii_case(&normalized))
            .cloned()
            .ok_or_else(|| "Nutzer nicht gefunden.".to_owned())?;
        let expected = hash_password(&user.username, &user.salt_hex, password);
        if expected != user.password_hash_hex {
            return Err("Passwort ist ungueltig.".to_owned());
        }
        Ok(user)
    }

    pub fn save(&self) -> Result<(), String> {
        let payload = StoredUsers {
            users: self.users.clone(),
        };
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("Auth-Verzeichnis konnte nicht erstellt werden: {err}"))?;
        }
        let serialized = serde_json::to_string_pretty(&payload)
            .map_err(|err| format!("Auth-Daten konnten nicht serialisiert werden: {err}"))?;
        fs::write(&self.path, serialized)
            .map_err(|err| format!("Auth-Daten konnten nicht gespeichert werden: {err}"))?;
        Ok(())
    }
}

fn load_users(path: &Path) -> Option<Vec<UserRecord>> {
    let raw = fs::read_to_string(path).ok()?;
    let stored: StoredUsers = serde_json::from_str(&raw).ok()?;
    Some(stored.users)
}

fn normalize_username(value: &str) -> Result<String, String> {
    let cleaned = value.trim();
    if cleaned.len() < 3 {
        return Err("Nutzername muss mindestens 3 Zeichen haben.".to_owned());
    }
    if cleaned.len() > 32 {
        return Err("Nutzername darf hoechstens 32 Zeichen haben.".to_owned());
    }
    if !cleaned
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err("Nutzername darf nur ASCII-Buchstaben, Ziffern, _, - und . enthalten.".to_owned());
    }
    Ok(cleaned.to_owned())
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Passwort muss mindestens 8 Zeichen haben.".to_owned());
    }
    Ok(())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn make_salt(username: &str, timestamp: u64) -> String {
    let seed = format!("{username}:{timestamp}:aether-rust-shell");
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hash_password(username: &str, salt_hex: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(b"|");
    hasher.update(salt_hex.as_bytes());
    hasher.update(b"|");
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}
