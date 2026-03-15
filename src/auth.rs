use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserRecord {
    pub username: String,
    pub salt_hex: String,
    pub password_hash_hex: String,
    pub created_at_epoch: u64,
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default)]
    pub user_settings: HashMap<String, String>,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub login_at_epoch: u64,
    #[serde(default)]
    pub live_session_key: String,
    #[serde(default)]
    pub live_session_fingerprint: String,
    #[serde(default)]
    pub session_seed: u64,
    #[serde(default)]
    pub raw_storage_key_hex: String,
    #[serde(default)]
    pub raw_storage_fingerprint: String,
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
        let salt_hex = random_hex(16);
        let password_hash_hex = hash_password(&normalized, &salt_hex, password);
        let role = if self.users.is_empty() {
            "admin".to_owned()
        } else {
            "operator".to_owned()
        };
        self.users.push(UserRecord {
            username: normalized,
            salt_hex,
            password_hash_hex,
            created_at_epoch: now,
            role,
            user_settings: HashMap::from([
                ("security_mode".to_owned(), "local".to_owned()),
                ("storage_model".to_owned(), "append_only".to_owned()),
            ]),
            session_id: String::new(),
            login_at_epoch: 0,
            live_session_key: String::new(),
            live_session_fingerprint: String::new(),
            session_seed: 0,
            raw_storage_key_hex: String::new(),
            raw_storage_fingerprint: String::new(),
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
        Ok(issue_session(user, password))
    }

    pub fn update_user_setting(
        &mut self,
        username: &str,
        key: &str,
        value: &str,
    ) -> Result<(), String> {
        let normalized = normalize_username(username)?;
        let Some(user) = self
            .users
            .iter_mut()
            .find(|candidate| candidate.username.eq_ignore_ascii_case(&normalized))
        else {
            return Err("Nutzer nicht gefunden.".to_owned());
        };
        user.user_settings.insert(key.to_owned(), value.to_owned());
        self.save()
    }

    pub fn usernames(&self) -> Vec<String> {
        let mut usernames = self
            .users
            .iter()
            .map(|user| user.username.clone())
            .collect::<Vec<_>>();
        usernames.sort();
        usernames
    }

    pub fn save(&self) -> Result<(), String> {
        let payload = StoredUsers {
            users: self.users.clone(),
        };
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("Auth-Verzeichnis konnte nicht erstellt werden: {err}"))?;
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
        return Err(
            "Nutzername darf nur ASCII-Buchstaben, Ziffern, _, - und . enthalten.".to_owned(),
        );
    }
    Ok(cleaned.to_owned())
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Passwort muss mindestens 8 Zeichen haben.".to_owned());
    }
    Ok(())
}

fn issue_session(mut user: UserRecord, password: &str) -> UserRecord {
    let login_at_epoch = now_epoch();
    let nonce = random_hex(32);
    let live_session_key = sha256_hex(
        format!(
            "{}|{}|{}|{}|{}",
            user.username, user.password_hash_hex, user.salt_hex, login_at_epoch, nonce
        )
        .as_bytes(),
    );
    let live_session_fingerprint =
        live_session_key[..24.min(live_session_key.len())].to_ascii_uppercase();
    let raw_storage_key_hex =
        sha256_hex(format!("{}|{}|{}|storage", user.username, user.salt_hex, password).as_bytes());
    let raw_storage_fingerprint =
        raw_storage_key_hex[..24.min(raw_storage_key_hex.len())].to_ascii_uppercase();
    let session_seed = derive_session_seed(&user.username, &user.salt_hex, &nonce);
    user.session_id = format!("session-{}", random_hex(12));
    user.login_at_epoch = login_at_epoch;
    user.live_session_key = live_session_key;
    user.live_session_fingerprint = live_session_fingerprint;
    user.session_seed = session_seed;
    user.raw_storage_key_hex = raw_storage_key_hex;
    user.raw_storage_fingerprint = raw_storage_fingerprint;
    user
}

fn derive_session_seed(username: &str, salt_hex: &str, nonce: &str) -> u64 {
    let digest = Sha256::digest(format!("{username}|{salt_hex}|{nonce}|seed").as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

fn random_hex(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn hash_password(username: &str, salt_hex: &str, password: &str) -> String {
    sha256_hex(format!("{username}|{salt_hex}|{password}|aether-rust-shell").as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn default_role() -> String {
    "operator".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_issues_live_session_fields() {
        let path = PathBuf::from("data")
            .join("rust_shell")
            .join("test_users_auth.json");
        let _ = fs::remove_file(&path);
        let mut store = AuthStore::load_from(path.clone());
        store.register("tester", "supersecret").unwrap();
        let user = store.authenticate("tester", "supersecret").unwrap();
        assert!(!user.session_id.is_empty());
        assert!(!user.live_session_key.is_empty());
        assert!(user.session_seed > 0);
        let _ = fs::remove_file(&path);
    }
}
