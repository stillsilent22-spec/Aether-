use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
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
    #[serde(skip, default)]
    pub session_id: String,
    #[serde(skip, default)]
    pub login_at_epoch: u64,
    #[serde(skip, default)]
    pub live_session_key: String,
    #[serde(default)]
    pub live_session_fingerprint: String,
    #[serde(skip, default)]
    pub session_seed: u64,
    #[serde(skip, default)]
    pub raw_storage_key_hex: String,
    #[serde(default)]
    pub raw_storage_fingerprint: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub public_key_b64: String,
    #[serde(default)]
    pub yggdrasil_addr: String,
    #[serde(default)]
    pub device_fingerprint: String,
    #[serde(default)]
    pub genesis_bound: bool,
    #[serde(default)]
    pub native_ygg_bound: bool,
    #[serde(default)]
    pub identity_lock: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct StoredUsers {
    users: Vec<UserRecord>,
}

#[derive(Debug, Clone, Default)]
struct LocalIdentity {
    node_id: String,
    public_key_pem: String,
    public_key_b64: String,
    yggdrasil_addr: String,
    network_entry_id: String,
    device_fingerprint: String,
    native_ygg_capable: bool,
    genesis_publisher_id: String,
    genesis_node_id: String,
    genesis_public_key_b64: String,
    genesis_identity_lock: String,
    genesis_identity_lock_mode: String,
    genesis_key_present: bool,
    reserved_usernames: HashSet<String>,
}

impl LocalIdentity {
    fn has_verified_genesis_key_material(&self) -> bool {
        self.genesis_key_present
            && !self.genesis_publisher_id.is_empty()
            && !self.genesis_node_id.is_empty()
            && self.node_id.eq_ignore_ascii_case(&self.genesis_node_id)
            && !self.genesis_public_key_b64.is_empty()
            && self.public_key_b64 == self.genesis_public_key_b64
    }

    fn current_genesis_identity_lock(&self) -> String {
        if self.genesis_publisher_id.trim().is_empty() {
            return String::new();
        }
        identity_lock_for_username(&self.genesis_publisher_id, self)
    }

    fn can_seed_genesis_binding(&self) -> bool {
        if !self.has_verified_genesis_key_material() {
            return false;
        }
        let current_lock = self.current_genesis_identity_lock();
        if current_lock.is_empty() {
            return false;
        }
        if self.genesis_identity_lock.trim().is_empty() {
            return true;
        }
        let mode = self.genesis_identity_lock_mode.trim();
        self.genesis_identity_lock == current_lock
            && (mode.is_empty() || mode == "ygg-hw-username-v1")
    }

    fn is_verified_genesis(&self) -> bool {
        self.can_seed_genesis_binding() && !self.genesis_identity_lock.trim().is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TrustedPublishersManifest {
    #[serde(default)]
    admin_publisher_id: String,
    #[serde(default)]
    default_publisher_id: String,
    #[serde(default)]
    publishers: HashMap<String, TrustedPublisherEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TrustedPublisherEntry {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    signature_scheme: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    node_id: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    identity_lock: String,
    #[serde(default)]
    identity_lock_mode: String,
    #[serde(default)]
    notes: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DeviceLockRecord {
    #[serde(default)]
    node_id: String,
    #[serde(default)]
    device_fingerprint: String,
}

#[derive(Debug, Clone, Default)]
struct AccountClaim {
    username: String,
    node_id: String,
    device_fingerprint: String,
    yggdrasil_addr: String,
    identity_lock: String,
}

#[derive(Debug, Clone)]
pub struct AuthStore {
    path: PathBuf,
    users: Vec<UserRecord>,
}

impl AuthStore {
    pub fn load_default() -> Self {
        let path = crate::data_path("rust_shell/users.json");
        Self::load_from(path)
    }

    pub fn load_from(path: PathBuf) -> Self {
        let users = load_users(&path).unwrap_or_default();
        Self { path, users }
    }

    pub fn register(&mut self, username: &str, password: &str) -> Result<(), String> {
        let identity = load_local_identity()?;
        self.register_with_identity(username, password, &identity, true)
    }

    fn register_with_identity(
        &mut self,
        username: &str,
        password: &str,
        identity: &LocalIdentity,
        enforce_external_bindings: bool,
    ) -> Result<(), String> {
        let normalized = normalize_username(username)?;
        validate_password(password)?;
        ensure_local_account_available(&self.users, &normalized, identity)?;
        if enforce_external_bindings {
            ensure_native_ygg_binding_ready(identity)?;
            ensure_reserved_username_allowed(&normalized, identity)?;
            ensure_network_username_available(&normalized, identity)?;
        }
        let now = now_epoch();
        let salt_hex = random_hex(16);
        let password_hash_hex = hash_password(&normalized, &salt_hex, password);
        let identity_lock = identity_lock_for_username(&normalized, identity);
        let role = if identity.can_seed_genesis_binding()
            && normalized.eq_ignore_ascii_case(&identity.genesis_publisher_id)
        {
            "admin".to_owned()
        } else {
            "operator".to_owned()
        };
        let mut user_settings = HashMap::from([
            ("security_mode".to_owned(), "local".to_owned()),
            ("storage_model".to_owned(), "append_only".to_owned()),
        ]);
        user_settings.insert("bound_node_id".to_owned(), identity.node_id.clone());
        if !identity.device_fingerprint.is_empty() {
            user_settings.insert(
                "bound_device_fingerprint".to_owned(),
                identity.device_fingerprint.clone(),
            );
        }
        if !identity.yggdrasil_addr.is_empty() {
            user_settings.insert(
                "bound_yggdrasil_addr".to_owned(),
                identity.yggdrasil_addr.clone(),
            );
        }
        if !identity_lock.is_empty() {
            user_settings.insert("bound_identity_lock".to_owned(), identity_lock.clone());
            let lock_mode = if !identity.yggdrasil_addr.is_empty() {
                "ygg-hw-username-v1"
            } else {
                "dht-hw-username-v1"
            };
            user_settings.insert(
                "identity_lock_mode".to_owned(),
                lock_mode.to_owned(),
            );
        }
        if !identity.network_entry_id.is_empty() {
            user_settings.insert(
                "bound_network_entry_id".to_owned(),
                identity.network_entry_id.clone(),
            );
        }
        user_settings.insert(
            "native_ygg_bound".to_owned(),
            if identity.native_ygg_capable {
                "true".to_owned()
            } else {
                "false".to_owned()
            },
        );
        self.users.push(UserRecord {
            username: normalized.clone(),
            salt_hex,
            password_hash_hex,
            created_at_epoch: now,
            role,
            user_settings,
            session_id: String::new(),
            login_at_epoch: 0,
            live_session_key: String::new(),
            live_session_fingerprint: String::new(),
            session_seed: 0,
            raw_storage_key_hex: String::new(),
            raw_storage_fingerprint: String::new(),
            node_id: identity.node_id.clone(),
            public_key_b64: identity.public_key_b64.clone(),
            yggdrasil_addr: identity.yggdrasil_addr.clone(),
            device_fingerprint: identity.device_fingerprint.clone(),
            genesis_bound: identity.can_seed_genesis_binding()
                && username.eq_ignore_ascii_case(&identity.genesis_publisher_id),
            native_ygg_bound: identity.native_ygg_capable,
            identity_lock,
        });
        self.save()?;
        if enforce_external_bindings {
            sync_local_account_claim(&normalized, identity)?;
        }
        Ok(())
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Result<UserRecord, String> {
        let identity = load_local_identity()?;
        self.authenticate_with_identity(username, password, Some(&identity), true)
    }

    fn authenticate_with_identity(
        &self,
        username: &str,
        password: &str,
        identity: Option<&LocalIdentity>,
        enforce_external_bindings: bool,
    ) -> Result<UserRecord, String> {
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
        if enforce_external_bindings {
            let Some(identity) = identity else {
                return Err("Lokale Node-Identitaet fehlt.".to_owned());
            };
            validate_bound_user(&user, identity)?;
            sync_local_account_claim(&user.username, identity)?;
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

    pub fn change_password(
        &mut self,
        username: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), String> {
        let normalized = normalize_username(username)?;
        let Some(user) = self
            .users
            .iter_mut()
            .find(|candidate| candidate.username.eq_ignore_ascii_case(&normalized))
        else {
            return Err("Nutzer nicht gefunden.".to_owned());
        };

        let expected = hash_password(&user.username, &user.salt_hex, current_password);
        if expected != user.password_hash_hex {
            return Err("Aktuelles Passwort ist falsch.".to_owned());
        }

        validate_password(new_password)?;
        let new_salt = random_hex(16);
        user.salt_hex = new_salt.clone();
        user.password_hash_hex = hash_password(&user.username, &user.salt_hex, new_password);
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

    pub fn find_user(&self, username: &str) -> Option<UserRecord> {
        let normalized = normalize_username(username).ok()?;
        self.users
            .iter()
            .find(|candidate| candidate.username.eq_ignore_ascii_case(&normalized))
            .cloned()
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    pub fn sole_username(&self) -> Option<String> {
        if self.users.len() == 1 {
            self.users.first().map(|user| user.username.clone())
        } else {
            None
        }
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

fn load_local_identity() -> Result<LocalIdentity, String> {
    let node_path = crate::data_path("swarm/node.json");
    let mut node_object = load_json_object(&node_path)?;

    let public_key_pem = {
        let from_node = json_string(&node_object, "public_key_pem");
        if !from_node.is_empty() {
            from_node
        } else {
            fs::read_to_string(crate::data_path("keys/node_public.key")).map_err(|err| {
                format!(
                    "Lokaler Public Key fehlt in {}: {err}",
                    crate::data_path("keys/node_public.key").display()
                )
            })?
        }
    };

    let public_key_raw = decode_ed25519_public_key(&public_key_pem)?;
    let public_key_b64 = BASE64_STANDARD.encode(&public_key_raw);
    let derived_node_id = sha256_hex(&public_key_raw)[..16].to_owned();
    // DHT peer-id: gleichwertig zur Yggdrasil-Adresse fuer Nicht-Ygg-Knoten
    let network_entry_id = format!("peer-{}", &sha256_hex(&public_key_raw)[..32]);
    let stored_node_id = json_string(&node_object, "node_id");
    if !stored_node_id.is_empty() && !stored_node_id.eq_ignore_ascii_case(&derived_node_id) {
        node_object.insert("node_id".to_owned(), Value::String(derived_node_id.clone()));
        write_json_object(&node_path, &node_object)?;
    }

    let device_lock = load_device_lock().unwrap_or_default();
    if !device_lock.node_id.is_empty() && !device_lock.node_id.eq_ignore_ascii_case(&derived_node_id) {
        return Err(
            "Lokale Device-Bindung passt nicht zur aktuellen Node-ID. Starte den Python-Backend-Start erneut, damit die Hardware-Bindung repariert wird."
                .to_owned(),
        );
    }

    let manifest = load_trusted_publishers().unwrap_or_default();
    let genesis_publisher_id = if manifest.admin_publisher_id.trim().is_empty() {
        "tryharder997".to_owned()
    } else {
        manifest.admin_publisher_id.trim().to_owned()
    };
    let reserved_usernames = manifest
        .publishers
        .keys()
        .filter(|candidate| is_valid_reserved_username(candidate))
        .cloned()
        .collect::<HashSet<_>>();
    let genesis_entry = manifest
        .publishers
        .get(&genesis_publisher_id)
        .cloned()
        .unwrap_or_default();
    let native_ygg_capable = load_native_ygg_capability();

    Ok(LocalIdentity {
        node_id: derived_node_id,
        public_key_pem,
        public_key_b64,
        yggdrasil_addr: json_string(&node_object, "yggdrasil_addr"),
        network_entry_id,
        device_fingerprint: device_lock.device_fingerprint,
        native_ygg_capable,
        genesis_publisher_id,
        genesis_node_id: genesis_entry.node_id.trim().to_owned(),
        genesis_public_key_b64: genesis_entry.public_key.trim().to_owned(),
        genesis_identity_lock: genesis_entry.identity_lock.trim().to_owned(),
        genesis_identity_lock_mode: genesis_entry.identity_lock_mode.trim().to_owned(),
        genesis_key_present: crate::data_path("keys/genesis_node.key").exists(),
        reserved_usernames,
    })
}

fn load_device_lock() -> Option<DeviceLockRecord> {
    let path = crate::data_path("device_lock.json");
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn load_trusted_publishers() -> Result<TrustedPublishersManifest, String> {
    let path = crate::data_path("trusted_publishers.json");
    let raw = fs::read_to_string(&path)
        .map_err(|err| format!("trusted_publishers.json konnte nicht gelesen werden: {err}"))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("trusted_publishers.json ist ungueltig: {err}"))
}

fn load_native_ygg_capability() -> bool {
    let path = crate::data_path("interbus/hw_capability.json");
    let Ok(raw) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    if object
        .get("yggdrasil")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    // DHT-faehige Hardware gilt ebenfalls als netzwerkgebunden
    if object
        .get("dht")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    object
        .get("native_tier_rank")
        .and_then(Value::as_u64)
        .or_else(|| object.get("tier_rank").and_then(Value::as_u64))
        .unwrap_or(0)
        >= 3
}

fn ensure_native_ygg_binding_ready(identity: &LocalIdentity) -> Result<(), String> {
    if !identity.native_ygg_capable {
        return Ok(());
    }
    if identity.device_fingerprint.trim().is_empty() {
        return Err(
            "Netzwerkgebundener Knoten braucht eine lokale Hardware-Bindung. Starte Aether ueber start.py neu."
                .to_owned(),
        );
    }
    // Ygg-Pfad: Yggdrasil-Adresse erforderlich
    if !identity.yggdrasil_addr.trim().is_empty() {
        return Ok(());
    }
    // DHT-Pfad: deterministischer Peer-ID als gleichwertiger Anker
    if !identity.network_entry_id.trim().is_empty() {
        return Ok(());
    }
    Err(
        "Netzwerkgebundener Knoten braucht entweder eine Yggdrasil-Adresse oder eine DHT-Peer-ID. Starte Aether ueber start.py neu."
            .to_owned(),
    )
}

fn identity_lock_for_username(username: &str, identity: &LocalIdentity) -> String {
    if !identity.native_ygg_capable || identity.device_fingerprint.trim().is_empty() {
        return String::new();
    }
    // Ygg-Pfad: Yggdrasil-Adresse als Netzwerk-Anker
    if !identity.yggdrasil_addr.trim().is_empty() {
        return sha256_hex(
            format!(
                "aether.ygg-hw-user-lock.v1|{}|{}|{}|{}|{}",
                username.trim().to_ascii_lowercase(),
                identity.node_id.trim().to_ascii_lowercase(),
                identity.public_key_b64.trim(),
                identity.device_fingerprint.trim(),
                identity.yggdrasil_addr.trim().to_ascii_lowercase(),
            )
            .as_bytes(),
        );
    }
    // DHT-Pfad: deterministischer Peer-ID als gleichwertiger Netzwerk-Anker
    if !identity.network_entry_id.trim().is_empty() {
        return sha256_hex(
            format!(
                "aether.dht-hw-user-lock.v1|{}|{}|{}|{}|{}",
                username.trim().to_ascii_lowercase(),
                identity.node_id.trim().to_ascii_lowercase(),
                identity.public_key_b64.trim(),
                identity.device_fingerprint.trim(),
                identity.network_entry_id.trim().to_ascii_lowercase(),
            )
            .as_bytes(),
        );
    }
    String::new()
}

fn ensure_local_account_available(
    users: &[UserRecord],
    username: &str,
    identity: &LocalIdentity,
) -> Result<(), String> {
    if users
        .iter()
        .any(|user| user.username.eq_ignore_ascii_case(username))
    {
        return Err("Nutzername existiert bereits.".to_owned());
    }

    if let Some(user) = users
        .iter()
        .find(|user| !user.username.eq_ignore_ascii_case(username))
    {
        return Err(format!(
            "Dieses Geraet ist bereits an '{}' gebunden. Pro Geraet ist nur ein lokales Konto erlaubt.",
            user.username
        ));
    }

    if let Some(user) = users.iter().find(|user| {
        !user.node_id.is_empty() && !user.node_id.eq_ignore_ascii_case(&identity.node_id)
    }) {
        return Err(format!(
            "Das lokale Konto '{}' ist an eine andere Node-ID gebunden.",
            user.username
        ));
    }

    if identity.can_seed_genesis_binding()
        && !username.eq_ignore_ascii_case(&identity.genesis_publisher_id)
    {
        return Err(format!(
            "Dieses Geraet ist kryptographisch an den Genesis-Account '{}' gebunden.",
            identity.genesis_publisher_id
        ));
    }

    Ok(())
}

fn ensure_reserved_username_allowed(
    username: &str,
    identity: &LocalIdentity,
) -> Result<(), String> {
    if username.eq_ignore_ascii_case(&identity.genesis_publisher_id) {
        if identity.can_seed_genesis_binding() {
            return Ok(());
        }
        return Err(
            "Der Genesis-Account ist bereits global an ein anderes Schluesselpaar gebunden."
                .to_owned(),
        );
    }

    if identity
        .reserved_usernames
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(username))
    {
        return Err("Nutzername ist im Vertrauensregister bereits reserviert.".to_owned());
    }

    Ok(())
}

fn ensure_network_username_available(
    username: &str,
    identity: &LocalIdentity,
) -> Result<(), String> {
    let local_identity_lock = identity_lock_for_username(username, identity);
    for claim in load_swarm_account_claims()? {
        if !claim.username.eq_ignore_ascii_case(username) {
            continue;
        }
        if !claim.node_id.is_empty() && !claim.node_id.eq_ignore_ascii_case(&identity.node_id) {
            return Err(format!(
                "Nutzername '{}' ist im sichtbaren Netzwerk bereits an Node '{}' gebunden.",
                username, claim.node_id
            ));
        }
        if !claim.device_fingerprint.is_empty()
            && !identity.device_fingerprint.is_empty()
            && claim.device_fingerprint != identity.device_fingerprint
        {
            return Err(format!(
                "Nutzername '{}' ist bereits an eine andere Hardware-Bindung gekoppelt.",
                username
            ));
        }
        if identity.native_ygg_capable {
            ensure_native_ygg_binding_ready(identity)?;
            if !claim.yggdrasil_addr.is_empty()
                && !claim.yggdrasil_addr.eq_ignore_ascii_case(&identity.yggdrasil_addr)
            {
                return Err(format!(
                    "Nutzername '{}' ist bereits an eine andere Yggdrasil-Identitaet gekoppelt.",
                    username
                ));
            }
            if !claim.identity_lock.is_empty()
                && !local_identity_lock.is_empty()
                && claim.identity_lock != local_identity_lock
            {
                return Err(format!(
                    "Nutzername '{}' ist bereits an einen anderen Yggdrasil-/Hardware-Lock gekoppelt.",
                    username
                ));
            }
        }
    }
    Ok(())
}

fn load_swarm_account_claims() -> Result<Vec<AccountClaim>, String> {
    let mut claims = Vec::new();
    let local_path = crate::data_path("swarm/node.json");
    push_claim_from_path(&local_path, &mut claims)?;

    let nodes_dir = crate::data_path("swarm/nodes");
    if nodes_dir.is_dir() {
        let entries = fs::read_dir(&nodes_dir).map_err(|err| {
            format!(
                "Swarm-Nodes-Verzeichnis konnte nicht gelesen werden ({}): {err}",
                nodes_dir.display()
            )
        })?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                push_claim_from_path(&path, &mut claims)?;
            }
        }
    }

    Ok(claims)
}

fn push_claim_from_path(path: &Path, claims: &mut Vec<AccountClaim>) -> Result<(), String> {
    let payload = load_json_object(path)?;
    let username = json_string(&payload, "account_username");
    let node_id = json_string(&payload, "node_id");
    let device_fingerprint = json_string(&payload, "device_fingerprint");
    let yggdrasil_addr = json_string(&payload, "yggdrasil_addr");
    let identity_lock = json_string(&payload, "account_identity_lock");
    if !username.is_empty() && !node_id.is_empty() {
        claims.push(AccountClaim {
            username,
            node_id,
            device_fingerprint,
            yggdrasil_addr,
            identity_lock,
        });
    }
    Ok(())
}

fn validate_bound_user(user: &UserRecord, identity: &LocalIdentity) -> Result<(), String> {
    if !user.node_id.is_empty() && !user.node_id.eq_ignore_ascii_case(&identity.node_id) {
        return Err("Lokaler Account ist an eine andere Node-ID gebunden.".to_owned());
    }

    if !user.public_key_b64.is_empty() && user.public_key_b64 != identity.public_key_b64 {
        return Err("Lokaler Account passt nicht zum aktuellen Public Key.".to_owned());
    }

    if !user.device_fingerprint.is_empty()
        && !identity.device_fingerprint.is_empty()
        && user.device_fingerprint != identity.device_fingerprint
    {
        return Err("Dieses Konto ist an ein anderes Geraet gebunden.".to_owned());
    }

    let requires_ygg_lock = user.native_ygg_bound
        || (!user.yggdrasil_addr.is_empty() && !user.device_fingerprint.is_empty());
    if requires_ygg_lock {
        ensure_native_ygg_binding_ready(identity)?;
        if !user.yggdrasil_addr.is_empty()
            && !user.yggdrasil_addr.eq_ignore_ascii_case(&identity.yggdrasil_addr)
        {
            return Err(
                "Dieses Konto ist an eine andere Yggdrasil-Identitaet gebunden.".to_owned(),
            );
        }
        let expected_lock = identity_lock_for_username(&user.username, identity);
        if user.native_ygg_bound && user.identity_lock.trim().is_empty() {
            return Err("Netzwerkbindung des Kontos ist unvollstaendig (kein Identity-Lock gespeichert).".to_owned());
        }
        if !user.identity_lock.is_empty() && user.identity_lock != expected_lock {
            return Err(
                "Dieses Konto ist an einen anderen Yggdrasil-/Hardware-Lock gebunden."
                    .to_owned(),
            );
        }
    }

    if user.genesis_bound {
        if !user.username.eq_ignore_ascii_case(&identity.genesis_publisher_id) {
            return Err(
                "Genesis-Account passt nicht zum lokalen Genesis-Schluesselpaar.".to_owned(),
            );
        }
        if !identity.is_verified_genesis() && !identity.can_seed_genesis_binding() {
            return Err(
                "Genesis-Account passt nicht zum lokalen Genesis-Schluesselpaar.".to_owned(),
            );
        }
    }

    Ok(())
}

fn sync_local_account_claim(username: &str, identity: &LocalIdentity) -> Result<(), String> {
    let identity_lock = identity_lock_for_username(username, identity);
    sync_node_claim(&crate::data_path("swarm/node.json"), username, identity, &identity_lock)?;
    sync_node_claim(
        &crate::data_path(&format!("swarm/nodes/{}.json", identity.node_id)),
        username,
        identity,
        &identity_lock,
    )?;
    sync_settings_claim(username, identity, &identity_lock)?;
    if identity.can_seed_genesis_binding()
        && username.eq_ignore_ascii_case(&identity.genesis_publisher_id)
    {
        sync_trusted_genesis_claim(username, identity)?;
    }
    Ok(())
}

fn sync_node_claim(
	path: &Path,
	username: &str,
	identity: &LocalIdentity,
	identity_lock: &str,
) -> Result<(), String> {
    let mut payload = load_json_object(path)?;
    payload.insert(
        "schema".to_owned(),
        Value::String(
            payload
                .get("schema")
                .and_then(Value::as_str)
                .unwrap_or("aether.swarm.node.v2")
                .to_owned(),
        ),
    );
    payload.insert("node_id".to_owned(), Value::String(identity.node_id.clone()));
    payload.insert(
        "account_username".to_owned(),
        Value::String(username.to_owned()),
    );
    payload.insert(
        "native_ygg_bound".to_owned(),
        Value::Bool(identity.native_ygg_capable),
    );
    if !identity_lock.is_empty() {
        payload.insert(
            "account_identity_lock".to_owned(),
            Value::String(identity_lock.to_owned()),
        );
        let lock_mode = if !identity.yggdrasil_addr.is_empty() {
            "ygg-hw-username-v1"
        } else {
            "dht-hw-username-v1"
        };
        payload.insert(
            "identity_lock_mode".to_owned(),
            Value::String(lock_mode.to_owned()),
        );
    }
    if !identity.network_entry_id.is_empty() {
        payload.insert(
            "network_entry_id".to_owned(),
            Value::String(identity.network_entry_id.clone()),
        );
    }
    if !identity.public_key_pem.is_empty() {
        payload.insert(
            "public_key_pem".to_owned(),
            Value::String(identity.public_key_pem.clone()),
        );
    }
    if !identity.yggdrasil_addr.is_empty() {
        payload.insert(
            "yggdrasil_addr".to_owned(),
            Value::String(identity.yggdrasil_addr.clone()),
        );
    }
    if !identity.device_fingerprint.is_empty() {
        payload.insert(
            "device_fingerprint".to_owned(),
            Value::String(identity.device_fingerprint.clone()),
        );
    }
    if identity.can_seed_genesis_binding() {
        payload.insert("role".to_owned(), Value::String("genesis".to_owned()));
        payload.insert(
            "creator_locked_username".to_owned(),
            Value::String(identity.genesis_publisher_id.clone()),
        );
    }
    write_json_object(path, &payload)
}

fn sync_settings_claim(
	username: &str,
	identity: &LocalIdentity,
	identity_lock: &str,
) -> Result<(), String> {
    let path = crate::data_path("settings.json");
    let mut payload = load_json_object(&path)?;
    payload.insert("node_id".to_owned(), Value::String(identity.node_id.clone()));
    payload.insert(
        "account_username".to_owned(),
        Value::String(username.to_owned()),
    );
    payload.insert(
        "native_ygg_bound".to_owned(),
        Value::Bool(identity.native_ygg_capable),
    );
    if !identity_lock.is_empty() {
        payload.insert(
            "account_identity_lock".to_owned(),
            Value::String(identity_lock.to_owned()),
        );
        let lock_mode = if !identity.yggdrasil_addr.is_empty() {
            "ygg-hw-username-v1"
        } else {
            "dht-hw-username-v1"
        };
        payload.insert(
            "identity_lock_mode".to_owned(),
            Value::String(lock_mode.to_owned()),
        );
    }
    if identity.can_seed_genesis_binding() {
        payload.insert(
            "genesis_node_id".to_owned(),
            Value::String(identity.node_id.clone()),
        );
        payload.insert("node_role".to_owned(), Value::String("genesis".to_owned()));
        payload.insert("solo_genesis_mode".to_owned(), Value::Bool(true));
        payload.insert(
            "creator_locked_username".to_owned(),
            Value::String(identity.genesis_publisher_id.clone()),
        );
    }
    write_json_object(&path, &payload)
}

fn sync_trusted_genesis_claim(username: &str, identity: &LocalIdentity) -> Result<(), String> {
    let identity_lock = identity_lock_for_username(username, identity);
    if identity_lock.is_empty() {
        return Err(
            "Genesis-Claim braucht einen vollstaendigen Yggdrasil-/Hardware-/Username-Lock."
                .to_owned(),
        );
    }
    let path = crate::data_path("trusted_publishers.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|_| "{}".to_owned());
    let mut root: Value = serde_json::from_str(&raw).unwrap_or_else(|_| Value::Object(Map::new()));
    if !root.is_object() {
        root = Value::Object(Map::new());
    }
    let object = root.as_object_mut().expect("root is object");
    object.insert(
        "schema".to_owned(),
        Value::String(
            object
                .get("schema")
                .and_then(Value::as_str)
                .unwrap_or("aether.trusted_publishers.v1")
                .to_owned(),
        ),
    );
    object.insert(
        "admin_publisher_id".to_owned(),
        Value::String(username.to_owned()),
    );
    let publishers_value = object
        .entry("publishers".to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if !publishers_value.is_object() {
        *publishers_value = Value::Object(Map::new());
    }
    let publishers = publishers_value
        .as_object_mut()
        .expect("publishers must be object");
    let entry_value = publishers
        .entry(username.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if !entry_value.is_object() {
        *entry_value = Value::Object(Map::new());
    }
    let entry = entry_value.as_object_mut().expect("entry must be object");
    entry.insert("enabled".to_owned(), Value::Bool(true));
    entry.insert(
        "signature_scheme".to_owned(),
        Value::String("ed25519".to_owned()),
    );
    entry.insert(
        "public_key".to_owned(),
        Value::String(identity.public_key_b64.clone()),
    );
    entry.insert("node_id".to_owned(), Value::String(identity.node_id.clone()));
    entry.insert("role".to_owned(), Value::String("genesis".to_owned()));
    entry.insert(
        "identity_lock".to_owned(),
        Value::String(identity_lock),
    );
    entry.insert(
        "identity_lock_mode".to_owned(),
        Value::String("ygg-hw-username-v1".to_owned()),
    );
    entry
        .entry("notes".to_owned())
        .or_insert_with(|| Value::String("Admin / Genesis Node.".to_owned()));

    write_json_value(&path, &root)
}

fn load_json_object(path: &Path) -> Result<Map<String, Value>, String> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("{} konnte nicht gelesen werden: {err}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Map::new());
    }
    let value: Value = serde_json::from_str(&raw)
        .map_err(|err| format!("{} enthaelt ungueltiges JSON: {err}", path.display()))?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(format!("{} enthaelt kein JSON-Objekt.", path.display())),
    }
}

fn write_json_object(path: &Path, payload: &Map<String, Value>) -> Result<(), String> {
    write_json_value(path, &Value::Object(payload.clone()))
}

fn write_json_value(path: &Path, payload: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("{} konnte nicht erstellt werden: {err}", parent.display()))?;
    }
    let serialized = serde_json::to_string_pretty(payload)
        .map_err(|err| format!("{} konnte nicht serialisiert werden: {err}", path.display()))?;
    fs::write(path, serialized)
        .map_err(|err| format!("{} konnte nicht gespeichert werden: {err}", path.display()))?;
    Ok(())
}

fn json_string(payload: &Map<String, Value>, key: &str) -> String {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn decode_ed25519_public_key(pem: &str) -> Result<Vec<u8>, String> {
    let base64_body = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect::<String>();
    if base64_body.is_empty() {
        return Err("Public-Key-PEM ist leer.".to_owned());
    }
    let der = BASE64_STANDARD
        .decode(base64_body)
        .map_err(|err| format!("Public-Key-PEM konnte nicht dekodiert werden: {err}"))?;
    if der.len() < 32 {
        return Err("Public-Key-PEM ist zu kurz fuer einen Ed25519-Key.".to_owned());
    }
    Ok(der[der.len() - 32..].to_vec())
}

fn is_valid_reserved_username(candidate: &str) -> bool {
    let trimmed = candidate.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 32
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
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

    fn test_identity() -> LocalIdentity {
        let mut identity = LocalIdentity {
            node_id: "7a280b7e3ab3e042".to_owned(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAMsQdjWDgG0yv1IxWEFh5yC2H9bvXpGRKL8OTiVXqHeo=\n-----END PUBLIC KEY-----\n".to_owned(),
            public_key_b64: "MsQdjWDgG0yv1IxWEFh5yC2H9bvXpGRKL8OTiVXqHeo=".to_owned(),
            yggdrasil_addr: "200:ca77:8d5c:10b2:e3c0:d06c:6af4:dd5e".to_owned(),
            device_fingerprint: "device-fp".to_owned(),
            native_ygg_capable: true,
            genesis_publisher_id: "tryharder997".to_owned(),
            genesis_node_id: "7a280b7e3ab3e042".to_owned(),
            genesis_public_key_b64: "MsQdjWDgG0yv1IxWEFh5yC2H9bvXpGRKL8OTiVXqHeo=".to_owned(),
            genesis_identity_lock: String::new(),
            genesis_identity_lock_mode: "ygg-hw-username-v1".to_owned(),
            genesis_key_present: true,
            reserved_usernames: HashSet::from(["tryharder997".to_owned()]),
        };
        identity.genesis_identity_lock = identity_lock_for_username("tryharder997", &identity);
        identity
    }

    #[test]
    fn authenticate_issues_live_session_fields() {
        let path = crate::data_path("rust_shell/test_users_auth.json");
        let _ = fs::remove_file(&path);
        let mut store = AuthStore::load_from(path.clone());
        let identity = test_identity();
        store
            .register_with_identity("tryharder997", "supersecret", &identity, false)
            .unwrap();
        let user = store
            .authenticate_with_identity("tryharder997", "supersecret", Some(&identity), false)
            .unwrap();
        assert!(!user.session_id.is_empty());
        assert!(!user.live_session_key.is_empty());
        assert!(user.session_seed > 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn register_rejects_second_local_username() {
        let path = crate::data_path("rust_shell/test_users_single.json");
        let _ = fs::remove_file(&path);
        let mut store = AuthStore::load_from(path.clone());
        let identity = test_identity();
        store
            .register_with_identity("tryharder997", "supersecret", &identity, false)
            .unwrap();
        let err = store
            .register_with_identity("another_user", "supersecret", &identity, false)
            .unwrap_err();
        assert!(err.contains("nur ein lokales Konto erlaubt"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn identity_lock_changes_with_ygg_or_device() {
        let identity = test_identity();
        let baseline = identity_lock_for_username("tryharder997", &identity);
        assert!(!baseline.is_empty());

        let mut other_device = identity.clone();
        other_device.device_fingerprint = "device-fp-2".to_owned();
        assert_ne!(baseline, identity_lock_for_username("tryharder997", &other_device));

        let mut other_ygg = identity.clone();
        other_ygg.yggdrasil_addr = "200:ca77:8d5c:10b2:e3c0:d06c:6af4:ffff".to_owned();
        assert_ne!(baseline, identity_lock_for_username("tryharder997", &other_ygg));
    }

    #[test]
    fn validate_bound_user_rejects_yggdrasil_mismatch() {
        let identity = test_identity();
        let user = UserRecord {
            username: "tryharder997".to_owned(),
            salt_hex: "salt".to_owned(),
            password_hash_hex: "hash".to_owned(),
            created_at_epoch: 0,
            role: "admin".to_owned(),
            user_settings: HashMap::new(),
            session_id: String::new(),
            login_at_epoch: 0,
            live_session_key: String::new(),
            live_session_fingerprint: String::new(),
            session_seed: 0,
            raw_storage_key_hex: String::new(),
            raw_storage_fingerprint: String::new(),
            node_id: identity.node_id.clone(),
            public_key_b64: identity.public_key_b64.clone(),
            yggdrasil_addr: identity.yggdrasil_addr.clone(),
            device_fingerprint: identity.device_fingerprint.clone(),
            genesis_bound: true,
            native_ygg_bound: true,
            identity_lock: identity_lock_for_username("tryharder997", &identity),
        };

        let mut mismatched = identity.clone();
        mismatched.yggdrasil_addr = "200:ca77:8d5c:10b2:e3c0:d06c:6af4:1234".to_owned();
        let err = validate_bound_user(&user, &mismatched).unwrap_err();
        assert!(err.contains("Yggdrasil") || err.contains("Lock"));
    }

    #[test]
    fn verified_genesis_requires_manifest_identity_lock_match() {
        let identity = test_identity();
        assert!(identity.is_verified_genesis());

        let mut wrong_device = identity.clone();
        wrong_device.device_fingerprint = "other-device".to_owned();
        assert!(!wrong_device.is_verified_genesis());
        assert!(!wrong_device.can_seed_genesis_binding());
    }

    #[test]
    fn genesis_binding_can_seed_when_manifest_lock_missing() {
        let mut identity = test_identity();
        identity.genesis_identity_lock.clear();
        assert!(identity.can_seed_genesis_binding());
        assert!(!identity.is_verified_genesis());
    }
}
