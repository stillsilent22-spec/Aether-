use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use chrono::Utc;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::runtime::Builder;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRelayConfig {
    pub base_url: String,
    pub shared_secret: String,
    pub node_id: String,
    pub last_event_id: u64,
}

impl Default for ChatRelayConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            shared_secret: String::new(),
            node_id: format!("NODE-{}", Uuid::new_v4().simple()),
            last_event_id: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEvent {
    pub event_id: u64,
    pub created_at: String,
    pub origin_node: String,
    pub blob: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRelayEnvelope {
    pub room_kind: String,
    pub room_name: String,
    pub author: String,
    pub body: String,
    pub created_at: String,
}

pub struct ChatRelayStateStore {
    path: PathBuf,
}

pub struct ChatRelayClient {
    timeout_secs: f32,
}

impl ChatRelayStateStore {
    pub fn load_default() -> Result<ChatRelayConfig, String> {
        let path = PathBuf::from("data").join("rust_shell").join("chat_relay.json");
        if !path.exists() {
            return Ok(ChatRelayConfig::default());
        }
        let raw = fs::read_to_string(&path).map_err(|err| err.to_string())?;
        serde_json::from_str(&raw).map_err(|err| err.to_string())
    }

    pub fn new_default() -> Self {
        Self {
            path: PathBuf::from("data").join("rust_shell").join("chat_relay.json"),
        }
    }

    pub fn save(&self, config: &ChatRelayConfig) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        fs::write(
            &self.path,
            serde_json::to_string_pretty(config).map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())
    }
}

impl ChatRelayClient {
    pub fn new(timeout_secs: f32) -> Self {
        Self {
            timeout_secs: timeout_secs.max(1.0),
        }
    }

    pub fn health(&self, base_url: &str) -> Result<Value, String> {
        request_json(&format!("{}/health", normalize_url(base_url)), reqwest::Method::GET, None, HeaderMap::new(), self.timeout_secs)
    }

    pub fn publish(&self, config: &ChatRelayConfig, envelope: &ChatRelayEnvelope) -> Result<u64, String> {
        let blob = encrypt_sync_event(
            &serde_json::to_value(envelope).map_err(|err| err.to_string())?,
            &config.shared_secret,
        )?;
        let mut headers = sync_headers(&config.shared_secret)?;
        let body = serde_json::to_vec(&json!({
            "origin_node": config.node_id,
            "blob": blob,
        }))
        .map_err(|err| err.to_string())?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
        let response = request_json(
            &format!("{}/publish", normalize_url(&config.base_url)),
            reqwest::Method::POST,
            Some(body),
            headers,
            self.timeout_secs,
        )?;
        Ok(response.get("event_id").and_then(Value::as_u64).unwrap_or(0))
    }

    pub fn fetch(&self, config: &ChatRelayConfig) -> Result<Vec<(RelayEvent, ChatRelayEnvelope)>, String> {
        let mut headers = sync_headers(&config.shared_secret)?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
        let url = format!(
            "{}/events?after={}&limit=128",
            normalize_url(&config.base_url),
            config.last_event_id
        );
        let payload = request_json(&url, reqwest::Method::GET, None, headers, self.timeout_secs)?;
        let mut events = Vec::new();
        for item in payload.get("events").and_then(Value::as_array).cloned().unwrap_or_default() {
            let blob = item.get("blob").and_then(Value::as_str).unwrap_or_default();
            if blob.is_empty() {
                continue;
            }
            let decrypted = decrypt_sync_event(blob, &config.shared_secret)?;
            let envelope: ChatRelayEnvelope = serde_json::from_value(decrypted).map_err(|err| err.to_string())?;
            events.push((
                RelayEvent {
                    event_id: item.get("id").and_then(Value::as_u64).unwrap_or(0),
                    created_at: item.get("created_at").and_then(Value::as_str).unwrap_or_default().to_owned(),
                    origin_node: item.get("origin_node").and_then(Value::as_str).unwrap_or_default().to_owned(),
                    blob: blob.to_owned(),
                },
                envelope,
            ));
        }
        Ok(events)
    }
}

pub fn encrypt_sync_event(payload: &Value, shared_secret: &str) -> Result<String, String> {
    let key = derive_transport_key(shared_secret)?;
    let canonical = serde_json::to_vec(payload).map_err(|err| err.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    let digest = Sha256::digest(format!("{}|{}", Utc::now().timestamp_nanos_opt().unwrap_or_default(), Uuid::new_v4()).as_bytes());
    nonce_bytes.copy_from_slice(&digest[..12]);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|err| err.to_string())?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), canonical.as_ref())
        .map_err(|err| err.to_string())?;
    let mut payload = nonce_bytes.to_vec();
    payload.extend_from_slice(&ciphertext);
    Ok(BASE64_URL.encode(payload))
}

pub fn decrypt_sync_event(blob: &str, shared_secret: &str) -> Result<Value, String> {
    let key = derive_transport_key(shared_secret)?;
    let raw = BASE64_URL.decode(blob.as_bytes()).map_err(|err| err.to_string())?;
    if raw.len() < 13 {
        return Err("Ungueltiger Sync-Blob.".to_owned());
    }
    let (nonce, ciphertext) = raw.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|err| err.to_string())?;
    let payload = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|err| err.to_string())?;
    serde_json::from_slice(&payload).map_err(|err| err.to_string())
}

fn derive_transport_key(shared_secret: &str) -> Result<[u8; 32], String> {
    let normalized = shared_secret.trim();
    if normalized.len() < 8 {
        return Err("Das Sync-Secret muss mindestens 8 Zeichen lang sein.".to_owned());
    }
    let digest = Sha256::digest(normalized.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    Ok(key)
}

fn sync_headers(shared_secret: &str) -> Result<HeaderMap, String> {
    let token = Sha256::digest(&derive_transport_key(shared_secret)?);
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-aether-token"),
        HeaderValue::from_str(&token.iter().map(|byte| format!("{byte:02x}")).collect::<String>()).map_err(|err| err.to_string())?,
    );
    Ok(headers)
}

fn normalize_url(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_owned()
    } else {
        format!("http://{trimmed}")
    }
}

fn request_json(
    url: &str,
    method: reqwest::Method,
    body: Option<Vec<u8>>,
    headers: HeaderMap,
    timeout_secs: f32,
) -> Result<Value, String> {
    let runtime = Builder::new_current_thread().enable_all().build().map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs_f32(timeout_secs.max(1.0)))
            .build()
            .map_err(|err| err.to_string())?;
        let mut request = client.request(method, url).headers(headers);
        if let Some(payload) = body {
            request = request.body(payload);
        }
        let response = request.send().await.map_err(|err| err.to_string())?;
        let bytes = response.bytes().await.map_err(|err| err.to_string())?;
        serde_json::from_slice::<Value>(&bytes).map_err(|err| err.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_event_roundtrip_is_lossless() {
        let payload = json!({
            "room_kind": "shanway",
            "room_name": "Shanway",
            "author": "tester",
            "body": "hallo"
        });
        let blob = encrypt_sync_event(&payload, "supersecret").unwrap();
        let decoded = decrypt_sync_event(&blob, "supersecret").unwrap();
        assert_eq!(decoded["body"], "hallo");
    }

    #[test]
    fn relay_state_roundtrip_persists() {
        let store = ChatRelayStateStore {
            path: PathBuf::from("data").join("rust_shell").join("chat_relay_test.json"),
        };
        let config = ChatRelayConfig {
            base_url: "http://127.0.0.1:8765".to_owned(),
            shared_secret: "supersecret".to_owned(),
            node_id: "NODE-TEST".to_owned(),
            last_event_id: 7,
        };
        store.save(&config).unwrap();
        let raw = fs::read_to_string(&store.path).unwrap();
        let loaded: ChatRelayConfig = serde_json::from_str(&raw).unwrap();
        assert_eq!(loaded.last_event_id, 7);
        let _ = fs::remove_file(&store.path);
    }
}
