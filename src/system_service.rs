use aes_gcm::aead::{Aead, KeyInit, OsRng, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const SYSTEM_SERVICE_PORT: u16 = 40011;
pub const SERVICE_KEY_FILE: &str = "service_api.key";
pub const SERVICE_NAME: &str = "aether_system";

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceCommand {
    pub cmd: String,
    pub payload: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceResponse {
    pub ok: bool,
    pub message: String,
    pub data: Option<Value>,
}

pub fn service_socket_address() -> String {
    format!("127.0.0.1:{SYSTEM_SERVICE_PORT}")
}

pub fn service_key_path() -> PathBuf {
    crate::data_path(SERVICE_KEY_FILE)
}

pub fn load_or_create_service_key() -> Result<[u8; 32], String> {
    let path = service_key_path();
    if path.exists() {
        let mut file = File::open(&path).map_err(|e| format!("Unable to open service key: {e}"))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| format!("Unable to read service key: {e}"))?;
        if data.len() != 32 {
            return Err("Service key file has invalid length".to_owned());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        Ok(key)
    } else {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Unable to create service directory: {e}"))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| format!("Unable to create service key file: {e}"))?;
        file.write_all(&key)
            .map_err(|e| format!("Unable to write service key: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Unable to set key file permissions: {e}"))?;
        }
        Ok(key)
    }
}

pub fn encrypt_payload(key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, message)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    let mut frame = nonce_bytes.to_vec();
    frame.extend(ciphertext);
    Ok(frame)
}

pub fn decrypt_payload(key: &[u8; 32], frame: &[u8]) -> Result<Vec<u8>, String> {
    if frame.len() < 12 {
        return Err("Encrypted frame is too short".to_owned());
    }
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce = Nonce::from_slice(&frame[..12]);
    let ciphertext = &frame[12..];
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {e}"))
}

pub async fn run_system_service() -> Result<(), String> {
    let key = load_or_create_service_key()?;
    let addr = service_socket_address();
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Failed to bind system service socket {addr}: {e}"))?;
    println!("[{}] listening on {addr}", SERVICE_NAME);
    loop {
        let (socket, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("Accept failed: {e}"))?;
        let key = key;
        tokio::spawn(async move {
            if let Err(err) = handle_connection(key, socket).await {
                eprintln!("[{}] connection error from {peer}: {err}", SERVICE_NAME);
            }
        });
    }
}

async fn handle_connection(key: [u8; 32], mut socket: TcpStream) -> Result<(), String> {
    let frame = read_frame(&mut socket).await?;
    let plaintext = decrypt_payload(&key, &frame)?;
    let command: ServiceCommand = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Invalid command JSON: {e}"))?;
    let response = execute_command(command).await;
    let encoded = serde_json::to_vec(&response).map_err(|e| format!("Response JSON failed: {e}"))?;
    let encrypted = encrypt_payload(&key, &encoded)?;
    write_frame(&mut socket, &encrypted).await
}

async fn read_frame(socket: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    socket
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("Read failed: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buffer = vec![0u8; len];
    socket
        .read_exact(&mut buffer)
        .await
        .map_err(|e| format!("Read failed: {e}"))?;
    Ok(buffer)
}

async fn write_frame(socket: &mut TcpStream, frame: &[u8]) -> Result<(), String> {
    let len = (frame.len() as u32).to_be_bytes();
    socket
        .write_all(&len)
        .await
        .map_err(|e| format!("Write failed: {e}"))?;
    socket
        .write_all(frame)
        .await
        .map_err(|e| format!("Write failed: {e}"))
}

async fn execute_command(command: ServiceCommand) -> ServiceResponse {
    match command.cmd.as_str() {
        "status" => ServiceResponse {
            ok: true,
            message: "Aether system service is alive".to_owned(),
            data: Some(serde_json::json!({
                "service": SERVICE_NAME,
                "port": SYSTEM_SERVICE_PORT,
            })),
        },
        "analyze" => {
            match command.payload.and_then(|payload| payload.get("data").and_then(|v| v.as_str()).map(|s| s.to_owned())) {
                Some(base64_data) => match STANDARD.decode(&base64_data) {
                    Ok(bytes) => {
                        let analysis = analyze_bytes(&bytes);
                        ServiceResponse {
                            ok: true,
                            message: "Analysis completed".to_owned(),
                            data: Some(analysis),
                        }
                    }
                    Err(err) => ServiceResponse {
                        ok: false,
                        message: format!("Base64 decode failed: {err}"),
                        data: None,
                    },
                },
                None => ServiceResponse {
                    ok: false,
                    message: "Missing payload.data (base64)".to_owned(),
                    data: None,
                },
            }
        }
        "compress" => {
            match command.payload.and_then(|payload| payload.get("data").and_then(|v| v.as_str()).map(|s| s.to_owned())) {
                Some(base64_data) => match STANDARD.decode(&base64_data) {
                    Ok(bytes) => match compress_bytes(&bytes) {
                        Ok(compressed) => ServiceResponse {
                            ok: true,
                            message: "Compression completed".to_owned(),
                            data: Some(serde_json::json!({
                                "compressed_base64": STANDARD.encode(&compressed),
                                "ratio": compressed.len() as f64 / bytes.len().max(1) as f64,
                            })),
                        },
                        Err(err) => ServiceResponse {
                            ok: false,
                            message: err,
                            data: None,
                        },
                    },
                    Err(err) => ServiceResponse {
                        ok: false,
                        message: format!("Base64 decode failed: {err}"),
                        data: None,
                    },
                },
                None => ServiceResponse {
                    ok: false,
                    message: "Missing payload.data (base64)".to_owned(),
                    data: None,
                },
            }
        }
        other => ServiceResponse {
            ok: false,
            message: format!("Unknown command: {other}"),
            data: None,
        },
    }
}

fn analyze_bytes(bytes: &[u8]) -> Value {
    let entropy = byte_entropy(bytes);
    let periodicity = byte_periodicity(bytes);
    let spectral = noether_spectral_5(bytes);
    serde_json::json!({
        "length": bytes.len(),
        "entropy": entropy,
        "periodicity": periodicity,
        "spectral_bins": spectral,
        "compressibility_estimate": (1.0 - entropy / 8.0).max(0.0),
    })
}

fn byte_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total;
        entropy -= p * p.log2();
    }
    entropy
}

fn byte_periodicity(bytes: &[u8]) -> f64 {
    if bytes.len() < 4 {
        return 0.0;
    }
    let max_lag = bytes.len().min(48);
    let mut best = 0.0;
    for lag in 1..max_lag {
        let mut matches = 0usize;
        let mut compared = 0usize;
        for idx in 0..bytes.len() - lag {
            compared += 1;
            if bytes[idx] == bytes[idx + lag] {
                matches += 1;
            }
        }
        if compared > 0 {
            let score = matches as f64 / compared as f64;
            if score > best {
                best = score;
            }
        }
    }
    best.clamp(0.0, 1.0)
}

fn noether_spectral_5(data: &[u8]) -> [f64; 5] {
    let sample: Vec<f64> = data.iter().take(256).map(|b| *b as f64 / 255.0).collect();
    let n = sample.len();
    if n == 0 {
        return [0.0; 5];
    }
    let nf = n as f64;
    let mut out = [0.0; 5];
    for (ki, k) in (1usize..=5).enumerate() {
        let mut re = 0.0;
        let mut im = 0.0;
        for (idx, &x) in sample.iter().enumerate() {
            let angle = (2.0 * std::f64::consts::PI * k as f64 * idx as f64) / nf;
            re += x * angle.cos();
            im += x * angle.sin();
        }
        out[ki] = (re * re + im * im).sqrt() / nf;
    }
    out
}

fn compress_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::{write::ZlibEncoder, Compression};
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(data)
        .map_err(|e| format!("Compression failed: {e}"))?;
    encoder
        .finish()
        .map_err(|e| format!("Compression finish failed: {e}"))
}

pub async fn send_local_command(command: &ServiceCommand) -> Result<ServiceResponse, String> {
    let key = load_or_create_service_key()?;
    let addr = service_socket_address();
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("Connect failed to {addr}: {e}"))?;
    let payload = serde_json::to_vec(command).map_err(|e| format!("Serialize failed: {e}"))?;
    let encrypted = encrypt_payload(&key, &payload)?;
    write_frame(&mut stream, &encrypted).await?;
    let response_frame = read_frame(&mut stream).await?;
    let response_plain = decrypt_payload(&key, &response_frame)?;
    let response: ServiceResponse = serde_json::from_slice(&response_plain)
        .map_err(|e| format!("Response JSON decode failed: {e}"))?;
    Ok(response)
}
