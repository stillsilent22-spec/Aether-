use crate::inter_layer_bus::{
    BusEvent, CrossProgramReuseEvent, OfflineCacheEvent, PackInstalledEvent, PackRecommendedEvent,
    ShaderCacheHitEvent, ShanwayUserMessageEvent, TextureUploadResultEvent, VramOptimizedEvent,
    VramPressureEvent, WorkflowHitEvent, WorkflowLearnedEvent,
};
use chrono::Utc;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const TRANSPORT_DIR: &str = "data/interbus";
const EVENT_LOG_FILE: &str = "event_stream.jsonl";
const PUBLISH_LOG_FILE: &str = "publish_requests.jsonl";

pub fn ensure_transport_dir() -> Result<(), String> {
    fs::create_dir_all(transport_dir()).map_err(|err| err.to_string())
}

pub fn utc_now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn append_event(event: &BusEvent) -> Result<(), String> {
    ensure_transport_dir()?;
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .open(event_log_path())
        .map_err(|err| err.to_string())?;
    writeln!(handle, "{}", serialize_envelope(event)).map_err(|err| err.to_string())
}

pub fn append_publish_request(event_type: &str, payload_json: &str) -> Result<(), String> {
    ensure_transport_dir()?;
    let payload: Value = serde_json::from_str(payload_json).map_err(|err| err.to_string())?;
    let line = json!({
        "event_type": event_type,
        "payload": payload,
        "ts": utc_now_iso(),
    });
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .open(publish_log_path())
        .map_err(|err| err.to_string())?;
    writeln!(handle, "{line}").map_err(|err| err.to_string())
}

pub fn read_publish_requests_from(offset: u64) -> Result<(Vec<BusEvent>, u64), String> {
    ensure_transport_dir()?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(publish_log_path())
        .map_err(|err| err.to_string())?;
    let metadata_len = file.metadata().map_err(|err| err.to_string())?.len();
    let mut cursor = if offset > metadata_len { 0 } else { offset };
    file.seek(SeekFrom::Start(cursor))
        .map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut events = Vec::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).map_err(|err| err.to_string())?;
        if bytes_read == 0 {
            break;
        }
        cursor += bytes_read as u64;
        let raw = match serde_json::from_str::<Value>(&line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let event_type = raw
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let payload = raw.get("payload").cloned().unwrap_or_else(|| json!({}));
        if let Ok(event) = parse_event(event_type, payload) {
            events.push(event);
        }
    }
    Ok((events, cursor))
}

pub fn stream_events(filter: &[String]) -> Result<(), String> {
    ensure_transport_dir()?;
    let mut cursor = 0u64;
    loop {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(event_log_path())
            .map_err(|err| err.to_string())?;
        let len = file.metadata().map_err(|err| err.to_string())?.len();
        if cursor > len {
            cursor = 0;
        }
        file.seek(SeekFrom::Start(cursor))
            .map_err(|err| err.to_string())?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut advanced = false;
        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).map_err(|err| err.to_string())?;
            if bytes_read == 0 {
                break;
            }
            cursor += bytes_read as u64;
            advanced = true;
            let raw = match serde_json::from_str::<Value>(&line) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let event_type = raw
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if !filter.is_empty() && !filter.iter().any(|item| item == &event_type) {
                continue;
            }
            println!("{raw}");
            let _ = std::io::stdout().flush();
        }
        if !advanced {
            thread::sleep(Duration::from_millis(200));
        }
    }
}

pub fn event_type_name(event: &BusEvent) -> &'static str {
    match event {
        BusEvent::WorkflowAnchorHit(_) => "WorkflowAnchorHit",
        BusEvent::WorkflowAnchorLearned(_) => "WorkflowAnchorLearned",
        BusEvent::CrossProgramVramReuse(_) => "CrossProgramVramReuse",
        BusEvent::OfflineCachePrepared(_) => "OfflineCachePrepared",
        BusEvent::PackRecommended(_) => "PackRecommended",
        BusEvent::PackInstalled(_) => "PackInstalled",
        BusEvent::VramPressureChanged(_) => "VramPressureChanged",
        BusEvent::VramOptimized(_) => "VramOptimized",
        BusEvent::TextureUploadCompleted(_) => "TextureUploadCompleted",
        BusEvent::ShaderCacheHit(_) => "ShaderCacheHit",
        BusEvent::ShanwayUserMessage(_) => "ShanwayUserMessage",
        _ => "Unsupported",
    }
}

fn serialize_envelope(event: &BusEvent) -> Value {
    json!({
        "event_type": event_type_name(event),
        "payload": serialize_payload(event),
        "ts": utc_now_iso(),
    })
}

fn serialize_payload(event: &BusEvent) -> Value {
    match event {
        BusEvent::WorkflowAnchorHit(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::WorkflowAnchorLearned(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::CrossProgramVramReuse(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::OfflineCachePrepared(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::PackRecommended(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::PackInstalled(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::VramPressureChanged(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::VramOptimized(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::TextureUploadCompleted(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::ShaderCacheHit(payload) => {
            serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
        }
        BusEvent::ShanwayUserMessage(payload) => json!({
            "process_id": payload.process_id,
            "message": payload.message,
            "trust_score": payload.trust_score,
            "action_available": payload.action_available,
        }),
        _ => json!({}),
    }
}

fn parse_event(event_type: &str, payload: Value) -> Result<BusEvent, String> {
    match event_type {
        "WorkflowAnchorHit" => serde_json::from_value::<WorkflowHitEvent>(payload)
            .map(BusEvent::WorkflowAnchorHit)
            .map_err(|err| err.to_string()),
        "WorkflowAnchorLearned" => serde_json::from_value::<WorkflowLearnedEvent>(payload)
            .map(BusEvent::WorkflowAnchorLearned)
            .map_err(|err| err.to_string()),
        "CrossProgramVramReuse" => serde_json::from_value::<CrossProgramReuseEvent>(payload)
            .map(BusEvent::CrossProgramVramReuse)
            .map_err(|err| err.to_string()),
        "OfflineCachePrepared" => serde_json::from_value::<OfflineCacheEvent>(payload)
            .map(BusEvent::OfflineCachePrepared)
            .map_err(|err| err.to_string()),
        "PackRecommended" => serde_json::from_value::<PackRecommendedEvent>(payload)
            .map(BusEvent::PackRecommended)
            .map_err(|err| err.to_string()),
        "PackInstalled" => serde_json::from_value::<PackInstalledEvent>(payload)
            .map(BusEvent::PackInstalled)
            .map_err(|err| err.to_string()),
        "VramPressureChanged" => serde_json::from_value::<VramPressureEvent>(payload)
            .map(BusEvent::VramPressureChanged)
            .map_err(|err| err.to_string()),
        "VramOptimized" => serde_json::from_value::<VramOptimizedEvent>(payload)
            .map(BusEvent::VramOptimized)
            .map_err(|err| err.to_string()),
        "TextureUploadCompleted" => serde_json::from_value::<TextureUploadResultEvent>(payload)
            .map(BusEvent::TextureUploadCompleted)
            .map_err(|err| err.to_string()),
        "ShaderCacheHit" => serde_json::from_value::<ShaderCacheHitEvent>(payload)
            .map(BusEvent::ShaderCacheHit)
            .map_err(|err| err.to_string()),
        "ShanwayUserMessage" => {
            parse_shanway_user_message(payload).map(BusEvent::ShanwayUserMessage)
        }
        other => Err(format!("unsupported event type: {other}")),
    }
}

fn parse_shanway_user_message(payload: Value) -> Result<ShanwayUserMessageEvent, String> {
    Ok(ShanwayUserMessageEvent {
        process_id: payload
            .get("process_id")
            .and_then(Value::as_u64)
            .map(|value| value as u32),
        message: payload
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        trust_score: payload
            .get("trust_score")
            .and_then(Value::as_f64)
            .unwrap_or_default() as f32,
        action_available: payload
            .get("action_available")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn transport_dir() -> PathBuf {
    PathBuf::from(TRANSPORT_DIR)
}

fn event_log_path() -> PathBuf {
    transport_dir().join(EVENT_LOG_FILE)
}

fn publish_log_path() -> PathBuf {
    transport_dir().join(PUBLISH_LOG_FILE)
}
