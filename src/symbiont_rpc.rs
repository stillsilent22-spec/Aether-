use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Send a blocking JSON-RPC request to the Symbiont bridge over a raw TCP/HTTP-1.1
/// connection.  Called from within `async move {}` blocks via Iced's
/// `Task::perform`, so it must be synchronous.
///
/// # Arguments
/// * `host` – hostname or IP (typically `"127.0.0.1"`)
/// * `port` – TCP port (typically `38571`)
/// * `endpoint` – URL path without leading slash, e.g. `"aether/profile"`
/// * `body` – JSON body to POST
///
/// # Errors
/// Returns `Err(String)` on connection failure, write/read error, or if the
/// response body is not valid JSON.
pub fn request_json(
    host: &str,
    port: u16,
    endpoint: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body_str = serde_json::to_string(&body)
        .map_err(|e| format!("JSON-Serialisierungsfehler: {e}"))?;
    let body_bytes = body_str.as_bytes();

    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("Symbiont-Verbindung fehlgeschlagen ({addr}): {e}"))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("Timeout-Konfiguration fehlgeschlagen: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Timeout-Konfiguration fehlgeschlagen: {e}"))?;

    let request = format!(
        "POST /{endpoint} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body_bytes.len()
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("HTTP-Request-Schreiben fehlgeschlagen: {e}"))?;
    stream
        .write_all(body_bytes)
        .map_err(|e| format!("HTTP-Body-Schreiben fehlgeschlagen: {e}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("HTTP-Response-Lesen fehlgeschlagen: {e}"))?;

    // HTTP-Header von Body trennen
    let body_start = response
        .find("\r\n\r\n")
        .ok_or_else(|| "Ungültige HTTP-Antwort: kein Header-Body-Trennzeichen".to_owned())?
        + 4;
    let json_body = &response[body_start..];

    serde_json::from_str(json_body)
        .map_err(|e| format!("Symbiont-Antwort kein gültiges JSON: {e}\nRaw: {json_body}"))
}
