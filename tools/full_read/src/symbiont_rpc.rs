use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn read_framed_json(stream: &mut TcpStream) -> Result<Value, String> {
    let mut header_bytes: Vec<u8> = Vec::with_capacity(256);
    let mut window: [u8; 4] = [0; 4];
    let mut byte = [0u8; 1];

    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|err| format!("Symbiont read header failed: {err}"))?;
        header_bytes.push(byte[0]);
        window[0] = window[1];
        window[1] = window[2];
        window[2] = window[3];
        window[3] = byte[0];
        if window == [b'\r', b'\n', b'\r', b'\n'] {
            break;
        }
        if header_bytes.len() > 16 * 1024 {
            return Err("Symbiont header too large".to_owned());
        }
    }

    let header = String::from_utf8_lossy(&header_bytes);
    let mut content_len: usize = 0;
    for line in header.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_len = rest.trim().parse::<usize>().unwrap_or(0);
            break;
        }
    }
    if content_len == 0 {
        return Err("Symbiont response without content-length".to_owned());
    }

    let mut body = vec![0u8; content_len];
    stream
        .read_exact(&mut body)
        .map_err(|err| format!("Symbiont read body failed: {err}"))?;

    serde_json::from_slice::<Value>(&body)
        .map_err(|err| format!("Symbiont response JSON invalid: {err}"))
}

pub fn request_json(host: &str, port: u16, method: &str, params: Value) -> Result<Value, String> {
    let addr = format!("{host}:{port}");
    let socket_addr = addr
        .to_socket_addrs()
        .map_err(|err| format!("Symbiont address invalid: {err}"))?
        .next()
        .ok_or_else(|| "Symbiont address resolution returned no target".to_owned())?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3))
        .map_err(|err| format!("Symbiont socket connect failed: {err}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(8)));

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let body = serde_json::to_vec(&payload)
        .map_err(|err| format!("Symbiont request serialization failed: {err}"))?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());

    stream
        .write_all(header.as_bytes())
        .map_err(|err| format!("Symbiont write header failed: {err}"))?;
    stream
        .write_all(&body)
        .map_err(|err| format!("Symbiont write body failed: {err}"))?;
    stream
        .flush()
        .map_err(|err| format!("Symbiont flush failed: {err}"))?;

    let response = read_framed_json(&mut stream)?;
    if let Some(error) = response.get("error") {
        return Err(format!("Symbiont RPC error: {error}"));
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}
