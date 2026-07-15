use std::fs;
use std::io::{self, BufRead, Write};

use psbt_lab_rust_adapter::{ADAPTER_PROTOCOL, handle_value};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

fn artifact_digest() -> String {
    let bytes = std::env::current_exe()
        .ok()
        .and_then(|path| fs::read(path).ok())
        .unwrap_or_else(|| b"psbt-lab-rust-adapter".to_vec());
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn read_bounded_line<R: BufRead>(reader: &mut R, line: &mut Vec<u8>) -> io::Result<bool> {
    line.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(!line.is_empty());
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > MAX_LINE_BYTES + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "adapter request exceeds the 4 MiB line limit",
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            return Ok(true);
        }
    }
}

fn main() -> io::Result<()> {
    let digest = artifact_digest();
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut line = Vec::new();

    while read_bounded_line(&mut reader, &mut line)? {
        let response = match serde_json::from_slice::<Value>(&line) {
            Ok(value) => handle_value(value, &digest),
            Err(_) => json!({
                "protocol": ADAPTER_PROTOCOL,
                "id": "invalid-1",
                "status": "rejected",
                "implementation": {
                    "name": "rust-bitcoin",
                    "version": env!("CARGO_PKG_VERSION"),
                    "artifactDigest": digest
                },
                "error": {
                    "class": "protocol.invalid_json",
                    "message": "Request line is not valid JSON",
                    "retryable": false
                }
            }),
        };
        serde_json::to_writer(&mut writer, &response)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}
