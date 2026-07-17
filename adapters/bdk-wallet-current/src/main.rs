use std::fs;
use std::io::{self, BufRead, Write};

use psbt_lab_bdk_wallet_adapter::{
    FixtureCommitments, MAX_LINE_BYTES, handle_value_with_commitments, invalid_json_response,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn artifact_digest() -> String {
    let bytes = std::env::current_exe()
        .ok()
        .and_then(|path| fs::read(path).ok())
        .unwrap_or_else(|| b"psbt-lab-bdk-wallet-adapter".to_vec());
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
            line.pop();
            return Ok(true);
        }
    }
}

fn main() -> io::Result<()> {
    let digest = artifact_digest();
    let raw_commitments = std::env::var("PSBT_LAB_FIXTURE_COMMITMENTS").ok();
    let commitments = FixtureCommitments::from_json(raw_commitments.as_deref())
        .unwrap_or_else(|_| FixtureCommitments::invalid());
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut line = Vec::new();

    while read_bounded_line(&mut reader, &mut line)? {
        let response = match serde_json::from_slice::<Value>(&line) {
            Ok(value) => handle_value_with_commitments(value, &digest, &commitments),
            Err(_) => invalid_json_response(&digest),
        };
        let encoded = serde_json::to_vec(&response)?;
        if encoded.len() > MAX_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "adapter response exceeds the 4 MiB line limit",
            ));
        }
        writer.write_all(&encoded)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}
