use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn run_adapter(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_psbt-lab-rust-psbt-v2-adapter"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("adapter executable starts");
    let _ = child.stdin.take().expect("adapter stdin").write_all(input);
    child.wait_with_output().expect("adapter exits")
}

#[test]
fn serves_protocol_0_2_as_bounded_json_lines() {
    let request = json!({
        "protocol": "psbt-lab.adapter/0.2",
        "id": "hello-1",
        "operation": "hello",
        "payload": {}
    });
    let input = format!("{request}\n{{not json\n");
    let output = run_adapter(input.as_bytes());

    assert!(
        output.status.success(),
        "adapter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses: Vec<Value> = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("JSON response line"))
        .collect();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], "hello-1");
    assert_eq!(responses[0]["status"], "ok");
    assert_eq!(responses[1]["id"], "invalid-1");
    assert_eq!(responses[1]["status"], "rejected");
    assert_eq!(responses[1]["error"]["class"], "protocol.invalid_json");
    assert!(
        responses[0]["implementation"]["artifactDigest"]
            .as_str()
            .is_some_and(|digest| digest.len() == 71 && digest.starts_with("sha256:"))
    );
}

#[test]
fn exits_without_allocating_an_unbounded_request_line() {
    let input = vec![b'x'; psbt_lab_rust_psbt_v2_adapter::MAX_LINE_BYTES + 2];
    let output = run_adapter(&input);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("4 MiB line limit"));
}
