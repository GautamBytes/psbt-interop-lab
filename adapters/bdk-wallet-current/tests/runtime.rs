use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

const FIXED_SIGNABLE_PSBT_V0: &str = "cHNidP8BAF4CAAAAAabTulINz+LhVA4VD8G0vFOohTRR1SaURoBkvPBzDudKAAAAAAD/////AWi/AAAAAAAAIgAgGGMUPBTFFmgEvRkgM1baE2yYVnjNTSehuMYylgSQMmIAAAAAAAEBK1DDAAAAAAAAIgAgGGMUPBTFFmgEvRkgM1baE2yYVnjNTSehuMYylgSQMmIBBSMhAnm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYrAAA";
const CORE_TYPESCRIPT_UNSIGNED_TX_COMMITMENT: &str =
    "sha256:2f46d1ac133fc2d11c6c267ae8a299eb19d688f9d1ea7d1fa0e178aaf339e4de";

fn request(operation: &str, payload: Value) -> Value {
    json!({
        "protocol": "psbt-lab.adapter/0.2",
        "id": "runtime-1",
        "operation": operation,
        "payload": payload
    })
}

fn run(lines: &[Vec<u8>], commitments: Option<&str>) -> Vec<Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_psbt-lab-bdk-wallet-adapter"));
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(commitments) = commitments {
        command.env("PSBT_LAB_FIXTURE_COMMITMENTS", commitments);
    }
    let mut child = command.spawn().expect("adapter executable starts");
    let mut stdin = child.stdin.take().expect("adapter stdin");
    for line in lines {
        stdin.write_all(line).expect("request line");
        stdin.write_all(b"\n").expect("request terminator");
    }
    drop(stdin);
    let output = child.wait_with_output().expect("adapter exits");
    assert!(
        output.status.success(),
        "adapter stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("UTF-8 stdout")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON response line"))
        .collect()
}

#[test]
fn binary_runs_network_free_and_emits_one_response_per_request() {
    let lines = [
        serde_json::to_vec(&request("hello", json!({}))).expect("hello request"),
        serde_json::to_vec(&request(
            "native-parse",
            json!({"psbt": FIXED_SIGNABLE_PSBT_V0}),
        ))
        .expect("parse request"),
    ];
    let responses = run(&lines, None);

    assert_eq!(responses.len(), 2);
    assert!(responses.iter().all(|response| response["status"] == "ok"));
    for response in responses {
        let digest = response["implementation"]["artifactDigest"]
            .as_str()
            .expect("artifact digest");
        assert!(
            digest.starts_with("sha256:")
                && digest.len() == 71
                && digest[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        );
        assert_eq!(response["implementation"]["version"], "3.1.0");
    }
}

#[test]
fn binary_reports_malformed_json_without_exiting() {
    let lines = [
        b"{not-json}".to_vec(),
        serde_json::to_vec(&request("hello", json!({}))).unwrap(),
    ];
    let responses = run(&lines, None);

    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["protocol"], "psbt-lab.adapter/0.2");
    assert_eq!(responses[0]["id"], "invalid-1");
    assert_eq!(responses[0]["status"], "rejected");
    assert_eq!(responses[0]["error"]["class"], "protocol.invalid_json");
    assert_eq!(responses[1]["status"], "ok");
}

#[test]
fn binary_signs_only_with_the_startup_fixture_commitment() {
    let line = serde_json::to_vec(&request(
        "sign",
        json!({
            "psbt": FIXED_SIGNABLE_PSBT_V0,
            "network": "regtest",
            "fixtureId": "happy-path"
        }),
    ))
    .expect("sign request");
    let commitments = format!(r#"{{"happy-path":"{CORE_TYPESCRIPT_UNSIGNED_TX_COMMITMENT}"}}"#);
    let signed = run(std::slice::from_ref(&line), Some(&commitments));
    assert_eq!(signed[0]["status"], "ok", "{}", signed[0]);
    assert_eq!(signed[0]["output"]["signedInputs"], 1);

    let invalid = run(std::slice::from_ref(&line), Some("{not-json}"));
    assert_eq!(invalid[0]["status"], "crashed", "{}", invalid[0]);
    assert_eq!(
        invalid[0]["error"]["class"],
        "adapter.invalid_configuration"
    );
}
