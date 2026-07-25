import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { test } from "node:test";

const VALID_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";

async function request(value) {
  const child = spawn(process.execPath, ["adapter.mjs"], {
    cwd: new URL("..", import.meta.url),
    stdio: ["pipe", "pipe", "pipe"],
  });
  const lines = createInterface({ input: child.stdout });
  child.stdin.end(`${typeof value === "string" ? value : JSON.stringify(value)}\n`);
  const [line] = await once(lines, "line");
  const [status] = await once(child, "exit");
  assert.equal(status, 0);
  return JSON.parse(line);
}

function envelope(operation, payload = {}) {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: `test-${operation}`,
    operation,
    payload,
  };
}

test("advertises a public parser and roundtrip adapter", async () => {
  const response = await request(envelope("hello"));

  assert.equal(response.status, "ok");
  assert.deepEqual(response.output.operations, ["hello", "native-parse", "roundtrip"]);
  assert.deepEqual(response.output.roles, ["parser"]);
  assert.deepEqual(response.output.psbtVersions, [0]);
  assert.deepEqual(response.output.scriptTypes, [
    "p2sh-p2wpkh",
    "p2wpkh",
    "p2wsh",
    "p2tr-keypath",
    "p2tr-scriptpath",
  ]);
});

test("uses bitcoinjs-lib for native parse and semantic roundtrip", async () => {
  const parsed = await request(envelope("native-parse", { psbt: VALID_PSBT }));
  const roundtrip = await request(envelope("roundtrip", { psbt: VALID_PSBT }));

  assert.equal(parsed.status, "ok");
  assert.equal(parsed.output.nativeParser, "wallet-ci-bitcoinjs");
  assert.equal(parsed.output.inputs, 1);
  assert.equal(parsed.output.outputs, 1);
  assert.equal(roundtrip.status, "ok");
  assert.equal(roundtrip.output.psbt, VALID_PSBT);
});

test("returns stable failures for malformed requests and PSBTs", async () => {
  const malformed = await request("{");
  const invalid = await request(envelope("native-parse", { psbt: "bm90IGEgcHNidA==" }));
  const unsupported = await request(envelope("sign", { psbt: VALID_PSBT }));

  assert.equal(malformed.status, "rejected");
  assert.equal(malformed.error.class, "protocol.invalid_json");
  assert.equal(invalid.status, "rejected");
  assert.equal(invalid.error.class, "psbt.native_parse_failed");
  assert.equal(unsupported.status, "unsupported");
  assert.equal(unsupported.error.class, "operation.unsupported");
});
