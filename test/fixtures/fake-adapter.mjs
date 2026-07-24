import { existsSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";

const mode = process.argv[2] ?? "ok";
const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const lines = createInterface({ input: process.stdin, crlfDelay: Number.POSITIVE_INFINITY });

for await (const line of lines) {
  const request = JSON.parse(line);

  if (mode === "conformant" || mode === "parser-only") {
    const implementation = {
      name: "fake-wallet",
      version: "1.0.0",
      artifactDigest: `sha256:${"b".repeat(64)}`,
      sourceRevision: "fake-wallet-v1.0.0",
    };
    if (request.operation === "hello") {
      process.stdout.write(
        `${JSON.stringify({
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "ok",
          implementation,
          output: {
            operations:
              mode === "conformant"
                ? ["hello", "native-parse", "roundtrip"]
                : ["hello", "native-parse"],
            roles: ["parser"],
            psbtVersions: [0],
            scriptTypes: ["p2wsh"],
            operationScriptTypes: mode === "conformant" ? { roundtrip: ["p2wsh"] } : {},
          },
        })}\n`,
      );
      continue;
    }
    if (request.operation === "native-parse" && request.payload.psbt === MINIMAL_PSBT) {
      process.stdout.write(
        `${JSON.stringify({
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "ok",
          implementation,
          output: { nativeParser: "fake-wallet", psbtVersion: 0, inputs: 1, outputs: 1 },
        })}\n`,
      );
      continue;
    }
    if (request.operation === "native-parse") {
      process.stdout.write(
        `${JSON.stringify({
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "rejected",
          implementation,
          error: {
            class: "psbt.native_parse_failed",
            message: "Native parser rejected malformed PSBT",
            retryable: false,
          },
        })}\n`,
      );
      continue;
    }
    if (request.operation === "roundtrip") {
      process.stdout.write(
        `${JSON.stringify({
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "ok",
          implementation,
          output: { psbt: request.payload.psbt, byteIdentical: true, psbtVersion: 0 },
        })}\n`,
      );
      continue;
    }
  }

  if (mode === "timeout") {
    continue;
  }
  if (mode === "oversized") {
    process.stdout.write(`${"x".repeat(2048)}\n`);
    continue;
  }
  if (mode === "stderr") {
    process.stderr.write("diagnostic".repeat(512));
  }

  if (mode === "wrong-id-once") {
    const marker = process.argv[3];
    if (!marker) throw new Error("wrong-id-once requires a marker path");
    if (!existsSync(marker)) {
      writeFileSync(marker, "failed\n", { flag: "wx", mode: 0o600 });
      process.stdout.write(
        `${JSON.stringify({
          protocol: "psbt-lab.adapter/0.2",
          id: "different-id",
          status: "ok",
          implementation: {
            name: "fake",
            version: "1.0.0",
            artifactDigest: `sha256:${"a".repeat(64)}`,
          },
          output: { echoed: request.operation },
        })}\n`,
      );
      continue;
    }
  }

  const id = mode === "wrong-id" ? "different-id" : request.id;
  process.stdout.write(
    `${JSON.stringify({
      protocol: "psbt-lab.adapter/0.2",
      id,
      status: "ok",
      implementation: {
        name: "fake",
        version: "1.0.0",
        artifactDigest: `sha256:${"a".repeat(64)}`,
      },
      output: { echoed: request.operation },
    })}\n`,
  );
}
