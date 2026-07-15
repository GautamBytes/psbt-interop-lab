import { createInterface } from "node:readline";

const mode = process.argv[2] ?? "ok";
const lines = createInterface({ input: process.stdin, crlfDelay: Number.POSITIVE_INFINITY });

for await (const line of lines) {
  const request = JSON.parse(line);

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

  const id = mode === "wrong-id" ? "different-id" : request.id;
  process.stdout.write(
    `${JSON.stringify({
      protocol: "psbt-lab.adapter/0.1",
      id,
      status: "ok",
      implementation: {
        name: "fake",
        version: "1.0.0",
        artifactDigest: "sha256:deadbeef",
      },
      output: { echoed: request.operation },
    })}\n`,
  );
}
