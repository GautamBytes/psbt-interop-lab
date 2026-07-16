import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { createProgram } from "../src/cli.js";

describe("CLI program", () => {
  test("exposes discovery, matrix, runtime, and replay commands", () => {
    const commands = createProgram().commands.map((command) => command.name());

    expect(commands).toEqual([
      "doctor",
      "self-test",
      "list",
      "adapter",
      "run",
      "matrix",
      "stop",
      "replay",
    ]);
  });

  test("runs external adapter conformance from a manifest", () => {
    const directory = mkdtempSync(resolve(tmpdir(), "psbt-lab-conformance-"));
    const manifest = resolve(directory, "adapters.json");
    const entrypoint = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
    const adapter = fileURLToPath(new URL("fixtures/fake-adapter.mjs", import.meta.url));
    writeFileSync(
      manifest,
      JSON.stringify({
        schema: "psbt-lab.adapters/0.1",
        adapters: [
          {
            id: "fake-wallet",
            command: process.execPath,
            args: [adapter, "conformant"],
            expected: {
              name: "fake-wallet",
              version: "1.0.0",
              sourceRevision: "fake-wallet-v1.0.0",
            },
          },
        ],
      }),
      { mode: 0o600 },
    );

    try {
      const result = spawnSync(
        process.execPath,
        ["--import", "tsx", entrypoint, "adapter", "check", manifest, "--json"],
        { encoding: "utf8", timeout: 30_000 },
      );

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toMatchObject({ passed: true });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);

  test("writes default artifacts under the caller's working directory", () => {
    const matrix = createProgram().commands.find((command) => command.name() === "matrix");
    const artifacts = matrix?.options.find((option) => option.long === "--artifacts");

    expect(artifacts?.defaultValue).toBe(resolve(process.cwd(), "artifacts"));
  });

  test("runs when launched through an npm-style executable symlink", () => {
    const directory = mkdtempSync(resolve(tmpdir(), "psbt-lab-cli-"));
    const entrypoint = resolve(directory, "psbt-lab.ts");
    symlinkSync(fileURLToPath(new URL("../src/cli.ts", import.meta.url)), entrypoint);

    try {
      const result = spawnSync(process.execPath, ["--import", "tsx", entrypoint, "--version"], {
        encoding: "utf8",
        timeout: 30_000,
      });

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout.trim()).toBe("0.3.0");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);
});
