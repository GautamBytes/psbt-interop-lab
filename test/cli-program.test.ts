import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { createProgram } from "../src/cli.js";

describe("CLI program", () => {
  test("exposes discovery, matrix, runtime, and replay commands", () => {
    const commands = createProgram().commands.map((command) => command.name());

    expect(commands).toEqual(["doctor", "self-test", "list", "run", "matrix", "replay"]);
  });

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
      expect(result.stdout.trim()).toBe("0.2.0");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);
});
