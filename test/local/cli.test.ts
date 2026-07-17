import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { createProgram } from "../../src/cli.js";

describe("local parser CLI", () => {
  test("exposes the Dockerless local parser runtime", () => {
    const command = createProgram().commands.find(
      (candidate) => candidate.name() === "parse-matrix",
    );
    const runtime = command?.options.find((option) => option.long === "--runtime");

    expect(runtime?.defaultValue).toBe("local");
  });

  test("runs without Docker or ambient executables", () => {
    const entrypoint = fileURLToPath(new URL("../../src/cli.ts", import.meta.url));
    const result = spawnSync(
      process.execPath,
      ["--import", "tsx", entrypoint, "parse-matrix", "--runtime", "local", "--json"],
      {
        encoding: "utf8",
        timeout: 30_000,
        env: { ...process.env, PATH: "", DOCKER_HOST: "invalid://must-not-be-used" },
      },
    );

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    const report = JSON.parse(result.stdout);
    expect(report).toMatchObject({
      runtime: "local",
      outcome: "partial",
      summary: { passed: 2, failed: 0 },
    });
    expect(report.cells).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ adapterId: "bundled-js", status: "passed" }),
        expect.objectContaining({ adapterId: "rust-bitcoin-native", status: "unsupported" }),
      ]),
    );
  }, 35_000);
});
