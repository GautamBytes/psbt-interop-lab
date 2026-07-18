import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { createProgram } from "../src/cli.js";

describe("CLI program", () => {
  test("exposes discovery, matrix, runtime, and replay commands", () => {
    const commands = createProgram().commands.map((command) => command.name());

    expect(commands).toEqual([
      "quickstart",
      "doctor",
      "self-test",
      "list",
      "adapter",
      "run",
      "matrix",
      "parse-matrix",
      "stop",
      "replay",
    ]);
  });

  test("offers a bounded quickstart with reusable images and optional Core retention", () => {
    const quickstart = createProgram().commands.find((command) => command.name() === "quickstart");

    expect(quickstart?.options.some((option) => option.long === "--artifacts")).toBe(true);
    expect(quickstart?.options.some((option) => option.long === "--no-build")).toBe(true);
    expect(quickstart?.options.some((option) => option.long === "--keep-core")).toBe(true);
    expect(quickstart?.options.some((option) => option.long === "--scenario")).toBe(false);
    expect(quickstart?.options.some((option) => option.long === "--adapter-manifest")).toBe(false);
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

  test.each(["run", "matrix"])("accepts an external adapter manifest for %s", (commandName) => {
    const command = createProgram().commands.find((candidate) => candidate.name() === commandName);

    expect(command?.options.some((option) => option.long === "--adapter-manifest")).toBe(true);
    expect(command?.options.some((option) => option.long === "--suite-manifest")).toBe(true);
  });

  test.each(["run", "matrix"])(
    "accepts repeatable scenarios and an optional category for %s",
    (commandName) => {
      const command = createProgram().commands.find(
        (candidate) => candidate.name() === commandName,
      );

      command?.parseOptions([
        "--scenario",
        "happy-path",
        "--scenario",
        "p2wpkh-sign-rust-bitcoin",
        "--category",
        "cross-library-signing",
      ]);

      expect(command?.opts()).toMatchObject({
        scenario: ["happy-path", "p2wpkh-sign-rust-bitcoin"],
        category: "cross-library-signing",
      });
    },
  );

  test("rejects an unknown scenario with available selectors before invoking Docker", () => {
    const directory = mkdtempSync(resolve(tmpdir(), "psbt-lab-selector-"));
    const marker = resolve(directory, "docker-invoked");
    const docker = resolve(directory, "docker");
    const entrypoint = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
    writeFileSync(docker, `#!/bin/sh\ntouch ${JSON.stringify(marker)}\nexit 99\n`);
    chmodSync(docker, 0o700);

    try {
      const result = spawnSync(
        process.execPath,
        ["--import", "tsx", entrypoint, "run", "--scenario", "does-not-exist"],
        {
          encoding: "utf8",
          timeout: 30_000,
          env: { ...process.env, PATH: `${directory}:${process.env["PATH"] ?? ""}` },
        },
      );

      expect(result.status).not.toBe(0);
      expect(result.stderr).toMatch(/Unknown scenario.*does-not-exist/i);
      expect(result.stderr).toMatch(/happy-path/);
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);

  test("rejects filtered custom suites before invoking Docker", () => {
    const directory = mkdtempSync(resolve(tmpdir(), "psbt-lab-selector-suite-"));
    const marker = resolve(directory, "docker-invoked");
    const docker = resolve(directory, "docker");
    const entrypoint = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
    const suite = fileURLToPath(new URL("../examples/custom-suite.json", import.meta.url));
    writeFileSync(docker, `#!/bin/sh\ntouch ${JSON.stringify(marker)}\nexit 99\n`);
    chmodSync(docker, 0o700);

    try {
      const result = spawnSync(
        process.execPath,
        [
          "--import",
          "tsx",
          entrypoint,
          "run",
          "--scenario",
          "happy-path",
          "--suite-manifest",
          suite,
        ],
        {
          encoding: "utf8",
          timeout: 30_000,
          env: { ...process.env, PATH: `${directory}:${process.env["PATH"] ?? ""}` },
        },
      );

      expect(result.status).not.toBe(0);
      expect(result.stderr).toMatch(/scenario selection.*suite manifest/i);
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);

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
      expect(result.stdout.trim()).toBe("0.5.3");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);
});
