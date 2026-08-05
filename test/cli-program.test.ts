import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
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
      "baseline",
      "doctor",
      "self-test",
      "list",
      "adapter",
      "run",
      "matrix",
      "parse-matrix",
      "fuzz",
      "stop",
      "replay",
      "compare",
      "history",
    ]);
  });

  test("offers bounded seeded differential fuzzing and regression promotion", () => {
    const fuzz = createProgram().commands.find((command) => command.name() === "fuzz");
    const parseMatrix = createProgram().commands.find(
      (command) => command.name() === "parse-matrix",
    );

    expect(fuzz?.options.find((option) => option.long === "--seed")?.defaultValue).toBe(0);
    expect(fuzz?.options.find((option) => option.long === "--cases")?.defaultValue).toBe(64);
    expect(fuzz?.options.some((option) => option.long === "--fixture")).toBe(true);
    expect(fuzz?.options.some((option) => option.long === "--promote")).toBe(true);
    expect(fuzz?.options.some((option) => option.long === "--adapter-manifest")).toBe(true);
    const issueBundle = fuzz?.options.find((option) => option.long === "--issue-bundle");
    expect((issueBundle as unknown as { conflictsWith?: string[] })?.conflictsWith).toContain(
      "promote",
    );
    expect(parseMatrix?.options.some((option) => option.long === "--suite-manifest")).toBe(true);
    expect(parseMatrix?.options.some((option) => option.long === "--adapter-manifest")).toBe(true);
    expect(() => fuzz?.parseOptions(["--cases", "0"])).toThrow(/between 1 and 512/i);
    expect(() => fuzz?.parseOptions(["--seed", "4294967296"])).toThrow(/32-bit/i);
  });

  test("offers ordered compatibility history export and an opt-in regression gate", () => {
    const history = createProgram().commands.find((command) => command.name() === "history");

    expect(history?.registeredArguments[0]?.variadic).toBe(true);
    expect(history?.options.some((option) => option.long === "--output")).toBe(true);
    expect(history?.options.some((option) => option.long === "--json")).toBe(true);
    expect(history?.options.some((option) => option.long === "--fail-on-regression")).toBe(true);
  });

  test("offers a bounded quickstart with reusable images and optional Core retention", () => {
    const quickstart = createProgram().commands.find((command) => command.name() === "quickstart");

    expect(quickstart?.options.some((option) => option.long === "--artifacts")).toBe(true);
    expect(quickstart?.options.some((option) => option.long === "--no-build")).toBe(true);
    expect(quickstart?.options.some((option) => option.long === "--keep-core")).toBe(true);
    expect(quickstart?.options.some((option) => option.long === "--scenario")).toBe(false);
    expect(quickstart?.options.some((option) => option.long === "--adapter-manifest")).toBe(false);
  });

  test("offers TypeScript adapter initialization next to conformance checking", () => {
    const adapter = createProgram().commands.find((command) => command.name() === "adapter");
    const init = adapter?.commands.find((command) => command.name() === "init");

    expect(adapter?.commands.map((command) => command.name())).toEqual(["check", "init"]);
    expect(init?.options.find((option) => option.long === "--name")?.mandatory).toBe(true);
    expect(init?.options.find((option) => option.long === "--template")?.defaultValue).toBe(
      "typescript",
    );
  });

  test("initializes a generated adapter from the CLI without installing dependencies", () => {
    const directory = mkdtempSync(resolve(tmpdir(), "psbt-lab-init-cli-"));
    const destination = resolve(directory, "wallet-adapter");
    const entrypoint = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

    try {
      const result = spawnSync(
        process.execPath,
        ["--import", "tsx", entrypoint, "adapter", "init", destination, "--name", "wallet-adapter"],
        { encoding: "utf8", timeout: 30_000 },
      );

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toContain(`Created TypeScript PSBT adapter at ${destination}`);
      expect(result.stdout).toContain("npm run conformance");
      expect(existsSync(resolve(destination, "adapter-manifest.json"))).toBe(true);
      expect(existsSync(resolve(destination, "node_modules"))).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);

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

  test("offers a baseline command with runtime options but no suite selector", () => {
    const baseline = createProgram().commands.find((command) => command.name() === "baseline");

    expect(baseline?.options.some((option) => option.long === "--artifacts")).toBe(true);
    expect(baseline?.options.some((option) => option.long === "--adapter-manifest")).toBe(true);
    expect(baseline?.options.some((option) => option.long === "--suite-manifest")).toBe(true);
    expect(baseline?.options.some((option) => option.long === "--scenario")).toBe(true);
    expect(baseline?.options.some((option) => option.long === "--category")).toBe(true);
    expect(baseline?.options.some((option) => option.long === "--suite")).toBe(false);
  });

  test("compares two artifact directories as JSON", () => {
    const directory = mkdtempSync(resolve(tmpdir(), "psbt-lab-compare-cli-"));
    const base = resolve(directory, "base");
    const head = resolve(directory, "head");
    const entrypoint = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
    const baseManifest = {
      schema: "psbt-lab.run/0.1",
      runId: "base-run",
      suite: "proof",
      startedAt: "2026-07-24T00:00:00.000Z",
      completedAt: "2026-07-24T00:00:01.000Z",
      outcome: "passed",
      adapters: [
        {
          name: "rust-bitcoin",
          version: "0.1.0",
          artifactDigest: `sha256:${"a".repeat(64)}`,
        },
      ],
      scenarios: [
        {
          id: "happy-path",
          title: "Happy path",
          category: "cross-library-signing",
          outcome: "passed",
          summary: "Policy accepted",
          durationMs: 1,
          assertions: [{ name: "core-policy-accepted", passed: true }],
        },
      ],
      checkpoints: [],
    };
    const headManifest = {
      ...baseManifest,
      runId: "head-run",
      outcome: "failed",
      scenarios: [
        {
          ...baseManifest.scenarios[0],
          outcome: "failed",
          summary: "Policy rejected",
          assertions: [{ name: "core-policy-accepted", passed: false }],
        },
      ],
    };

    try {
      mkdirSync(base);
      mkdirSync(head);
      writeFileSync(resolve(base, "manifest.json"), `${JSON.stringify(baseManifest)}\n`, {
        mode: 0o600,
      });
      writeFileSync(resolve(head, "manifest.json"), `${JSON.stringify(headManifest)}\n`, {
        mode: 0o600,
      });

      const result = spawnSync(
        process.execPath,
        ["--import", "tsx", entrypoint, "compare", base, head, "--json"],
        { encoding: "utf8", timeout: 30_000 },
      );

      expect(result.status).toBe(1);
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toMatchObject({
        changed: true,
        summary: { scenarioChanges: 1, assertionChanges: 1 },
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);

  test.each(["run", "matrix", "baseline"])(
    "accepts an external adapter manifest for %s",
    (commandName) => {
      const command = createProgram().commands.find(
        (candidate) => candidate.name() === commandName,
      );

      expect(command?.options.some((option) => option.long === "--adapter-manifest")).toBe(true);
      expect(command?.options.some((option) => option.long === "--suite-manifest")).toBe(true);
    },
  );

  test.each(["run", "matrix", "baseline"])("offers CI report outputs for %s", (commandName) => {
    const command = createProgram().commands.find((candidate) => candidate.name() === commandName);

    expect(command?.options.some((option) => option.long === "--junit")).toBe(true);
    expect(command?.options.some((option) => option.long === "--sarif")).toBe(true);
  });

  test.each(["run", "matrix", "baseline"])(
    "can restrict execution to external adapters for %s",
    (commandName) => {
      const command = createProgram().commands.find(
        (candidate) => candidate.name() === commandName,
      );

      expect(command?.options.some((option) => option.long === "--external-only")).toBe(true);
    },
  );

  test.each(["run", "matrix", "baseline"])(
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
      expect(result.stdout.trim()).toBe("0.8.0");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);
});
