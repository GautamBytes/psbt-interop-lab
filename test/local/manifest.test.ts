import { createHash } from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";
import type { AdapterProcessOptions } from "../../src/protocol/adapter-process.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(resolve(tmpdir(), "psbt-lab-local-runtime-"));
  temporaryDirectories.push(directory);
  return directory;
}

function sha256(content: string): string {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function manifest(path: string, digest: string): unknown {
  return {
    schema: "psbt-lab.local-runtime/0.1",
    adapters: [
      {
        id: "bundled-js",
        availability: "available",
        launch: { kind: "node", path, sha256: digest },
        timeoutMs: 5_000,
        expected: {
          name: "psbt-lab-js",
          version: "0.1.0",
          sourceRevision: "bundled-js-v1",
          artifactDigest: digest,
        },
      },
      {
        id: "native-rust",
        availability: "unsupported",
        reason: "No verified native bundle is published for this platform",
      },
    ],
  };
}

describe("local runtime manifest", () => {
  test("creates verified package-local processes and preserves unsupported adapters", async () => {
    const directory = temporaryDirectory();
    const source = "process.stdin.resume();\n";
    writeFileSync(resolve(directory, "adapter.mjs"), source, { mode: 0o600 });
    const createProcess = vi.fn((_options: AdapterProcessOptions) => ({
      request: vi.fn(),
      close: vi.fn(async () => undefined),
    }));
    const local = await import("../../src/local/provider.js").catch(() => undefined);
    expect(local, "the local runtime provider boundary is missing").toBeDefined();
    if (!local) return;

    const provider = await local.createLocalRuntimeProvider({
      packageDirectory: directory,
      manifest: manifest("adapter.mjs", sha256(source)),
      createProcess,
    });
    const adapters = await provider.adapters();

    expect(provider.runtime).toBe("local");
    expect(adapters.map(({ availability }) => availability)).toEqual(["available", "unsupported"]);
    const canonicalDirectory = realpathSync(directory);
    expect(createProcess).toHaveBeenCalledWith({
      command: process.execPath,
      args: [expect.stringMatching(/psbt-lab-local-adapters-/)],
      cwd: canonicalDirectory,
    });
    expect(adapters[1]).toMatchObject({
      id: "native-rust",
      availability: "unsupported",
      reason: expect.stringMatching(/no verified native bundle/i),
    });
  });

  test("rejects checksum mismatches before creating a process", async () => {
    const directory = temporaryDirectory();
    writeFileSync(resolve(directory, "adapter.mjs"), "changed\n", { mode: 0o600 });
    const local = await import("../../src/local/provider.js");
    const createProcess = vi.fn();

    await expect(
      local.createLocalRuntimeProvider({
        packageDirectory: directory,
        manifest: manifest("adapter.mjs", `sha256:${"0".repeat(64)}`),
        createProcess,
      }),
    ).rejects.toThrow(/checksum.*bundled-js/i);
    expect(createProcess).not.toHaveBeenCalled();
  });

  test("launches an immutable private snapshot of the verified adapter", async () => {
    const directory = temporaryDirectory();
    const artifact = resolve(directory, "adapter.mjs");
    const source = "process.stdin.resume();\n";
    writeFileSync(artifact, source, { mode: 0o600 });
    const createProcess = vi.fn((options: AdapterProcessOptions) => {
      writeFileSync(artifact, "throw new Error('replaced');\n", { mode: 0o600 });
      const launchedPath = options.args?.[0];
      expect(launchedPath).not.toBe(artifact);
      expect(readFileSync(launchedPath as string, "utf8")).toBe(source);
      return { request: vi.fn(), close: vi.fn(async () => undefined) };
    });
    const local = await import("../../src/local/provider.js");

    const provider = await local.createLocalRuntimeProvider({
      packageDirectory: directory,
      manifest: manifest("adapter.mjs", sha256(source)),
      createProcess,
    });

    await provider.close();
    expect(createProcess).toHaveBeenCalledOnce();
  });

  test("rejects paths that escape through a symlink", async () => {
    const directory = temporaryDirectory();
    const outside = temporaryDirectory();
    const source = "process.stdin.resume();\n";
    writeFileSync(resolve(outside, "adapter.mjs"), source, { mode: 0o600 });
    symlinkSync(resolve(outside, "adapter.mjs"), resolve(directory, "adapter.mjs"));
    const local = await import("../../src/local/provider.js");

    await expect(
      local.createLocalRuntimeProvider({
        packageDirectory: directory,
        manifest: manifest("adapter.mjs", sha256(source)),
        createProcess: vi.fn(),
      }),
    ).rejects.toThrow(/outside.*package/i);
  });

  test.each([
    ["absolute paths", "/tmp/adapter.mjs"],
    ["parent traversal", "../adapter.mjs"],
  ])("rejects %s", async (_label, path) => {
    const local = await import("../../src/local/manifest.js").catch(() => undefined);
    expect(local, "the local manifest parser is missing").toBeDefined();
    if (!local) return;

    expect(() =>
      local.parseLocalRuntimeManifest(manifest(path, `sha256:${"0".repeat(64)}`)),
    ).toThrow(/path/i);
  });

  test("rejects command injection properties instead of forwarding them", async () => {
    const local = await import("../../src/local/manifest.js").catch(() => undefined);
    expect(local, "the local manifest parser is missing").toBeDefined();
    if (!local) return;
    const value = manifest("adapter.mjs", `sha256:${"0".repeat(64)}`) as {
      adapters: Array<Record<string, unknown>>;
    };
    value.adapters[0] = { ...value.adapters[0], shell: true, command: "sh" };

    expect(() => local.parseLocalRuntimeManifest(value)).toThrow(
      /unknown.*command|unknown.*shell/i,
    );
  });
});
