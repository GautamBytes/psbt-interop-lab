import { execFile, spawn } from "node:child_process";
import type { FileHandle } from "node:fs/promises";
import { appendFile, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, test, vi } from "vitest";
import { verifyReplay } from "../../src/runner/replay.js";

const execFileAsync = promisify(execFile);
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const roots: string[] = [];

interface ChildResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "psbt-lab-replay-"));
  roots.push(root);
  return root;
}

function emptyManifest(): string {
  return JSON.stringify({
    schema: "psbt-lab.run/0.1",
    runId: "replay-regression",
    outcome: "passed",
    checkpoints: [],
    scenarios: [],
  });
}

async function runReplayChild(
  script: string,
  root: string,
  timeoutMilliseconds = 1_000,
): Promise<ChildResult> {
  const child = spawn(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "--eval", script],
    {
      env: { ...process.env, REPLAY_ROOT: root },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  let stdout = "";
  let stderr = "";
  let timedOut = false;
  let spawnError: Error | undefined;
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  child.once("error", (error) => {
    spawnError = error;
  });
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, timeoutMilliseconds);

  let code: number | null = null;
  let signal: NodeJS.Signals | null = null;
  try {
    await new Promise<void>((resolveClose) =>
      child.once("close", (exitCode, exitSignal) => {
        code = exitCode;
        signal = exitSignal;
        resolveClose();
      }),
    );
  } finally {
    clearTimeout(timeout);
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
    child.stdout.destroy();
    child.stderr.destroy();
  }
  if (spawnError) {
    throw spawnError;
  }
  return { code, signal, stdout, stderr, timedOut };
}

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("verifyReplay descriptor reads", () => {
  test.skipIf(process.platform === "win32")(
    "reaps a child blocked opening an unpaired FIFO",
    async () => {
      const root = await temporaryRoot();
      const fifoPath = join(root, "blocked");
      await execFileAsync("mkfifo", [fifoPath]);
      const script = `
        import { constants } from "node:fs";
        import { open } from "node:fs/promises";
        await open(${JSON.stringify(fifoPath)}, constants.O_RDONLY);
      `;

      const result = await runReplayChild(script, root, 100);

      expect(result).toMatchObject({
        code: null,
        signal: "SIGKILL",
        timedOut: true,
      });
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects an unpaired manifest FIFO without blocking",
    async () => {
      const root = await temporaryRoot();
      const manifestPath = join(root, "manifest.json");
      await execFileAsync("mkfifo", [manifestPath]);

      const replayModule = pathToFileURL(resolve("src/runner/replay.ts")).href;
      const script = `
        import { verifyReplay } from ${JSON.stringify(replayModule)};
        const result = await verifyReplay(process.env.REPLAY_ROOT).then(
          () => ({ ok: true }),
          (error) => ({ ok: false, message: error instanceof Error ? error.message : String(error) }),
        );
        process.stdout.write(JSON.stringify(result));
      `;
      const result = await runReplayChild(script, root);

      expect(result.timedOut, result.stderr).toBe(false);
      expect(JSON.parse(result.stdout)).toEqual({
        ok: false,
        message: "Replay checkpoint must be a regular file",
      });
    },
  );

  test("rejects a manifest that grows beyond its initial descriptor size", async () => {
    const root = await temporaryRoot();
    const manifestPath = join(root, "manifest.json");
    await writeFile(manifestPath, emptyManifest());

    const probe = await open(manifestPath, "r");
    const fileHandlePrototype = Object.getPrototypeOf(probe) as FileHandle;
    const originalStat = fileHandlePrototype.stat;
    await probe.close();
    let grewAfterStat = false;
    vi.spyOn(fileHandlePrototype, "stat").mockImplementation(async function (this: FileHandle) {
      const metadata = await originalStat.call(this);
      if (!grewAfterStat) {
        grewAfterStat = true;
        await appendFile(manifestPath, "x".repeat(MAX_MANIFEST_BYTES + 1));
      }
      return metadata;
    });

    await expect(verifyReplay(root)).rejects.toThrow(/size limit/i);
    expect(grewAfterStat).toBe(true);
  });
});
