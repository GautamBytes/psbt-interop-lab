import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "vitest";
import { AdapterProcess, AdapterProtocolError } from "../../src/protocol/adapter-process.js";
import { ADAPTER_PROTOCOL, type AdapterRequest } from "../../src/protocol/types.js";

const fixture = fileURLToPath(new URL("../fixtures/fake-adapter.mjs", import.meta.url));

const running: AdapterProcess[] = [];

function create(mode = "ok", overrides: Record<string, unknown> = {}) {
  const adapter = new AdapterProcess({
    command: process.execPath,
    args: [fixture, mode],
    cwd: process.cwd(),
    maxLineBytes: 1024,
    maxStderrBytes: 64,
    ...overrides,
  });
  running.push(adapter);
  return adapter;
}

function request(id = "hello-1"): AdapterRequest {
  return {
    protocol: ADAPTER_PROTOCOL,
    id,
    operation: "hello",
    payload: {},
  };
}

afterEach(async () => {
  await Promise.all(running.splice(0).map((adapter) => adapter.close()));
});

describe("AdapterProcess", () => {
  test("exchanges one validated JSONL request", async () => {
    const adapter = create();

    const response = await adapter.request(request(), 1_000);

    expect(response.status).toBe("ok");
    if (response.status === "ok") {
      expect(response.output).toEqual({ echoed: "hello" });
    }
  });

  test("rejects a response with a mismatched id", async () => {
    const adapter = create("wrong-id");

    await expect(adapter.request(request(), 1_000)).rejects.toThrow(/response id/i);
  });

  test("restarts after a protocol violation before the next request", async () => {
    const directory = await mkdtemp(join(tmpdir(), "psbt-lab-adapter-restart-"));
    try {
      const marker = join(directory, "failed-once");
      const adapter = create("ok", { args: [fixture, "wrong-id-once", marker] });

      await expect(adapter.request(request("first"), 1_000)).rejects.toThrow(/response id/i);
      const response = await adapter.request(request("second"), 1_000);

      expect(response.status).toBe("ok");
      if (response.status === "ok") {
        expect(response.output).toEqual({ echoed: "hello" });
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("terminates an adapter that exceeds its line limit", async () => {
    const adapter = create("oversized");

    await expect(adapter.request(request(), 1_000)).rejects.toThrow(/line limit/i);
  });

  test("times out and terminates an unresponsive adapter", async () => {
    const adapter = create("timeout");

    await expect(adapter.request(request(), 20)).rejects.toThrow(/timed out/i);
  });

  test("caps captured stderr", async () => {
    const adapter = create("stderr");

    await adapter.request(request(), 1_000);

    expect(Buffer.byteLength(adapter.stderr)).toBeLessThanOrEqual(64);
  });

  test("validates a request before starting the process", async () => {
    const adapter = create();
    const unsafe = { ...request(), id: "../unsafe" } as AdapterRequest;

    await expect(adapter.request(unsafe, 1_000)).rejects.toBeInstanceOf(AdapterProtocolError);
  });
});
