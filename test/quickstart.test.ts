import { resolve } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { runDetectorCanaries } from "../src/canaries.js";
import { QUICKSTART_SCENARIO, type QuickstartDependencies, runQuickstart } from "../src/cli.js";

function dependencies(overrides: Partial<QuickstartDependencies> = {}): QuickstartDependencies {
  return {
    checkRuntime: vi.fn().mockResolvedValue([
      { name: "Node.js", ok: true, required: true, detail: process.versions.node },
      { name: "Docker", ok: true, required: true, detail: "29.0.0" },
      { name: "Docker Compose", ok: true, required: true, detail: "5.1.2" },
    ]),
    runCanaries: vi.fn(runDetectorCanaries),
    execute: vi.fn().mockResolvedValue(undefined),
    stopCore: vi.fn().mockResolvedValue(undefined),
    write: vi.fn(),
    ...overrides,
  };
}

describe("quickstart workflow", () => {
  test("checks the runtime, proves the detectors, runs one real handoff, and cleans up", async () => {
    const deps = dependencies();
    const artifacts = resolve("quickstart-artifacts");

    await runQuickstart({ artifacts, build: true, keepCore: false }, deps);

    expect(deps.checkRuntime).toHaveBeenCalledOnce();
    expect(deps.runCanaries).toHaveBeenCalledOnce();
    expect(deps.execute).toHaveBeenCalledWith({
      suite: "proof",
      artifacts,
      rpcUrl: "http://127.0.0.1:18443",
      build: true,
      startCore: true,
      scenario: [QUICKSTART_SCENARIO],
    });
    expect(deps.stopCore).toHaveBeenCalledOnce();
    expect(vi.mocked(deps.write).mock.calls.join("\n")).toMatch(
      /one real Core.*rust-bitcoin.*Core handoff/i,
    );
  });

  test("still stops Core when the interoperability run fails", async () => {
    const failure = new Error("scenario failed");
    const deps = dependencies({ execute: vi.fn().mockRejectedValue(failure) });

    await expect(
      runQuickstart(
        { artifacts: resolve("quickstart-artifacts"), build: true, keepCore: false },
        deps,
      ),
    ).rejects.toBe(failure);

    expect(deps.stopCore).toHaveBeenCalledOnce();
  });

  test("does not start Docker work when a required runtime check fails", async () => {
    const deps = dependencies({
      checkRuntime: vi
        .fn()
        .mockResolvedValue([{ name: "Docker", ok: false, required: true, detail: "not running" }]),
    });

    await expect(
      runQuickstart(
        { artifacts: resolve("quickstart-artifacts"), build: true, keepCore: false },
        deps,
      ),
    ).rejects.toThrow(/runtime checks failed/i);

    expect(deps.runCanaries).not.toHaveBeenCalled();
    expect(deps.execute).not.toHaveBeenCalled();
    expect(deps.stopCore).not.toHaveBeenCalled();
  });

  test("keeps Core running only when explicitly requested", async () => {
    const deps = dependencies();

    await runQuickstart(
      { artifacts: resolve("quickstart-artifacts"), build: false, keepCore: true },
      deps,
    );

    expect(deps.execute).toHaveBeenCalledWith(
      expect.objectContaining({ build: false, scenario: [QUICKSTART_SCENARIO] }),
    );
    expect(deps.stopCore).not.toHaveBeenCalled();
  });
});
