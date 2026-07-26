import { resolve } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { type BaselineDependencies, runBaseline } from "../src/cli.js";

function dependencies(overrides: Partial<BaselineDependencies> = {}): BaselineDependencies {
  return {
    checkRuntime: vi.fn().mockResolvedValue([
      { name: "Node.js", ok: true, required: true, detail: process.versions.node },
      { name: "Docker", ok: true, required: true, detail: "29.0.0" },
      { name: "Docker Compose", ok: true, required: true, detail: "5.1.2" },
    ]),
    execute: vi.fn().mockResolvedValue(undefined),
    write: vi.fn(),
    ...overrides,
  };
}

describe("baseline workflow", () => {
  test("checks the runtime before running the complete proof matrix", async () => {
    const deps = dependencies();
    const artifacts = resolve("baseline-artifacts");
    const junit = resolve("reports", "baseline.xml");
    const sarif = resolve("reports", "baseline.sarif");

    await runBaseline(
      {
        artifacts,
        rpcUrl: "http://127.0.0.1:18443",
        build: true,
        startCore: true,
        scenario: [],
        junit,
        sarif,
      },
      deps,
    );

    expect(deps.checkRuntime).toHaveBeenCalledOnce();
    expect(deps.execute).toHaveBeenCalledWith({
      suite: "proof",
      artifacts,
      rpcUrl: "http://127.0.0.1:18443",
      build: true,
      startCore: true,
      scenario: [],
      junit,
      sarif,
    });
    expect(vi.mocked(deps.write).mock.calls.join("\n")).toMatch(/complete proof matrix/i);
  });
});
