import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { actionConfiguration, buildMatrixArguments } from "../scripts/run-action.mjs";

describe("GitHub Action", () => {
  test("declares the v0.7 package, report, build, and upload inputs", async () => {
    const action = await readFile(resolve("action.yml"), "utf8");

    expect(action).toContain("adapter-manifest:");
    expect(action).toContain("package-spec:");
    expect(action).toContain('default: "psbt-interop-lab@0.7"');
    expect(action).toContain("junit:");
    expect(action).toContain("sarif:");
    expect(action).toContain("build:");
    expect(action).toContain("upload-artifacts:");
    expect(action).toContain("node-version: 24");
    expect(action).toContain("scripts/run-action.mjs");
    expect(action).toContain("actions/upload-artifact@");
  });

  test("builds an external-only matrix command without shell interpolation", () => {
    expect(
      buildMatrixArguments({
        adapterManifest: "/workspace/wallet adapters.json",
        artifacts: "/workspace/artifacts",
        junit: "/workspace/reports/results.xml",
        sarif: "/workspace/reports/results.sarif",
        build: false,
      }),
    ).toEqual([
      "matrix",
      "--external-only",
      "--adapter-manifest",
      "/workspace/wallet adapters.json",
      "--artifacts",
      "/workspace/artifacts",
      "--junit",
      "/workspace/reports/results.xml",
      "--sarif",
      "/workspace/reports/results.sarif",
      "--no-build",
    ]);
  });

  test("requires a manifest and accepts only literal boolean inputs", () => {
    expect(() =>
      actionConfiguration({
        PSBT_LAB_ADAPTER_MANIFEST: "",
        PSBT_LAB_BUILD: "true",
      }),
    ).toThrow(/adapter-manifest/i);
    expect(() =>
      actionConfiguration({
        PSBT_LAB_ADAPTER_MANIFEST: "adapter.json",
        PSBT_LAB_BUILD: "yes",
      }),
    ).toThrow(/build.*true.*false/i);
  });
});
