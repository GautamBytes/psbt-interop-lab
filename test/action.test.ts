import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { actionConfiguration, buildMatrixArguments } from "../scripts/run-action.mjs";

describe("GitHub Action", () => {
  test("ships adapter templates in the npm release", async () => {
    const packageManifest = JSON.parse(await readFile(resolve("package.json"), "utf8")) as {
      files?: string[];
    };

    expect(packageManifest.files).toContain("templates");
  });

  test("runs the expensive feature proof only for unstacked or top-layer pull requests", async () => {
    const workflow = await readFile(resolve(".github/workflows/ci.yml"), "utf8");

    expect(workflow).toContain("github.event.pull_request.stack == null");
    expect(workflow).toContain(
      "github.event.pull_request.stack.position == github.event.pull_request.stack.size",
    );
  });

  test("checks generated adapters with the packed candidate CLI", async () => {
    const workflow = await readFile(resolve(".github/workflows/ci.yml"), "utf8");

    expect(workflow).toContain(
      "/tmp/psbt-install/node_modules/.bin/psbt-lab adapter check /tmp/psbt-generated-adapter/adapter-manifest.json",
    );
    expect(workflow).not.toContain("npm run conformance --prefix /tmp/psbt-generated-adapter");
  });

  test("checks issue-bundle help from the packed candidate CLI", async () => {
    const workflow = await readFile(resolve(".github/workflows/ci.yml"), "utf8");

    expect(workflow).toContain("/tmp/psbt-install/node_modules/.bin/psbt-lab fuzz --help");
  });

  test("checks compatibility-history help from the packed candidate CLI", async () => {
    const workflow = await readFile(resolve(".github/workflows/ci.yml"), "utf8");

    expect(workflow).toContain("/tmp/psbt-install/node_modules/.bin/psbt-lab history --help");
  });

  test("declares the v0.10.1 package, report, build, and upload inputs", async () => {
    const action = await readFile(resolve("action.yml"), "utf8");

    expect(action).toContain("adapter-manifest:");
    expect(action).toContain("package-spec:");
    expect(action).toContain('default: "psbt-interop-lab@0.10.1"');
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

  test("pins the default action install to the exact reviewed release", () => {
    expect(
      actionConfiguration({
        PSBT_LAB_ADAPTER_MANIFEST: "adapter.json",
        PSBT_LAB_BUILD: "false",
      }).packageSpec,
    ).toBe("psbt-interop-lab@0.10.1");
  });
});
