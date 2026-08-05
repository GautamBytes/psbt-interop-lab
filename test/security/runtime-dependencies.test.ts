import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";

function readProjectFile(path: string): string {
  return readFileSync(resolve(process.cwd(), path), "utf8");
}

describe("published runtime dependency boundary", () => {
  test("uses generated validators without loading Ajv at runtime", () => {
    const packageJson = JSON.parse(readProjectFile("package.json")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      scripts?: Record<string, string>;
      files?: string[];
    };

    expect(packageJson.dependencies).not.toHaveProperty("ajv");
    expect(packageJson.devDependencies).toHaveProperty("ajv");
    expect(packageJson.scripts?.["check:validators"]).toBe(
      "tsx scripts/generate-validators.ts --check",
    );
    expect(packageJson.scripts?.["build"]).toContain("tsx scripts/copy-static-assets.ts");
    expect(readProjectFile("src/protocol/schema.ts")).not.toContain('from "ajv"');
    expect(readProjectFile("src/protocol/schema-definitions.ts")).not.toContain('from "ajv"');
    expect(readProjectFile("src/conformance/manifest.ts")).not.toContain('from "ajv"');
    expect(readProjectFile("src/generated/validators.ts")).not.toMatch(
      /(?:from\s+["']ajv|require\(["']ajv)/,
    );
    expect(readProjectFile("scripts/copy-static-assets.ts")).toContain(
      "suite-manifest.schema.json",
    );
    expect(packageJson.files).toEqual(
      expect.arrayContaining([
        "src/custom/suite-manifest.schema.json",
        "adapters/bdk-wallet-current/Cargo.lock",
        "adapters/rust-psbt-v2/Cargo.lock",
        "adapters/libwally-1.5.4/build-requirements.txt",
        "adapters/musig2-rust/Cargo.lock",
        "adapters/musig2-scure/package-lock.json",
        "adapters/hwi-simulator/package-lock.json",
        "examples/custom-suite.json",
      ]),
    );
  });

  test("ships and verifies the independent Scure MuSig2 runtime", () => {
    const packageJson = JSON.parse(readProjectFile("package.json"));
    const compose = readProjectFile("compose.yaml");
    const cli = readProjectFile("src/cli.ts");
    const workflow = readProjectFile(".github/workflows/ci.yml");

    expect(packageJson.files).toEqual(
      expect.arrayContaining([
        "adapters/musig2-scure/Dockerfile",
        "adapters/musig2-scure/package.json",
        "adapters/musig2-scure/package-lock.json",
        "adapters/musig2-scure/adapter.mjs",
        "adapters/musig2-scure/test",
      ]),
    );
    expect(compose).toMatch(
      /musig2-signer-2:\n(?:.|\n)*?image: psbt-interop-lab\/musig2-scure:0\.1\.0\n(?:.|\n)*?context: adapters\/musig2-scure/,
    );
    expect(cli).toContain('"psbt-interop-lab/musig2-scure:0.1.0"');
    expect(cli).toContain('"musig2-scure-signer-2": "musig2-signer-2"');
    expect(workflow).toContain("working-directory: adapters/musig2-scure");
    expect(workflow).toContain("npm audit --omit=dev");
    expect(workflow).toContain("node_modules/psbt-interop-lab/adapters/musig2-scure/Dockerfile");
  });

  test("pins Go vulnerability scanning in CI", () => {
    expect(readProjectFile(".github/workflows/ci.yml")).toContain(
      "go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...",
    );
  });
});
