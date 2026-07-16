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
  });

  test("pins Go vulnerability scanning in CI", () => {
    expect(readProjectFile(".github/workflows/ci.yml")).toContain(
      "go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...",
    );
  });
});
