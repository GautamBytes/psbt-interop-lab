import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { initializeAdapterProject } from "../../src/scaffold/init.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function generatedProject(): Promise<{
  readonly directory: string;
  readonly files: readonly string[];
}> {
  const root = await mkdtemp(join(tmpdir(), "psbt-generated-project-"));
  roots.push(root);
  const result = await initializeAdapterProject({
    directory: "wallet-adapter",
    name: "wallet-example",
    template: "typescript",
    cwd: root,
  });
  return { directory: result.directory, files: result.files };
}

describe("generated TypeScript adapter project", () => {
  test("contains the complete deterministic project tree", async () => {
    const generated = await generatedProject();
    const expectedFiles = [
      ".github/workflows/psbt-interop.yml",
      ".gitignore",
      "README.md",
      "adapter-manifest.json",
      "package-lock.json",
      "package.json",
      "src/adapter.ts",
      "test/adapter.test.mjs",
      "tsconfig.json",
    ].sort((left, right) => left.localeCompare(right));

    expect(generated.files).toEqual(expectedFiles);
    for (const file of generated.files) {
      const contents = await readFile(join(generated.directory, file), "utf8");
      expect(contents, file).not.toMatch(/\{\{[A-Z_]+\}\}/);
    }
  });

  test("renders matching project, implementation, and manifest identities", async () => {
    const generated = await generatedProject();
    const packageJson = JSON.parse(
      await readFile(join(generated.directory, "package.json"), "utf8"),
    ) as Record<string, unknown>;
    const packageLock = JSON.parse(
      await readFile(join(generated.directory, "package-lock.json"), "utf8"),
    ) as {
      name?: string;
      packages?: Record<
        string,
        { name?: string; version?: string; resolved?: string; integrity?: string }
      >;
    };
    const manifest = JSON.parse(
      await readFile(join(generated.directory, "adapter-manifest.json"), "utf8"),
    ) as {
      adapters: Array<{
        id: string;
        command: string;
        args: string[];
        expected: { name: string; version: string; sourceRevision: string };
      }>;
    };
    const adapter = await readFile(join(generated.directory, "src/adapter.ts"), "utf8");

    expect(packageJson).toMatchObject({
      name: "psbt-adapter-wallet-example",
      version: "0.1.0",
      private: true,
    });
    expect(packageLock.name).toBe("psbt-adapter-wallet-example");
    expect(packageLock.packages?.[""]?.name).toBe("psbt-adapter-wallet-example");
    expect(packageLock.packages?.["node_modules/psbt-interop-lab"]).toMatchObject({
      version: "0.10.1",
      resolved: "https://registry.npmjs.org/psbt-interop-lab/-/psbt-interop-lab-0.10.1.tgz",
    });
    expect(packageLock.packages?.["node_modules/psbt-interop-lab"]?.integrity).toBeUndefined();
    expect(manifest.adapters[0]).toEqual({
      id: "wallet-example",
      command: "node",
      args: ["dist/adapter.js"],
      cwd: ".",
      expected: {
        name: "wallet-example",
        version: "0.1.0",
        sourceRevision: "generated-typescript-template-v1",
      },
    });
    expect(adapter).toContain('name: "wallet-example"');
    expect(adapter).toContain('version: "0.1.0"');
    expect(adapter).toContain('sourceRevision: "generated-typescript-template-v1"');
    expect(adapter).toContain('artifactDigest: `sha256:${createHash("sha256")');
  });

  test("pins the generated workflow and dependencies to reviewed versions", async () => {
    const generated = await generatedProject();
    const packageJson = JSON.parse(
      await readFile(join(generated.directory, "package.json"), "utf8"),
    ) as {
      dependencies: Record<string, string>;
      devDependencies: Record<string, string>;
    };
    const workflow = await readFile(
      join(generated.directory, ".github/workflows/psbt-interop.yml"),
      "utf8",
    );
    const readme = await readFile(join(generated.directory, "README.md"), "utf8");

    expect(packageJson.dependencies).toEqual({ "bitcoinjs-lib": "7.0.1" });
    expect(packageJson.devDependencies).toEqual({
      "@types/node": "24.13.3",
      "psbt-interop-lab": "0.10.1",
      typescript: "7.0.2",
    });
    expect(workflow).toContain("actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10");
    expect(workflow).toContain(
      "GautamBytes/psbt-interop-lab@be10bae35542aa1adae605dbe1d19c662f8f540d # v0.10.1",
    );
    expect(workflow).not.toContain("GautamBytes/psbt-interop-lab@v0.10.1");
    expect(workflow).toContain("adapter-manifest: adapter-manifest.json");
    expect(readme).toContain("it cannot contain its own digest");
    expect(readme).toContain(
      "npm install --save-dev --package-lock-only --ignore-scripts psbt-interop-lab@0.10.1",
    );
  });

  test("uses a bounded streaming parser for adapter input", async () => {
    const generated = await generatedProject();
    const adapter = await readFile(join(generated.directory, "src/adapter.ts"), "utf8");

    expect(adapter).not.toContain('from "node:readline"');
    expect(adapter).toContain("discardingOversizedLine");
    expect(adapter).toContain('"protocol.line_too_large"');
  });
});
