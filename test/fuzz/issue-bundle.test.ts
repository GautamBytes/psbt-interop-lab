import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { createParserIssueBundle, writeParserIssueBundle } from "../../src/fuzz/issue-bundle.js";
import { LOCAL_PARSE_FIXTURES } from "../../src/local/fixtures.js";

const roots: string[] = [];
const IMPLEMENTATION = {
  name: "wallet-parser",
  version: "2.0.0",
  sourceRevision: "wallet-parser-v2",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function input() {
  const fixture = LOCAL_PARSE_FIXTURES[0];
  if (!fixture) throw new Error("Missing local parser fixture");
  return {
    fixture,
    runtime: "local+external",
    seed: 42,
    caseIndex: 3,
    recipes: [{ kind: "truncate" as const, byteLength: 10 }],
    outcomes: {
      lab: {
        classification: "rejected" as const,
        detail: "SECRET_RAW_DIAGNOSTIC /private/wallet/path",
      },
      wallet: {
        classification: "accepted" as const,
        detail: "COMMAND=/private/wallet-adapter ENV=SECRET_VALUE",
        facts: { psbtVersion: 0, inputs: 0, outputs: 0 },
      },
    },
    implementations: { wallet: IMPLEMENTATION },
  };
}

function sha256(contents: string): string {
  return `sha256:${createHash("sha256").update(contents, "utf8").digest("hex")}`;
}

describe("createParserIssueBundle", () => {
  test("renders deterministic committed evidence and a neutral issue draft", () => {
    const first = createParserIssueBundle(input());
    const second = createParserIssueBundle(input());

    expect(first).toEqual(second);
    expect(first.map(({ path }) => path)).toEqual([
      "issue.md",
      "manifest.json",
      "regression-suite.json",
    ]);
    const contents = Object.fromEntries(first.map((file) => [file.path, file.contents]));
    const issue = contents["issue.md"];
    const suite = contents["regression-suite.json"];
    const manifestText = contents["manifest.json"];
    if (!issue || !suite || !manifestText) throw new Error("Incomplete issue bundle");
    const manifest = JSON.parse(manifestText);

    expect(manifest).toMatchObject({
      schema: "psbt-lab.issue-bundle/0.1",
      generator: { name: "psbt-interop-lab", version: "0.10.1" },
      runtime: "local+external",
      fixture: {
        id: "bip174-minimal-v0",
        title: "Minimal unsigned PSBTv0",
        source: "BIP174 public test fixture",
        psbtVersion: 0,
      },
      seed: 42,
      caseIndex: 3,
      scenarioId: "fuzz-42-3",
      implementations: { wallet: IMPLEMENTATION },
      outcomes: {
        lab: { classification: "rejected" },
        wallet: {
          classification: "accepted",
          facts: { psbtVersion: 0, inputs: 0, outputs: 0 },
        },
      },
    });
    expect(manifest.files).toEqual({
      "issue.md": sha256(issue),
      "regression-suite.json": sha256(suite),
    });
    expect(issue).toContain("Differential parser behavior requiring investigation");
    expect(issue).toContain("has not assigned fault");
    expect(issue).toContain("psbt-interop-lab@0.10.1");
    expect(issue).toContain("--adapter-manifest adapter-manifest.json");
    expect(issue).toContain(IMPLEMENTATION.artifactDigest);
    expect(suite).toContain('"schema": "psbt-lab.suite/0.2"');

    const allOutput = first.map(({ contents: value }) => value).join("\n");
    expect(allOutput).not.toMatch(/SECRET_RAW_DIAGNOSTIC|SECRET_VALUE|COMMAND=/);
    expect(allOutput).not.toContain("/private/wallet/path");
    expect(manifestText).not.toMatch(/createdAt|timestamp/i);
  });

  test("keeps adversarial implementation metadata inside a Markdown code span", () => {
    const bundle = createParserIssueBundle({
      ...input(),
      implementations: {
        wallet: {
          ...IMPLEMENTATION,
          name: "wallet``` [forged](https://example.invalid)",
        },
      },
    });
    const issue = bundle.find(({ path }) => path === "issue.md")?.contents;

    expect(issue).toContain("```` wallet``` [forged](https://example.invalid) ````");
    expect(issue).not.toContain("wallet\\`\\`\\`");
  });
});

describe("writeParserIssueBundle", () => {
  test("claims an absent destination and refuses existing entries", async () => {
    const root = await mkdtemp(join(tmpdir(), "psbt-issue-bundle-"));
    roots.push(root);
    const destination = join(root, "bundle");

    await writeParserIssueBundle(destination, input());
    await expect(readFile(join(destination, "issue.md"), "utf8")).resolves.toContain(
      "requiring investigation",
    );

    await expect(writeParserIssueBundle(destination, input())).rejects.toThrow(/already exists/i);

    const file = join(root, "file");
    const link = join(root, "link");
    await writeFile(file, "keep\n", "utf8");
    await symlink(file, link);
    for (const existing of [file, link]) {
      await expect(writeParserIssueBundle(existing, input())).rejects.toThrow(/already exists/i);
    }
    await expect(readFile(file, "utf8")).resolves.toBe("keep\n");
    await expect(lstat(link)).resolves.toMatchObject({});
  });

  test("requires an existing real parent directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "psbt-issue-bundle-"));
    roots.push(root);
    const parentFile = join(root, "parent");
    await writeFile(parentFile, "keep\n", "utf8");

    await expect(writeParserIssueBundle(join(root, "missing", "bundle"), input())).rejects.toThrow(
      /parent.*directory/i,
    );
    await expect(writeParserIssueBundle(join(parentFile, "bundle"), input())).rejects.toThrow(
      /parent.*directory/i,
    );
    await mkdir(join(root, "unrelated"));
  });
});
