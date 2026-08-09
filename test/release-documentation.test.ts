import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function read(path: string): string {
  return readFileSync(join(process.cwd(), path), "utf8");
}

describe("release documentation", () => {
  it("keeps public version references on the package version", () => {
    const packageVersion = JSON.parse(read("package.json")).version as string;
    const publicFiles = ["README.md", "src/version.ts", "website/AGENTS.md"];

    expect(packageVersion).toBe("0.9.0");
    for (const path of publicFiles) {
      expect(read(path), path).toContain(packageVersion);
    }
    expect(read("website/src/release.ts")).toContain(
      'import packageMetadata from "../../package.json"',
    );
    expect(read("website/src/release.ts")).toContain("version: packageMetadata.version");
  });

  it("records the v0.9.0 release capabilities in the packaged changelog", () => {
    const packageJson = JSON.parse(read("package.json")) as { files: string[] };
    const changelog = read("CHANGELOG.md");

    expect(packageJson.files).toContain("CHANGELOG.md");
    expect(changelog).toContain("## [0.9.0] - 2026-08-05");
    expect(changelog).toContain("TypeScript adapter project initializer");
    expect(changelog).toContain("upstream issue bundles");
    expect(changelog).toContain("compatibility history");
    expect(changelog).toContain("independent Rust and TypeScript MuSig2");
  });

  it("ships the contributor guide referenced by the packaged README", () => {
    const packageJson = JSON.parse(read("package.json")) as { files: string[] };

    expect(packageJson.files).toContain("CONTRIBUTING.md");
  });

  it("does not ship internal implementation plans or design discussions", () => {
    expect(existsSync(join(process.cwd(), "docs/superpowers/plans"))).toBe(false);
    expect(existsSync(join(process.cwd(), "docs/superpowers/specs"))).toBe(false);
  });

  it("documents neutral, replayable parser issue bundles", () => {
    const readme = read("README.md");
    const adapters = read("docs/adapters.md");
    const futureWork = read("docs/future-work.md");

    for (const document of [readme, adapters]) {
      expect(document).toContain("--issue-bundle parser-issue");
      expect(document).toContain("manifest.json");
      expect(document).toContain("regression-suite.json");
      expect(document).toContain("issue.md");
      expect(document.replace(/\s+/g, " ")).toMatch(
        /has not assigned fault|does not assign fault/i,
      );
      expect(document).toContain("public test");
    }
    expect(futureWork).not.toContain(
      "Attach promoted parser regressions to upstream-ready issue templates",
    );
  });

  it("documents ordered, replay-verified compatibility history", () => {
    const readme = read("README.md");
    const architecture = read("docs/architecture.md");
    const futureWork = read("docs/future-work.md");

    for (const document of [readme, architecture]) {
      expect(document).toContain("psbt-lab history");
      expect(document).toContain("--fail-on-regression");
      expect(document).toMatch(/oldest.to.newest/i);
      expect(document).toMatch(/replay.verif/i);
      for (const classification of ["unchanged", "regression", "improvement", "mixed", "changed"]) {
        expect(document).toContain(classification);
      }
    }
    expect(futureWork).not.toContain(
      "Publish recurring baseline comparisons as versioned regression reports",
    );
    expect(futureWork).toMatch(/scheduled|publish/i);
  });

  it("keeps every raw repository resource imported by the website in Vercel builds", () => {
    const importedResources = [
      read("website/src/pages/documents.ts"),
      read("website/src/pages/repository-resources.ts"),
    ].flatMap((source) =>
      [...source.matchAll(/from "\.\.\/\.\.\/\.\.\/([^"?]+)\?raw"/g)].flatMap((match) =>
        match[1] ? [match[1]] : [],
      ),
    );
    const includedPaths = new Set(
      read(".vercelignore")
        .split("\n")
        .filter((line) => line.startsWith("!"))
        .map((line) => line.slice(1)),
    );

    for (const path of importedResources) {
      expect(includedPaths.has(path), path).toBe(true);
    }
  });

  it("keeps package metadata imported by the website in Vercel builds", () => {
    const includedPaths = new Set(
      read(".vercelignore")
        .split("\n")
        .filter((line) => line.startsWith("!"))
        .map((line) => line.slice(1)),
    );

    expect(read("website/src/release.ts")).toContain('from "../../package.json"');
    expect(includedPaths.has("package.json")).toBe(true);
  });

  it("documents the active PSBTv2 and Taproot script-path capabilities", () => {
    const psbtv2 = read("adapters/rust-psbt-v2/README.md");
    const bdk = read("adapters/bdk-wallet-current/README.md");

    expect(psbtv2).toContain('"extract", "construct"');
    expect(psbtv2).toContain('"extractor", "constructor"');
    expect(psbtv2).toContain(
      '"scriptTypes": ["p2pkh", "p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"]',
    );
    expect(psbtv2).toContain("psbt.zero_amount_unsupported");
    expect(psbtv2.replace(/\s+/g, " ")).toContain("Taproot inspection and native roundtripping");
    expect(psbtv2).not.toContain("parser-only PSBTv2 adapter");
    expect(read("adapters/rust-psbt-v2/src/lib.rs")).not.toContain("parser-only adapter scope");
    expect(bdk).toContain("p2tr-scriptpath");
    expect(bdk).toContain("tap_leaves_options=All for p2tr-scriptpath signing");
  });

  it("states the bounded, partial Dockerless runtime honestly", () => {
    for (const path of ["README.md", "SECURITY.md", "docs/architecture.md"]) {
      const document = read(path);
      expect(document, path).toContain("Dockerless");
      expect(document, path).toMatch(/parser-only|parser checks/);
      expect(document, path).toContain("unsupported");
    }
  });

  it("distinguishes quickstart from the complete matrix", () => {
    const readme = read("README.md");
    const normalizedReadme = readme.replace(/\s+/g, " ");

    expect(normalizedReadme).toContain("bounded first-run proof");
    expect(normalizedReadme).toContain("complete 48-scenario matrix");
    expect(normalizedReadme).toContain("five semantic detector canaries");
    expect(normalizedReadme).toContain("stops the local regtest node automatically");
    expect(readme).not.toContain("focused v0.5.1 run");
  });

  it("uses public HTTPS URLs for npm README walkthrough images", () => {
    const readme = read("README.md");
    const imageSources = [...readme.matchAll(/!\[[^\]]*\]\(([^)]+)\)/g)].map((match) => match[1]);

    expect(imageSources).toHaveLength(2);
    for (const source of imageSources) {
      expect(source).toMatch(
        /^https:\/\/raw\.githubusercontent\.com\/GautamBytes\/psbt-interop-lab\/[0-9a-f]{40}\//,
      );
    }
  });

  it("pins every public walkthrough reference to one immutable revision", () => {
    const publicFiles = [
      "README.md",
      "website/index.html",
      "website/src/components/MarkdownPage.tsx",
    ];
    const revisions = publicFiles.flatMap((path) => {
      const source = read(path);
      expect(source, path).not.toContain(
        "raw.githubusercontent.com/GautamBytes/psbt-interop-lab/main/docs/assets/walkthrough/",
      );
      return [
        ...source.matchAll(
          /raw\.githubusercontent\.com\/GautamBytes\/psbt-interop-lab\/([0-9a-f]{40})\/docs\/assets\/walkthrough\//g,
        ),
      ].map((match) => match[1]);
    });

    expect(revisions.length).toBeGreaterThanOrEqual(4);
    expect(new Set(revisions)).toEqual(new Set(["d29ac0fe83ce23e54a57707dc67c4d316b2b140d"]));
  });
});
