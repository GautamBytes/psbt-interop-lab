import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function read(path: string): string {
  return readFileSync(join(process.cwd(), path), "utf8");
}

describe("release documentation", () => {
  it("keeps public version references on the package version", () => {
    const packageVersion = JSON.parse(read("package.json")).version as string;
    const publicFiles = [
      "README.md",
      "src/cli.ts",
      "website/src/App.tsx",
      "website/src/content.ts",
      "website/src/components/Sections.tsx",
    ];

    expect(packageVersion).toBe("0.5.4");
    for (const path of publicFiles) {
      expect(read(path), path).toContain(packageVersion);
    }
  });

  it("documents the active PSBTv2 and Taproot script-path capabilities", () => {
    const psbtv2 = read("adapters/rust-psbt-v2/README.md");
    const bdk = read("adapters/bdk-wallet-current/README.md");

    expect(psbtv2).toContain('"sign", "combine", "finalize", "extract"');
    expect(psbtv2).toContain('"scriptTypes": ["p2wpkh", "p2wsh"]');
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
    expect(normalizedReadme).toContain("complete 31-scenario matrix");
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
});
