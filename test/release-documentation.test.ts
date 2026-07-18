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

    expect(packageVersion).toBe("0.5.1");
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
});
