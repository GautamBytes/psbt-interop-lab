import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "vitest";
import { availableAdapterTemplates, resolveAdapterTemplate } from "../../src/scaffold/registry.js";
import { renderAdapterTemplate } from "../../src/scaffold/render.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryTemplate(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "psbt-scaffold-render-"));
  roots.push(root);
  return root;
}

function templateAt(root: string) {
  return {
    id: "typescript" as const,
    displayName: "TypeScript" as const,
    directory: pathToFileURL(`${root}/`),
  };
}

const values = {
  ADAPTER_NAME: "wallet",
  PACKAGE_NAME: "psbt-adapter-wallet",
  LAB_VERSION: "0.9.0",
};

describe("adapter template registry", () => {
  test("exposes only the built-in TypeScript template", () => {
    expect(availableAdapterTemplates()).toEqual(["typescript"]);
    expect(resolveAdapterTemplate("typescript")).toMatchObject({
      id: "typescript",
      displayName: "TypeScript",
    });
  });

  test("rejects unknown templates with the available value", () => {
    expect(() => resolveAdapterTemplate("rust")).toThrow(
      "Unknown adapter template rust; available templates: typescript",
    );
  });
});

describe("renderAdapterTemplate", () => {
  test("renders known placeholders, removes template suffixes, and sorts paths", async () => {
    const root = await temporaryTemplate();
    await mkdir(join(root, "z"));
    await writeFile(join(root, "z", "b.tmpl"), "{{ADAPTER_NAME}}\n", "utf8");
    await writeFile(
      join(root, "a.tmpl"),
      "{{PACKAGE_NAME}} {{LAB_VERSION}} {{ADAPTER_NAME}}\n",
      "utf8",
    );

    await expect(renderAdapterTemplate(templateAt(root), values)).resolves.toEqual([
      {
        path: "a",
        contents: "psbt-adapter-wallet 0.9.0 wallet\n",
      },
      { path: "z/b", contents: "wallet\n" },
    ]);
  });

  test("rejects unknown placeholders", async () => {
    const root = await temporaryTemplate();
    await writeFile(join(root, "bad.tmpl"), "{{UNKNOWN_VALUE}}\n", "utf8");

    await expect(renderAdapterTemplate(templateAt(root), values)).rejects.toThrow(
      "Unknown template placeholder UNKNOWN_VALUE",
    );
  });

  test("rejects symbolic links", async () => {
    const root = await temporaryTemplate();
    await writeFile(join(root, "target.tmpl"), "value\n", "utf8");
    await symlink(join(root, "target.tmpl"), join(root, "link.tmpl"));

    await expect(renderAdapterTemplate(templateAt(root), values)).rejects.toThrow(/symbolic link/i);
  });

  test("rejects files without the template suffix", async () => {
    const root = await temporaryTemplate();
    await writeFile(join(root, "README.md"), "value\n", "utf8");

    await expect(renderAdapterTemplate(templateAt(root), values)).rejects.toThrow(
      /must end with \.tmpl/i,
    );
  });
});
