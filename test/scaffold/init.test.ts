import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { initializeAdapterProject } from "../../src/scaffold/init.js";
import { writeGeneratedProject } from "../../src/scaffold/write.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "psbt-scaffold-init-"));
  roots.push(root);
  return root;
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

describe("initializeAdapterProject", () => {
  test.each(["", "Wallet", "wallet_name", "wallet/name", "-wallet", "a".repeat(64)])(
    "rejects invalid adapter name %j before touching the destination",
    async (name) => {
      const root = await temporaryRoot();
      const destination = join(root, "generated");

      await expect(
        initializeAdapterProject({
          directory: destination,
          name,
          template: "typescript",
          cwd: root,
        }),
      ).rejects.toThrow("Adapter name must match ^[a-z0-9][a-z0-9-]{0,62}$");
      expect(await exists(destination)).toBe(false);
    },
  );

  test.each(["a", `a${"b".repeat(62)}`])("accepts valid boundary name %j", async (name) => {
    const root = await temporaryRoot();

    await expect(
      initializeAdapterProject({
        directory: "generated",
        name,
        template: "missing",
        cwd: root,
      }),
    ).rejects.toThrow(/Unknown adapter template missing/);
  });
});

describe("writeGeneratedProject", () => {
  test("claims an absent destination and writes sorted generated files", async () => {
    const root = await temporaryRoot();
    const destination = join(root, "generated");

    await writeGeneratedProject(destination, [
      { path: "z/value.txt", contents: "z\n" },
      { path: "name.txt", contents: "wallet\n" },
    ]);

    await expect(readFile(join(destination, "name.txt"), "utf8")).resolves.toBe("wallet\n");
    await expect(readFile(join(destination, "z/value.txt"), "utf8")).resolves.toBe("z\n");
  });

  test("refuses every kind of existing destination without changing it", async () => {
    const root = await temporaryRoot();
    const existingDirectory = join(root, "directory");
    const existingFile = join(root, "file");
    const existingLink = join(root, "link");
    await mkdir(existingDirectory);
    await writeFile(join(existingDirectory, "sentinel"), "keep\n", "utf8");
    await writeFile(existingFile, "keep\n", "utf8");
    await symlink(existingFile, existingLink);

    for (const destination of [existingDirectory, existingFile, existingLink]) {
      await expect(
        writeGeneratedProject(destination, [{ path: "new.txt", contents: "replace\n" }]),
      ).rejects.toThrow(/already exists/i);
    }

    await expect(readFile(join(existingDirectory, "sentinel"), "utf8")).resolves.toBe("keep\n");
    await expect(readFile(existingFile, "utf8")).resolves.toBe("keep\n");
  });

  test("requires an existing directory parent", async () => {
    const root = await temporaryRoot();
    const missingParent = join(root, "missing", "generated");
    const fileParent = join(root, "parent-file");
    await writeFile(fileParent, "not a directory\n", "utf8");

    await expect(
      writeGeneratedProject(missingParent, [{ path: "value.txt", contents: "value\n" }]),
    ).rejects.toThrow(/parent.*directory/i);
    await expect(
      writeGeneratedProject(join(fileParent, "generated"), [
        { path: "value.txt", contents: "value\n" },
      ]),
    ).rejects.toThrow(/parent.*directory/i);
  });

  test.each(["", "/absolute", "..", "../escape", "a/../b", "a\\b"])(
    "rejects unsafe generated path %j before claiming the destination",
    async (path) => {
      const root = await temporaryRoot();
      const destination = join(root, "generated");

      await expect(
        writeGeneratedProject(destination, [{ path, contents: "value\n" }]),
      ).rejects.toThrow(/Invalid generated file path/);
      expect(await exists(destination)).toBe(false);
    },
  );

  test("rejects duplicate generated paths before claiming the destination", async () => {
    const root = await temporaryRoot();
    const destination = join(root, "generated");

    await expect(
      writeGeneratedProject(destination, [
        { path: "value.txt", contents: "one\n" },
        { path: "value.txt", contents: "two\n" },
      ]),
    ).rejects.toThrow(/Invalid generated file path/);
    expect(await exists(destination)).toBe(false);
  });

  test("removes only its claimed destination after a mid-write failure", async () => {
    const root = await temporaryRoot();
    const destination = join(root, "generated");
    const sibling = join(root, "sibling.txt");
    await writeFile(sibling, "keep\n", "utf8");

    await expect(
      writeGeneratedProject(destination, [
        { path: "a", contents: "file\n" },
        { path: "a/b", contents: "conflict\n" },
      ]),
    ).rejects.toThrow();

    expect(await exists(destination)).toBe(false);
    await expect(readFile(sibling, "utf8")).resolves.toBe("keep\n");
  });
});
