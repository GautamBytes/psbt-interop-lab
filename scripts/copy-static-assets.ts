import { copyFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const source = resolve(root, "src/conformance/adapter-manifest.schema.json");
const destinationDirectory = resolve(root, "dist/conformance");

await mkdir(destinationDirectory, { recursive: true });
await copyFile(source, resolve(destinationDirectory, "adapter-manifest.schema.json"));
