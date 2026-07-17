import { copyFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const assets = [
  {
    source: "src/conformance/adapter-manifest.schema.json",
    destination: "dist/conformance/adapter-manifest.schema.json",
  },
  {
    source: "src/custom/suite-manifest.schema.json",
    destination: "dist/custom/suite-manifest.schema.json",
  },
] as const;

for (const asset of assets) {
  const destination = resolve(root, asset.destination);
  await mkdir(resolve(destination, ".."), { recursive: true });
  await copyFile(resolve(root, asset.source), destination);
}
