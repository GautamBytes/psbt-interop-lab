import { resolve } from "node:path";
import { VERSION } from "../version.js";
import type { AdapterInitOptions, AdapterInitResult } from "./model.js";
import { resolveAdapterTemplate } from "./registry.js";
import { renderAdapterTemplate } from "./render.js";
import { writeGeneratedProject } from "./write.js";

const ADAPTER_NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;

export async function initializeAdapterProject(
  options: AdapterInitOptions,
): Promise<AdapterInitResult> {
  if (!ADAPTER_NAME.test(options.name)) {
    throw new TypeError("Adapter name must match ^[a-z0-9][a-z0-9-]{0,62}$");
  }
  const template = resolveAdapterTemplate(options.template);
  const directory = resolve(options.cwd, options.directory);
  const files = await renderAdapterTemplate(template, {
    ADAPTER_NAME: options.name,
    PACKAGE_NAME: `psbt-adapter-${options.name}`,
    LAB_VERSION: VERSION,
  });
  await writeGeneratedProject(directory, files);
  return {
    template: template.id,
    directory,
    files: files.map(({ path }) => path),
  };
}
