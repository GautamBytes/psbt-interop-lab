import { readdir, readFile } from "node:fs/promises";
import { join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import type { AdapterTemplate, GeneratedFile } from "./model.js";

const TEMPLATE_SUFFIX = ".tmpl";
const PLACEHOLDER = /\{\{([A-Z_]+)\}\}/g;
const UNRESOLVED_PLACEHOLDER = /\{\{[^{}]+\}\}/;
const ALLOWED_PLACEHOLDERS = new Set(["ADAPTER_NAME", "PACKAGE_NAME", "LAB_VERSION"]);

function renderContents(contents: string, values: Readonly<Record<string, string>>): string {
  const rendered = contents.replace(PLACEHOLDER, (_match, key: string) => {
    if (!ALLOWED_PLACEHOLDERS.has(key)) {
      throw new TypeError(`Unknown template placeholder ${key}`);
    }
    const value = values[key];
    if (value === undefined) {
      throw new TypeError(`Missing template placeholder ${key}`);
    }
    return value;
  });
  const unresolved = UNRESOLVED_PLACEHOLDER.exec(rendered)?.[0];
  if (unresolved) {
    throw new TypeError(`Unresolved template placeholder ${unresolved}`);
  }
  return rendered;
}

async function collectTemplateFiles(
  directory: string,
  relativeDirectory: string,
  values: Readonly<Record<string, string>>,
  output: GeneratedFile[],
): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));

  for (const entry of entries) {
    const source = join(directory, entry.name);
    const relativeSource = relativeDirectory
      ? posix.join(relativeDirectory, entry.name)
      : entry.name;
    if (entry.isSymbolicLink()) {
      throw new TypeError(`Adapter template contains a symbolic link: ${relativeSource}`);
    }
    if (entry.isDirectory()) {
      await collectTemplateFiles(source, relativeSource, values, output);
      continue;
    }
    if (!entry.isFile()) {
      throw new TypeError(`Adapter template contains an unsupported entry: ${relativeSource}`);
    }
    if (!entry.name.endsWith(TEMPLATE_SUFFIX)) {
      throw new TypeError(`Adapter template file must end with .tmpl: ${relativeSource}`);
    }
    const path = relativeSource.slice(0, -TEMPLATE_SUFFIX.length);
    const contents = await readFile(source, "utf8");
    output.push({ path, contents: renderContents(contents, values) });
  }
}

export async function renderAdapterTemplate(
  template: AdapterTemplate,
  values: Readonly<Record<string, string>>,
): Promise<readonly GeneratedFile[]> {
  const files: GeneratedFile[] = [];
  await collectTemplateFiles(fileURLToPath(template.directory), "", values, files);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}
