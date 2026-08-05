import type { AdapterTemplate } from "./model.js";

const TYPESCRIPT_TEMPLATE: AdapterTemplate = {
  id: "typescript",
  displayName: "TypeScript",
  directory: new URL("../../templates/typescript/", import.meta.url),
};

const TEMPLATES = new Map<string, AdapterTemplate>([[TYPESCRIPT_TEMPLATE.id, TYPESCRIPT_TEMPLATE]]);

export function availableAdapterTemplates(): readonly string[] {
  return [...TEMPLATES.keys()].sort();
}

export function resolveAdapterTemplate(id: string): AdapterTemplate {
  const template = TEMPLATES.get(id);
  if (!template) {
    throw new TypeError(
      `Unknown adapter template ${id}; available templates: ${availableAdapterTemplates().join(", ")}`,
    );
  }
  return template;
}
