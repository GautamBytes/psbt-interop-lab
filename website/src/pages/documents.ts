import readme from "../../../README.md?raw";
import adapters from "../../../docs/adapters.md?raw";
import security from "../../../SECURITY.md?raw";
import { repositoryUrl } from "../content";
import { routes, type RoutePath } from "../routes";

export interface WebsiteDocument {
  route: RoutePath;
  label: string;
  description: string;
  markdown: string;
  sourcePath: string;
  sourceUrl: string;
  baseDir: string;
}

export const documents: WebsiteDocument[] = [
  {
    route: routes.docs,
    label: "Documentation",
    description: "Install, run, extend, and understand the complete interoperability suite.",
    markdown: readme,
    sourcePath: "README.md",
    sourceUrl: `${repositoryUrl}/blob/main/README.md`,
    baseDir: "",
  },
  {
    route: routes.adapterKit,
    label: "Adapter kit",
    description: "Connect another wallet or library to the matrix through the local JSONL contract.",
    markdown: adapters,
    sourcePath: "docs/adapters.md",
    sourceUrl: `${repositoryUrl}/blob/main/docs/adapters.md`,
    baseDir: "docs",
  },
  {
    route: routes.security,
    label: "Security",
    description: "Understand the lab's trust boundaries, protected assets, controls, and residual risks.",
    markdown: security,
    sourcePath: "SECURITY.md",
    sourceUrl: `${repositoryUrl}/blob/main/SECURITY.md`,
    baseDir: "",
  },
];

export function findDocument(pathname: string): WebsiteDocument | undefined {
  return documents.find((document) => document.route === pathname);
}
