import adapters from "../../../docs/adapters.md?raw";
import architecture from "../../../docs/architecture.md?raw";
import conformancePolicy from "../../../docs/conformance-policy.md?raw";
import futureWork from "../../../docs/future-work.md?raw";
import sources from "../../../docs/sources.md?raw";
import threatModel from "../../../psbt-interop-lab-threat-model.md?raw";
import readme from "../../../README.md?raw";
import security from "../../../SECURITY.md?raw";
import { repositoryUrl } from "../content";
import { type RoutePath, routes } from "../routes";

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
    description:
      "Connect another wallet or library to the matrix through the local JSONL contract.",
    markdown: adapters,
    sourcePath: "docs/adapters.md",
    sourceUrl: `${repositoryUrl}/blob/main/docs/adapters.md`,
    baseDir: "docs",
  },
  {
    route: routes.architecture,
    label: "Architecture",
    description:
      "Understand the orchestrator, native adapters, Core oracle, semantic checks, and report pipeline.",
    markdown: architecture,
    sourcePath: "docs/architecture.md",
    sourceUrl: `${repositoryUrl}/blob/main/docs/architecture.md`,
    baseDir: "docs",
  },
  {
    route: routes.conformancePolicy,
    label: "Conformance policy",
    description:
      "Understand stable rule IDs, normative levels, sources, and expected-versus-observed evidence.",
    markdown: conformancePolicy,
    sourcePath: "docs/conformance-policy.md",
    sourceUrl: `${repositoryUrl}/blob/main/docs/conformance-policy.md`,
    baseDir: "docs",
  },
  {
    route: routes.futureWork,
    label: "Future work",
    description:
      "See the compatibility, diagnostics, integration, and maintenance work planned beyond the current release.",
    markdown: futureWork,
    sourcePath: "docs/future-work.md",
    sourceUrl: `${repositoryUrl}/blob/main/docs/future-work.md`,
    baseDir: "docs",
  },
  {
    route: routes.sources,
    label: "Official sources",
    description:
      "Review the protocol specifications, library documentation, versions, and pinned artifacts behind the suite.",
    markdown: sources,
    sourcePath: "docs/sources.md",
    sourceUrl: `${repositoryUrl}/blob/main/docs/sources.md`,
    baseDir: "docs",
  },
  {
    route: routes.security,
    label: "Security",
    description:
      "Understand the lab's trust boundaries, protected assets, controls, and residual risks.",
    markdown: security,
    sourcePath: "SECURITY.md",
    sourceUrl: `${repositoryUrl}/blob/main/SECURITY.md`,
    baseDir: "",
  },
  {
    route: routes.threatModel,
    label: "Threat model",
    description:
      "Inspect the local runtime and CI trust boundaries, protected assets, controls, and residual risks.",
    markdown: threatModel,
    sourcePath: "psbt-interop-lab-threat-model.md",
    sourceUrl: `${repositoryUrl}/blob/main/psbt-interop-lab-threat-model.md`,
    baseDir: "",
  },
];

export function findDocument(pathname: string): WebsiteDocument | undefined {
  return documents.find((document) => document.route === pathname);
}

export function findDocumentBySourcePath(sourcePath: string): WebsiteDocument | undefined {
  return documents.find((document) => document.sourcePath === sourcePath);
}
