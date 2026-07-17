import adapterManifestSchema from "../../../src/conformance/adapter-manifest.schema.json?raw";
import customSuiteExample from "../../../examples/custom-suite.json?raw";
import customSuiteSchema from "../../../src/custom/suite-manifest.schema.json?raw";
import { repositoryUrl } from "../content";

export interface RepositoryResource {
  route: string;
  label: string;
  description: string;
  sourcePath: string;
  sourceUrl: string;
  kind: "file" | "directory";
  language?: string;
  content?: string;
  entries?: string[];
}

export const repositoryResources: RepositoryResource[] = [
  {
    route: "/files/src/conformance/adapter-manifest.schema.json",
    label: "Adapter manifest schema",
    description: "The exact JSON Schema used to validate third-party adapter manifests before execution.",
    sourcePath: "src/conformance/adapter-manifest.schema.json",
    sourceUrl: `${repositoryUrl}/blob/main/src/conformance/adapter-manifest.schema.json`,
    kind: "file",
    language: "json",
    content: adapterManifestSchema,
  },
  {
    route: "/files/src/custom/suite-manifest.schema.json",
    label: "Custom suite schema",
    description: "The fixture and scenario contract accepted by custom interoperability suites.",
    sourcePath: "src/custom/suite-manifest.schema.json",
    sourceUrl: `${repositoryUrl}/blob/main/src/custom/suite-manifest.schema.json`,
    kind: "file",
    language: "json",
    content: customSuiteSchema,
  },
  {
    route: "/files/examples/custom-suite.json",
    label: "Custom suite example",
    description: "A complete custom fixture and multi-adapter roundtrip that can be used as a starting point.",
    sourcePath: "examples/custom-suite.json",
    sourceUrl: `${repositoryUrl}/blob/main/examples/custom-suite.json`,
    kind: "file",
    language: "json",
    content: customSuiteExample,
  },
  {
    route: "/files/website",
    label: "Website source",
    description: "The standalone Vite application that renders this project website and mirrors repository documentation.",
    sourcePath: "website/",
    sourceUrl: `${repositoryUrl}/tree/main/website`,
    kind: "directory",
    entries: [
      "website/src/",
      "website/public/",
      "website/package.json",
      "website/vite.config.ts",
      "website/tsconfig.json",
      "website/design-qa.md",
    ],
  },
];

export function findRepositoryResource(pathname: string): RepositoryResource | undefined {
  return repositoryResources.find((resource) => resource.route === pathname);
}

export function findRepositoryResourceBySourcePath(sourcePath: string): RepositoryResource | undefined {
  const normalized = sourcePath.replace(/\/+$/, "");
  return repositoryResources.find((resource) => resource.sourcePath.replace(/\/+$/, "") === normalized);
}
