import { createHash } from "node:crypto";
import type { AdapterImplementation } from "../protocol/types.js";
import type { GeneratedFile } from "../scaffold/model.js";
import { writeGeneratedProject } from "../scaffold/write.js";
import { VERSION } from "../version.js";
import type { ParserExpectedOutcome, ParserOutcome } from "./differential.js";
import { type DifferentialPromotionInput, promoteDifferentialCase } from "./promotion.js";

export const ISSUE_BUNDLE_SCHEMA = "psbt-lab.issue-bundle/0.1" as const;

export interface ParserIssueBundleInput extends DifferentialPromotionInput {
  readonly runtime: string;
  readonly implementations: Readonly<Record<string, AdapterImplementation>>;
}

function digest(contents: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(contents, "utf8").digest("hex")}`;
}

function sortedEntries<T>(value: Readonly<Record<string, T>>): readonly (readonly [string, T])[] {
  return Object.keys(value)
    .sort((left, right) => left.localeCompare(right))
    .map((key) => [key, value[key] as T] as const);
}

function normalizeOutcome(outcome: ParserOutcome): ParserExpectedOutcome {
  return {
    classification: outcome.classification,
    ...(outcome.facts === undefined ? {} : { facts: { ...outcome.facts } }),
  };
}

function normalizedOutcomes(
  outcomes: Readonly<Record<string, ParserOutcome>>,
): Readonly<Record<string, ParserExpectedOutcome>> {
  return Object.fromEntries(
    sortedEntries(outcomes).map(([id, outcome]) => [id, normalizeOutcome(outcome)]),
  );
}

function normalizedImplementations(
  implementations: Readonly<Record<string, AdapterImplementation>>,
): Readonly<Record<string, AdapterImplementation>> {
  return Object.fromEntries(
    sortedEntries(implementations).map(([id, implementation]) => [
      id,
      {
        name: implementation.name,
        version: implementation.version,
        ...(implementation.sourceRevision === undefined
          ? {}
          : { sourceRevision: implementation.sourceRevision }),
        artifactDigest: implementation.artifactDigest,
      },
    ]),
  );
}

function markdownCode(value: string): string {
  const normalized = value.replace(/[\r\n]+/g, " ");
  const backtickRuns = normalized.match(/`+/g) ?? [];
  if (backtickRuns.length === 0) return `\`${normalized}\``;
  const fence = "`".repeat(Math.max(...backtickRuns.map((run) => run.length)) + 1);
  return `${fence} ${normalized} ${fence}`;
}

function factSummary(outcome: ParserExpectedOutcome): string {
  if (typeof outcome === "string" || outcome.facts === undefined) return "";
  return `; facts PSBTv${outcome.facts.psbtVersion}, inputs=${outcome.facts.inputs}, outputs=${outcome.facts.outputs}`;
}

function issueMarkdown(
  input: ParserIssueBundleInput,
  outcomes: Readonly<Record<string, ParserExpectedOutcome>>,
  implementations: Readonly<Record<string, AdapterImplementation>>,
  suiteDigest: string,
): string {
  const lines = sortedEntries(outcomes).map(([id, outcome]) => {
    const normalized = typeof outcome === "string" ? { classification: outcome } : outcome;
    const implementation = implementations[id];
    const identity = implementation
      ? `; implementation ${markdownCode(implementation.name)} ${markdownCode(implementation.version)}` +
        (implementation.sourceRevision === undefined
          ? ""
          : `, revision ${markdownCode(implementation.sourceRevision)}`) +
        `, artifact ${markdownCode(implementation.artifactDigest)}`
      : "";
    return `- ${markdownCode(id)}: **${normalized.classification}**${factSummary(outcome)}${identity}`;
  });

  return [
    "# Differential parser behavior requiring investigation",
    "",
    `PSBT Interop Lab ${VERSION} found a minimized parser classification difference for ${markdownCode(input.fixture.title)}. PSBT Interop Lab has not assigned fault to any implementation; this report records reproducible evidence for maintainer investigation.`,
    "",
    "## Evidence",
    "",
    `- Public fixture: ${markdownCode(input.fixture.id)} (${markdownCode(input.fixture.source)})`,
    `- Fixture SHA256: ${markdownCode(input.fixture.sha256.startsWith("sha256:") ? input.fixture.sha256 : `sha256:${input.fixture.sha256}`)}`,
    `- Runtime: ${markdownCode(input.runtime)}`,
    `- Seed and case: ${input.seed} / ${input.caseIndex}`,
    `- Regression suite SHA256: ${markdownCode(suiteDigest)}`,
    "",
    "## Observed outcomes",
    "",
    ...lines,
    "",
    "Raw adapter diagnostics, process commands, environment variables, and local paths are intentionally excluded from this bundle.",
    "",
    "## Reproduce",
    "",
    "Use the same trusted adapter manifest that enrolls the implementation under test:",
    "",
    "```sh",
    `npx --yes psbt-interop-lab@${VERSION} parse-matrix --runtime local --adapter-manifest adapter-manifest.json --suite-manifest regression-suite.json`,
    "```",
    "",
    "The fixture is public test data. This bundle contains no wallet keys, network credentials, or production transaction intent.",
    "",
  ].join("\n");
}

export function createParserIssueBundle(input: ParserIssueBundleInput): readonly GeneratedFile[] {
  const outcomes = normalizedOutcomes(input.outcomes);
  const implementations = normalizedImplementations(input.implementations);
  const suite = promoteDifferentialCase({
    fixture: input.fixture,
    seed: input.seed,
    caseIndex: input.caseIndex,
    recipes: input.recipes,
    outcomes: Object.fromEntries(
      sortedEntries(input.outcomes).map(([id, outcome]) => [id, outcome]),
    ),
  });
  const suiteContents = `${JSON.stringify(suite, null, 2)}\n`;
  const suiteDigest = digest(suiteContents);
  const issueContents = issueMarkdown(input, outcomes, implementations, suiteDigest);
  const manifest = {
    schema: ISSUE_BUNDLE_SCHEMA,
    generator: { name: "psbt-interop-lab", version: VERSION },
    runtime: input.runtime,
    fixture: {
      id: input.fixture.id,
      title: input.fixture.title,
      source: input.fixture.source,
      psbtVersion: input.fixture.psbtVersion,
      sha256: input.fixture.sha256.startsWith("sha256:")
        ? input.fixture.sha256
        : `sha256:${input.fixture.sha256}`,
    },
    seed: input.seed,
    caseIndex: input.caseIndex,
    scenarioId: suite.scenarios[0].id,
    implementations,
    outcomes,
    files: {
      "issue.md": digest(issueContents),
      "regression-suite.json": suiteDigest,
    },
  };
  const manifestContents = `${JSON.stringify(manifest, null, 2)}\n`;

  return [
    { path: "issue.md", contents: issueContents },
    { path: "manifest.json", contents: manifestContents },
    { path: "regression-suite.json", contents: suiteContents },
  ];
}

export async function writeParserIssueBundle(
  destination: string,
  input: ParserIssueBundleInput,
): Promise<void> {
  await writeGeneratedProject(destination, createParserIssueBundle(input));
}
