import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { AdapterImplementation } from "../protocol/types.js";
import type {
  ScenarioAssertionEvidence,
  ScenarioFinding,
  ScenarioOutcome,
} from "../scenarios/definition.js";
import type { RunManifest, ScenarioRecord } from "./artifacts.js";
import { verifyReplay } from "./replay.js";

export type RunComparisonChange =
  | {
      readonly kind: "run-outcome-changed";
      readonly before: RunManifest["outcome"];
      readonly after: RunManifest["outcome"];
    }
  | {
      readonly kind: "scenario-added" | "scenario-removed" | "scenario-outcome-changed";
      readonly scenarioId: string;
      readonly before?: ScenarioOutcome;
      readonly after?: ScenarioOutcome;
    }
  | {
      readonly kind: "assertion-added" | "assertion-removed" | "assertion-changed";
      readonly scenarioId: string;
      readonly assertionName: string;
      readonly before?: "passed" | "failed";
      readonly after?: "passed" | "failed";
    }
  | {
      readonly kind: "finding-added" | "finding-removed" | "finding-changed";
      readonly scenarioId: string;
      readonly findingId: string;
      readonly implementation: string;
    }
  | {
      readonly kind: "adapter-added" | "adapter-removed" | "adapter-changed";
      readonly adapter: string;
      readonly before?: string;
      readonly after?: string;
      readonly beforeSourceRevision?: string;
      readonly afterSourceRevision?: string;
      readonly beforeArtifactDigest?: string;
      readonly afterArtifactDigest?: string;
    };

export interface RunComparison {
  readonly changed: boolean;
  readonly base: {
    readonly runId: string;
    readonly outcome: RunManifest["outcome"];
    readonly verifiedCheckpoints: number;
  };
  readonly head: {
    readonly runId: string;
    readonly outcome: RunManifest["outcome"];
    readonly verifiedCheckpoints: number;
  };
  readonly summary: {
    readonly runOutcomeChanged: boolean;
    readonly scenarioChanges: number;
    readonly assertionChanges: number;
    readonly findingChanges: number;
    readonly adapterChanges: number;
  };
  readonly changes: readonly RunComparisonChange[];
}

function assertRunManifest(value: unknown): asserts value is RunManifest {
  if (
    typeof value !== "object" ||
    value === null ||
    (value as Partial<RunManifest>).schema !== "psbt-lab.run/0.1" ||
    typeof (value as Partial<RunManifest>).runId !== "string" ||
    ((value as Partial<RunManifest>).outcome !== "passed" &&
      (value as Partial<RunManifest>).outcome !== "failed") ||
    !Array.isArray((value as Partial<RunManifest>).adapters) ||
    !Array.isArray((value as Partial<RunManifest>).scenarios)
  ) {
    throw new Error("Comparison manifest does not match psbt-lab.run/0.1");
  }
}

async function loadVerifiedManifest(directory: string): Promise<{
  readonly manifest: RunManifest;
  readonly verifiedCheckpoints: number;
}> {
  const summary = await verifyReplay(directory);
  const text = await readFile(join(resolve(directory), "manifest.json"), "utf8");
  const decoded: unknown = JSON.parse(text);
  assertRunManifest(decoded);
  return { manifest: decoded, verifiedCheckpoints: summary.verifiedCheckpoints };
}

function byId<T>(values: readonly T[], id: (value: T) => string): Map<string, T> {
  return new Map(values.map((value) => [id(value), value]));
}

function assertionStatus(assertion: ScenarioAssertionEvidence): "passed" | "failed" {
  return assertion.passed && (assertion.failures?.length ?? 0) === 0 ? "passed" : "failed";
}

function findingKey(finding: ScenarioFinding): string {
  return `${finding.id}\0${finding.implementation}`;
}

function findingFingerprint(finding: ScenarioFinding): string {
  return JSON.stringify({
    id: finding.id,
    ruleId: finding.ruleId,
    implementation: finding.implementation,
    summary: finding.summary,
    actual: finding.actual,
    evidence: finding.evidence ?? [],
  });
}

function adapterFingerprint(adapter: AdapterImplementation): string {
  return JSON.stringify({
    version: adapter.version,
    sourceRevision: adapter.sourceRevision,
    artifactDigest: adapter.artifactDigest,
  });
}

interface AdapterBeforeFields {
  readonly before: string;
  readonly beforeSourceRevision?: string;
  readonly beforeArtifactDigest: string;
}

interface AdapterAfterFields {
  readonly after: string;
  readonly afterSourceRevision?: string;
  readonly afterArtifactDigest: string;
}

function adapterBeforeFields(adapter: AdapterImplementation): AdapterBeforeFields {
  return {
    before: adapter.version,
    ...(adapter.sourceRevision ? { beforeSourceRevision: adapter.sourceRevision } : {}),
    beforeArtifactDigest: adapter.artifactDigest,
  };
}

function adapterAfterFields(adapter: AdapterImplementation): AdapterAfterFields {
  return {
    after: adapter.version,
    ...(adapter.sourceRevision ? { afterSourceRevision: adapter.sourceRevision } : {}),
    afterArtifactDigest: adapter.artifactDigest,
  };
}

function compareAdapters(
  baseAdapters: readonly AdapterImplementation[],
  headAdapters: readonly AdapterImplementation[],
): RunComparisonChange[] {
  const changes: RunComparisonChange[] = [];
  const baseByName = byId(baseAdapters, (adapter) => adapter.name);
  const headByName = byId(headAdapters, (adapter) => adapter.name);
  for (const adapterName of [...new Set([...baseByName.keys(), ...headByName.keys()])].sort()) {
    const base = baseByName.get(adapterName);
    const head = headByName.get(adapterName);
    if (!base && head) {
      changes.push({
        kind: "adapter-added",
        adapter: adapterName,
        ...adapterAfterFields(head),
      });
      continue;
    }
    if (base && !head) {
      changes.push({
        kind: "adapter-removed",
        adapter: adapterName,
        ...adapterBeforeFields(base),
      });
      continue;
    }
    if (base && head && adapterFingerprint(base) !== adapterFingerprint(head)) {
      changes.push({
        kind: "adapter-changed",
        adapter: adapterName,
        ...adapterBeforeFields(base),
        ...adapterAfterFields(head),
      });
    }
  }
  return changes;
}

function compareAssertions(
  scenarioId: string,
  baseAssertions: readonly ScenarioAssertionEvidence[],
  headAssertions: readonly ScenarioAssertionEvidence[],
): RunComparisonChange[] {
  const changes: RunComparisonChange[] = [];
  const baseByName = byId(baseAssertions, (assertion) => assertion.name);
  const headByName = byId(headAssertions, (assertion) => assertion.name);
  for (const assertionName of [...new Set([...baseByName.keys(), ...headByName.keys()])].sort()) {
    const base = baseByName.get(assertionName);
    const head = headByName.get(assertionName);
    if (!base && head) {
      changes.push({
        kind: "assertion-added",
        scenarioId,
        assertionName,
        after: assertionStatus(head),
      });
      continue;
    }
    if (base && !head) {
      changes.push({
        kind: "assertion-removed",
        scenarioId,
        assertionName,
        before: assertionStatus(base),
      });
      continue;
    }
    if (base && head && assertionStatus(base) !== assertionStatus(head)) {
      changes.push({
        kind: "assertion-changed",
        scenarioId,
        assertionName,
        before: assertionStatus(base),
        after: assertionStatus(head),
      });
    }
  }
  return changes;
}

function compareFindings(
  scenarioId: string,
  baseFindings: readonly ScenarioFinding[],
  headFindings: readonly ScenarioFinding[],
): RunComparisonChange[] {
  const changes: RunComparisonChange[] = [];
  const baseByKey = byId(baseFindings, findingKey);
  const headByKey = byId(headFindings, findingKey);
  for (const key of [...new Set([...baseByKey.keys(), ...headByKey.keys()])].sort()) {
    const base = baseByKey.get(key);
    const head = headByKey.get(key);
    const finding = head ?? base;
    if (!finding) continue;
    if (!base && head) {
      changes.push({
        kind: "finding-added",
        scenarioId,
        findingId: head.id,
        implementation: head.implementation,
      });
      continue;
    }
    if (base && !head) {
      changes.push({
        kind: "finding-removed",
        scenarioId,
        findingId: base.id,
        implementation: base.implementation,
      });
      continue;
    }
    if (base && head && findingFingerprint(base) !== findingFingerprint(head)) {
      changes.push({
        kind: "finding-changed",
        scenarioId,
        findingId: finding.id,
        implementation: finding.implementation,
      });
    }
  }
  return changes;
}

function compareScenarios(
  baseScenarios: readonly ScenarioRecord[],
  headScenarios: readonly ScenarioRecord[],
): RunComparisonChange[] {
  const changes: RunComparisonChange[] = [];
  const baseById = byId(baseScenarios, (scenario) => scenario.id);
  const headById = byId(headScenarios, (scenario) => scenario.id);
  for (const scenarioId of [...new Set([...baseById.keys(), ...headById.keys()])].sort()) {
    const base = baseById.get(scenarioId);
    const head = headById.get(scenarioId);
    if (!base && head) {
      changes.push({ kind: "scenario-added", scenarioId, after: head.outcome });
      continue;
    }
    if (base && !head) {
      changes.push({ kind: "scenario-removed", scenarioId, before: base.outcome });
      continue;
    }
    if (!base || !head) continue;
    if (base.outcome !== head.outcome) {
      changes.push({
        kind: "scenario-outcome-changed",
        scenarioId,
        before: base.outcome,
        after: head.outcome,
      });
    }
    changes.push(...compareAssertions(scenarioId, base.assertions, head.assertions));
    changes.push(...compareFindings(scenarioId, base.findings ?? [], head.findings ?? []));
  }
  return changes;
}

export async function compareRuns(
  baseDirectory: string,
  headDirectory: string,
): Promise<RunComparison> {
  const [base, head] = await Promise.all([
    loadVerifiedManifest(baseDirectory),
    loadVerifiedManifest(headDirectory),
  ]);
  const changes: RunComparisonChange[] = [];
  if (base.manifest.outcome !== head.manifest.outcome) {
    changes.push({
      kind: "run-outcome-changed",
      before: base.manifest.outcome,
      after: head.manifest.outcome,
    });
  }
  changes.push(...compareAdapters(base.manifest.adapters, head.manifest.adapters));
  changes.push(...compareScenarios(base.manifest.scenarios, head.manifest.scenarios));

  const summary = {
    runOutcomeChanged: base.manifest.outcome !== head.manifest.outcome,
    scenarioChanges: changes.filter((change) => change.kind.startsWith("scenario-")).length,
    assertionChanges: changes.filter((change) => change.kind.startsWith("assertion-")).length,
    findingChanges: changes.filter((change) => change.kind.startsWith("finding-")).length,
    adapterChanges: changes.filter((change) => change.kind.startsWith("adapter-")).length,
  };
  return {
    changed: changes.length > 0,
    base: {
      runId: base.manifest.runId,
      outcome: base.manifest.outcome,
      verifiedCheckpoints: base.verifiedCheckpoints,
    },
    head: {
      runId: head.manifest.runId,
      outcome: head.manifest.outcome,
      verifiedCheckpoints: head.verifiedCheckpoints,
    },
    summary,
    changes,
  };
}
