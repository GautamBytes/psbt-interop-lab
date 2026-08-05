import type { AdapterHelloCapabilities } from "../protocol/types.js";
import type { PsbtWireFacts } from "../psbt/wire-facts.js";
import type {
  ScenarioAssertionEvidence,
  ScenarioFinding,
  ScenarioOutcome,
} from "../scenarios/definition.js";
import type {
  CheckpointRecord,
  RunAdapterRecord,
  RunManifest,
  ScenarioRecord,
} from "./artifacts.js";
import { loadVerifiedReplay, type VerifiedReplay } from "./replay.js";

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
    }
  | {
      readonly kind: "adapter-capabilities-changed";
      readonly adapter: string;
      readonly before?: AdapterHelloCapabilities;
      readonly after?: AdapterHelloCapabilities;
    }
  | {
      readonly kind: "checkpoint-added" | "checkpoint-removed" | "checkpoint-facts-changed";
      readonly scenarioId: string;
      readonly stage: string;
      readonly beforeSha256?: string;
      readonly afterSha256?: string;
      readonly beforeFacts?: PsbtWireFacts;
      readonly afterFacts?: PsbtWireFacts;
    };

export interface RunComparison {
  readonly changed: boolean;
  readonly base: {
    readonly runId: string;
    readonly completedAt: string;
    readonly outcome: RunManifest["outcome"];
    readonly verifiedCheckpoints: number;
  };
  readonly head: {
    readonly runId: string;
    readonly completedAt: string;
    readonly outcome: RunManifest["outcome"];
    readonly verifiedCheckpoints: number;
  };
  readonly summary: {
    readonly runOutcomeChanged: boolean;
    readonly scenarioChanges: number;
    readonly assertionChanges: number;
    readonly findingChanges: number;
    readonly adapterChanges: number;
    readonly capabilityChanges: number;
    readonly checkpointChanges: number;
  };
  readonly changes: readonly RunComparisonChange[];
}

function assertRunManifest(value: unknown): asserts value is RunManifest {
  if (
    typeof value !== "object" ||
    value === null ||
    (value as Partial<RunManifest>).schema !== "psbt-lab.run/0.1" ||
    typeof (value as Partial<RunManifest>).runId !== "string" ||
    typeof (value as Partial<RunManifest>).completedAt !== "string" ||
    ((value as Partial<RunManifest>).outcome !== "passed" &&
      (value as Partial<RunManifest>).outcome !== "failed") ||
    !Array.isArray((value as Partial<RunManifest>).adapters) ||
    !Array.isArray((value as Partial<RunManifest>).scenarios) ||
    !Array.isArray((value as Partial<RunManifest>).checkpoints)
  ) {
    throw new Error("Comparison manifest does not match psbt-lab.run/0.1");
  }
}

async function loadVerifiedManifest(directory: string): Promise<{
  readonly manifest: RunManifest;
  readonly verifiedCheckpoints: number;
}> {
  const verified = await loadVerifiedReplay(directory);
  assertRunManifest(verified.manifest);
  return verified;
}

function byId<T>(values: readonly T[], id: (value: T) => string): Map<string, T> {
  return new Map(values.map((value) => [id(value), value]));
}

function assertionStatus(assertion: ScenarioAssertionEvidence): "passed" | "failed" {
  return assertion.passed && (assertion.failures?.length ?? 0) === 0 ? "passed" : "failed";
}

function assertionFingerprint(assertion: ScenarioAssertionEvidence): string {
  return JSON.stringify({
    passed: assertion.passed,
    policy: assertion.policy,
    exactBytesEqual: assertion.exactBytesEqual,
    failures: assertion.failures ?? [],
    likelyImplementation: assertion.likelyImplementation,
    summary: assertion.summary,
  });
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

function adapterFingerprint(adapter: RunAdapterRecord): string {
  return JSON.stringify({
    version: adapter.version,
    sourceRevision: adapter.sourceRevision,
    artifactDigest: adapter.artifactDigest,
  });
}

function sorted<T extends string | number>(values: readonly T[] | undefined): T[] {
  return [...(values ?? [])].sort((left, right) => {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
  });
}

function normalizedCapabilities(
  capabilities: AdapterHelloCapabilities | undefined,
): AdapterHelloCapabilities | undefined {
  if (capabilities === undefined) return undefined;
  const operationScriptTypeEntries = Object.entries(capabilities.operationScriptTypes ?? {});
  const normalized: AdapterHelloCapabilities = {
    operations: sorted(capabilities.operations),
    roles: sorted(capabilities.roles),
    psbtVersions: sorted(capabilities.psbtVersions),
    scriptTypes: sorted(capabilities.scriptTypes),
  };
  if (operationScriptTypeEntries.length > 0) {
    normalized.operationScriptTypes = Object.fromEntries(
      operationScriptTypeEntries
        .sort(([left], [right]) => {
          if (left < right) return -1;
          if (left > right) return 1;
          return 0;
        })
        .map(([operation, scriptTypes]) => [operation, sorted(scriptTypes)]),
    ) as NonNullable<AdapterHelloCapabilities["operationScriptTypes"]>;
  }
  if (capabilities.features !== undefined) {
    normalized.features = sorted(capabilities.features);
  }
  return normalized;
}

function capabilitiesFingerprint(adapter: RunAdapterRecord): string | undefined {
  const normalized = normalizedCapabilities(adapter.capabilities);
  return normalized === undefined ? undefined : JSON.stringify(normalized);
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

function adapterBeforeFields(adapter: RunAdapterRecord): AdapterBeforeFields {
  return {
    before: adapter.version,
    ...(adapter.sourceRevision ? { beforeSourceRevision: adapter.sourceRevision } : {}),
    beforeArtifactDigest: adapter.artifactDigest,
  };
}

function adapterAfterFields(adapter: RunAdapterRecord): AdapterAfterFields {
  return {
    after: adapter.version,
    ...(adapter.sourceRevision ? { afterSourceRevision: adapter.sourceRevision } : {}),
    afterArtifactDigest: adapter.artifactDigest,
  };
}

function compareAdapters(
  baseAdapters: readonly RunAdapterRecord[],
  headAdapters: readonly RunAdapterRecord[],
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
    if (base && head && capabilitiesFingerprint(base) !== capabilitiesFingerprint(head)) {
      const before = normalizedCapabilities(base.capabilities);
      const after = normalizedCapabilities(head.capabilities);
      changes.push({
        kind: "adapter-capabilities-changed",
        adapter: adapterName,
        ...(before === undefined ? {} : { before }),
        ...(after === undefined ? {} : { after }),
      });
    }
  }
  return changes;
}

interface IndexedCheckpoint {
  readonly checkpoint: CheckpointRecord;
}

function checkpointBaseKey(checkpoint: CheckpointRecord): string {
  return `${checkpoint.scenario}\0${checkpoint.stage}`;
}

function indexCheckpoints(
  checkpoints: readonly CheckpointRecord[],
): Map<string, IndexedCheckpoint> {
  const seen = new Map<string, number>();
  return new Map(
    checkpoints.map((checkpoint) => {
      const baseKey = checkpointBaseKey(checkpoint);
      const occurrence = seen.get(baseKey) ?? 0;
      seen.set(baseKey, occurrence + 1);
      const key = `${baseKey}\0${occurrence}`;
      return [key, { checkpoint }];
    }),
  );
}

function checkpointFingerprint(checkpoint: CheckpointRecord): string {
  if (checkpoint.comparison !== "structure") {
    return JSON.stringify({ comparison: "exact", facts: checkpoint.facts });
  }
  const { sha256: _sha256, ...structure } = checkpoint.facts;
  return JSON.stringify({ comparison: "structure", facts: structure });
}

function checkpointChangeFields(checkpoint: CheckpointRecord): {
  readonly scenarioId: string;
  readonly stage: string;
} {
  return {
    scenarioId: checkpoint.scenario,
    stage: checkpoint.stage,
  };
}

function compareCheckpoints(
  baseCheckpoints: readonly CheckpointRecord[],
  headCheckpoints: readonly CheckpointRecord[],
): RunComparisonChange[] {
  const changes: RunComparisonChange[] = [];
  const baseByKey = indexCheckpoints(baseCheckpoints);
  const headByKey = indexCheckpoints(headCheckpoints);
  for (const key of [...new Set([...baseByKey.keys(), ...headByKey.keys()])].sort()) {
    const base = baseByKey.get(key)?.checkpoint;
    const head = headByKey.get(key)?.checkpoint;
    const checkpoint = head ?? base;
    if (!checkpoint) continue;
    if (!base && head) {
      changes.push({
        kind: "checkpoint-added",
        ...checkpointChangeFields(head),
        afterSha256: head.facts.sha256,
        afterFacts: head.facts,
      });
      continue;
    }
    if (base && !head) {
      changes.push({
        kind: "checkpoint-removed",
        ...checkpointChangeFields(base),
        beforeSha256: base.facts.sha256,
        beforeFacts: base.facts,
      });
      continue;
    }
    if (base && head && checkpointFingerprint(base) !== checkpointFingerprint(head)) {
      changes.push({
        kind: "checkpoint-facts-changed",
        ...checkpointChangeFields(checkpoint),
        beforeSha256: base.facts.sha256,
        afterSha256: head.facts.sha256,
        beforeFacts: base.facts,
        afterFacts: head.facts,
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
    if (base && head && assertionFingerprint(base) !== assertionFingerprint(head)) {
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

export function compareVerifiedReplays(base: VerifiedReplay, head: VerifiedReplay): RunComparison {
  assertRunManifest(base.manifest);
  assertRunManifest(head.manifest);
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
  changes.push(...compareCheckpoints(base.manifest.checkpoints, head.manifest.checkpoints));

  const summary = {
    runOutcomeChanged: base.manifest.outcome !== head.manifest.outcome,
    scenarioChanges: changes.filter((change) => change.kind.startsWith("scenario-")).length,
    assertionChanges: changes.filter((change) => change.kind.startsWith("assertion-")).length,
    findingChanges: changes.filter((change) => change.kind.startsWith("finding-")).length,
    adapterChanges: changes.filter(
      (change) =>
        change.kind === "adapter-added" ||
        change.kind === "adapter-removed" ||
        change.kind === "adapter-changed",
    ).length,
    capabilityChanges: changes.filter((change) => change.kind === "adapter-capabilities-changed")
      .length,
    checkpointChanges: changes.filter((change) => change.kind.startsWith("checkpoint-")).length,
  };
  return {
    changed: changes.length > 0,
    base: {
      runId: base.manifest.runId,
      completedAt: base.manifest.completedAt,
      outcome: base.manifest.outcome,
      verifiedCheckpoints: base.verifiedCheckpoints,
    },
    head: {
      runId: head.manifest.runId,
      completedAt: head.manifest.completedAt,
      outcome: head.manifest.outcome,
      verifiedCheckpoints: head.verifiedCheckpoints,
    },
    summary,
    changes,
  };
}

export async function compareRuns(
  baseDirectory: string,
  headDirectory: string,
): Promise<RunComparison> {
  const [base, head] = await Promise.all([
    loadVerifiedManifest(baseDirectory),
    loadVerifiedManifest(headDirectory),
  ]);
  return compareVerifiedReplays(base, head);
}
