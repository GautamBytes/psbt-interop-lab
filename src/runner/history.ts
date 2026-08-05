import { compareRuns, type RunComparisonChange } from "./compare.js";

export const COMPATIBILITY_HISTORY_SCHEMA = "psbt-lab.compatibility-history/0.1" as const;
const MIN_HISTORY_RUNS = 2;
const MAX_HISTORY_RUNS = 64;

export type CompatibilitySignalDirection = "regression" | "improvement" | "neutral";

export type CompatibilityTransitionClassification =
  | "unchanged"
  | "regression"
  | "improvement"
  | "mixed"
  | "changed";

export interface CompatibilityHistoryRun {
  readonly runId: string;
  readonly completedAt: string;
  readonly outcome: "passed" | "failed";
  readonly verifiedCheckpoints: number;
}

export interface DirectedCompatibilityChange {
  readonly direction: CompatibilitySignalDirection;
  readonly change: RunComparisonChange;
}

export interface CompatibilityHistoryTransition {
  readonly baseRunId: string;
  readonly headRunId: string;
  readonly classification: CompatibilityTransitionClassification;
  readonly signals: {
    readonly regressions: number;
    readonly improvements: number;
    readonly neutral: number;
  };
  readonly changes: readonly DirectedCompatibilityChange[];
}

export interface CompatibilityHistoryReport {
  readonly schema: typeof COMPATIBILITY_HISTORY_SCHEMA;
  readonly runs: readonly CompatibilityHistoryRun[];
  readonly transitions: readonly CompatibilityHistoryTransition[];
  readonly summary: {
    readonly runs: number;
    readonly transitions: number;
    readonly unchanged: number;
    readonly regressions: number;
    readonly improvements: number;
    readonly mixed: number;
    readonly changed: number;
  };
}

function scenarioDirection(
  before: "passed" | "failed" | "unsupported" | "skipped" | undefined,
  after: "passed" | "failed" | "unsupported" | "skipped" | undefined,
): CompatibilitySignalDirection {
  if (before === "passed" && (after === "failed" || after === "unsupported")) {
    return "regression";
  }
  if ((before === "failed" || before === "unsupported") && after === "passed") {
    return "improvement";
  }
  return "neutral";
}

export function classifyCompatibilityChange(
  change: RunComparisonChange,
): CompatibilitySignalDirection {
  switch (change.kind) {
    case "run-outcome-changed":
      return change.before === "passed" ? "regression" : "improvement";
    case "scenario-outcome-changed":
      return scenarioDirection(change.before, change.after);
    case "assertion-changed":
      if (change.before === "passed" && change.after === "failed") return "regression";
      if (change.before === "failed" && change.after === "passed") return "improvement";
      return "neutral";
    case "finding-added":
      return "regression";
    case "finding-removed":
      return "improvement";
    case "scenario-added":
    case "scenario-removed":
    case "assertion-added":
    case "assertion-removed":
    case "finding-changed":
    case "adapter-added":
    case "adapter-removed":
    case "adapter-changed":
    case "adapter-capabilities-changed":
    case "checkpoint-added":
    case "checkpoint-removed":
    case "checkpoint-facts-changed":
      return "neutral";
  }
}

function transitionClassification(signals: {
  readonly regressions: number;
  readonly improvements: number;
  readonly neutral: number;
}): CompatibilityTransitionClassification {
  if (signals.regressions > 0 && signals.improvements > 0) return "mixed";
  if (signals.regressions > 0) return "regression";
  if (signals.improvements > 0) return "improvement";
  if (signals.neutral > 0) return "changed";
  return "unchanged";
}

function validateRun(run: CompatibilityHistoryRun): number {
  const completedAt = Date.parse(run.completedAt);
  if (!Number.isFinite(completedAt) || new Date(completedAt).toISOString() !== run.completedAt) {
    throw new TypeError(`Run ${run.runId} completedAt must be an ISO timestamp`);
  }
  return completedAt;
}

function sameRun(left: CompatibilityHistoryRun, right: CompatibilityHistoryRun): boolean {
  return (
    left.runId === right.runId &&
    left.completedAt === right.completedAt &&
    left.outcome === right.outcome &&
    left.verifiedCheckpoints === right.verifiedCheckpoints
  );
}

export async function buildCompatibilityHistory(
  directories: readonly string[],
): Promise<CompatibilityHistoryReport> {
  if (directories.length < MIN_HISTORY_RUNS || directories.length > MAX_HISTORY_RUNS) {
    throw new RangeError(
      `Compatibility history requires between ${MIN_HISTORY_RUNS} and ${MAX_HISTORY_RUNS} artifact directories`,
    );
  }

  const runs: CompatibilityHistoryRun[] = [];
  const transitions: CompatibilityHistoryTransition[] = [];
  const runIds = new Set<string>();
  let previousCompletedAt: number | undefined;

  for (let index = 0; index < directories.length - 1; index += 1) {
    const baseDirectory = directories[index];
    const headDirectory = directories[index + 1];
    if (baseDirectory === undefined || headDirectory === undefined) {
      throw new Error("Compatibility history directory sequence is incomplete");
    }
    const comparison = await compareRuns(baseDirectory, headDirectory);
    const base: CompatibilityHistoryRun = { ...comparison.base };
    const head: CompatibilityHistoryRun = { ...comparison.head };

    if (index === 0) {
      previousCompletedAt = validateRun(base);
      runIds.add(base.runId);
      runs.push(base);
    } else {
      const previous = runs[runs.length - 1];
      if (previous === undefined || !sameRun(previous, base)) {
        throw new Error("Compatibility history artifact changed while it was being compared");
      }
    }

    const completedAt = validateRun(head);
    if (runIds.has(head.runId)) {
      throw new TypeError(`Compatibility history contains duplicate run id ${head.runId}`);
    }
    if (previousCompletedAt !== undefined && completedAt < previousCompletedAt) {
      throw new TypeError("Compatibility history runs must be provided oldest-to-newest");
    }
    previousCompletedAt = completedAt;
    runIds.add(head.runId);
    runs.push(head);

    const changes = comparison.changes.map((change) => ({
      direction: classifyCompatibilityChange(change),
      change,
    }));
    const signals = {
      regressions: changes.filter(({ direction }) => direction === "regression").length,
      improvements: changes.filter(({ direction }) => direction === "improvement").length,
      neutral: changes.filter(({ direction }) => direction === "neutral").length,
    };
    transitions.push({
      baseRunId: base.runId,
      headRunId: head.runId,
      classification: transitionClassification(signals),
      signals,
      changes,
    });
  }

  return {
    schema: COMPATIBILITY_HISTORY_SCHEMA,
    runs,
    transitions,
    summary: {
      runs: runs.length,
      transitions: transitions.length,
      unchanged: transitions.filter(({ classification }) => classification === "unchanged").length,
      regressions: transitions.filter(({ classification }) => classification === "regression")
        .length,
      improvements: transitions.filter(({ classification }) => classification === "improvement")
        .length,
      mixed: transitions.filter(({ classification }) => classification === "mixed").length,
      changed: transitions.filter(({ classification }) => classification === "changed").length,
    },
  };
}

export function historyHasLatestRegression(report: CompatibilityHistoryReport): boolean {
  const latest = report.transitions[report.transitions.length - 1];
  return latest?.classification === "regression" || latest?.classification === "mixed";
}
