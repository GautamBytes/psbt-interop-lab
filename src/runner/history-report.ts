import type { GeneratedFile } from "../scaffold/model.js";
import { writeGeneratedProject } from "../scaffold/write.js";
import type { RunComparisonChange } from "./compare.js";
import type { CompatibilityHistoryReport, CompatibilitySignalDirection } from "./history.js";

function markdownCode(value: string | number | undefined): string {
  const normalized = String(value ?? "unknown").replace(/[\r\n]+/g, " ");
  const backtickRuns = normalized.match(/`+/g) ?? [];
  if (backtickRuns.length === 0) return `\`${normalized}\``;
  const fence = "`".repeat(Math.max(...backtickRuns.map((run) => run.length)) + 1);
  return `${fence} ${normalized} ${fence}`;
}

function shortSha256(value: string | undefined): string {
  return value === undefined ? "unknown" : value.slice(0, 19);
}

function describeChange(change: RunComparisonChange): string {
  switch (change.kind) {
    case "run-outcome-changed":
      return `run outcome ${markdownCode(change.before)} -> ${markdownCode(change.after)}`;
    case "scenario-added":
      return `scenario ${markdownCode(change.scenarioId)} added as ${markdownCode(change.after)}`;
    case "scenario-removed":
      return `scenario ${markdownCode(change.scenarioId)} removed from ${markdownCode(change.before)}`;
    case "scenario-outcome-changed":
      return `scenario ${markdownCode(change.scenarioId)} ${markdownCode(change.before)} -> ${markdownCode(change.after)}`;
    case "assertion-added":
      return `assertion ${markdownCode(change.scenarioId)}/${markdownCode(change.assertionName)} added as ${markdownCode(change.after)}`;
    case "assertion-removed":
      return `assertion ${markdownCode(change.scenarioId)}/${markdownCode(change.assertionName)} removed from ${markdownCode(change.before)}`;
    case "assertion-changed":
      return `assertion ${markdownCode(change.scenarioId)}/${markdownCode(change.assertionName)} ${markdownCode(change.before)} -> ${markdownCode(change.after)}`;
    case "finding-added":
      return `finding ${markdownCode(change.scenarioId)}/${markdownCode(change.findingId)} added for ${markdownCode(change.implementation)}`;
    case "finding-removed":
      return `finding ${markdownCode(change.scenarioId)}/${markdownCode(change.findingId)} removed for ${markdownCode(change.implementation)}`;
    case "finding-changed":
      return `finding ${markdownCode(change.scenarioId)}/${markdownCode(change.findingId)} changed for ${markdownCode(change.implementation)}`;
    case "adapter-added":
      return `adapter ${markdownCode(change.adapter)} added at ${markdownCode(change.after)}`;
    case "adapter-removed":
      return `adapter ${markdownCode(change.adapter)} removed from ${markdownCode(change.before)}`;
    case "adapter-changed":
      return `adapter ${markdownCode(change.adapter)} ${markdownCode(change.before)} -> ${markdownCode(change.after)}`;
    case "adapter-capabilities-changed":
      return `adapter ${markdownCode(change.adapter)} capabilities changed`;
    case "checkpoint-added":
      return `checkpoint ${markdownCode(change.scenarioId)}/${markdownCode(change.stage)} added at ${markdownCode(shortSha256(change.afterSha256))}`;
    case "checkpoint-removed":
      return `checkpoint ${markdownCode(change.scenarioId)}/${markdownCode(change.stage)} removed from ${markdownCode(shortSha256(change.beforeSha256))}`;
    case "checkpoint-facts-changed":
      return `checkpoint ${markdownCode(change.scenarioId)}/${markdownCode(change.stage)} ${markdownCode(shortSha256(change.beforeSha256))} -> ${markdownCode(shortSha256(change.afterSha256))}`;
  }
}

function directionLabel(direction: CompatibilitySignalDirection): string {
  return direction === "neutral" ? "NEUTRAL" : direction.toUpperCase();
}

export function formatCompatibilityHistory(report: CompatibilityHistoryReport): string {
  const lines = [
    "# PSBT Compatibility History",
    "",
    `Schema: ${markdownCode(report.schema)}`,
    "",
    `Summary: runs=${report.summary.runs} transitions=${report.summary.transitions} regressions=${report.summary.regressions} improvements=${report.summary.improvements} mixed=${report.summary.mixed} changed=${report.summary.changed} unchanged=${report.summary.unchanged}`,
    "",
    "## Runs",
    "",
    ...report.runs.map(
      (run) =>
        `- ${markdownCode(run.runId)} completed ${markdownCode(run.completedAt)}: **${run.outcome.toUpperCase()}** (${run.verifiedCheckpoints} verified checkpoints)`,
    ),
    "",
    "## Transitions",
    "",
  ];

  for (const transition of report.transitions) {
    lines.push(
      `### ${markdownCode(transition.baseRunId)} -> ${markdownCode(transition.headRunId)}: ${transition.classification.toUpperCase()}`,
      "",
      `Signals: regressions=${transition.signals.regressions} improvements=${transition.signals.improvements} neutral=${transition.signals.neutral}`,
      "",
    );
    if (transition.changes.length === 0) {
      lines.push("No recorded compatibility changes.", "");
      continue;
    }
    lines.push(
      ...transition.changes.map(
        ({ direction, change }) => `- **${directionLabel(direction)}** ${describeChange(change)}`,
      ),
      "",
    );
  }

  return lines.join("\n");
}

export function createCompatibilityHistoryBundle(
  report: CompatibilityHistoryReport,
): readonly GeneratedFile[] {
  return [
    { path: "history.json", contents: `${JSON.stringify(report, null, 2)}\n` },
    { path: "history.md", contents: formatCompatibilityHistory(report) },
  ];
}

export async function writeCompatibilityHistoryBundle(
  destination: string,
  report: CompatibilityHistoryReport,
): Promise<void> {
  await writeGeneratedProject(destination, createCompatibilityHistoryBundle(report));
}
