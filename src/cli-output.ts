import { type DetectorCanaryResult, detectorCanariesPassed } from "./canaries.js";
import type { AdapterConformanceReport } from "./conformance/check.js";
import type { ReplaySummary } from "./runner/replay.js";
import type { ProofResult, ProofScenarioSummary } from "./scenarios/proof.js";

export interface DoctorCheck {
  name: string;
  ok: boolean;
  required: boolean;
  detail: string;
}

export function formatDoctorChecks(checks: DoctorCheck[]): string {
  return checks
    .map((check) => {
      const status = check.ok
        ? check.required
          ? "PASS"
          : "READY"
        : check.required
          ? "FAIL"
          : "MISS";
      return `${status}  ${check.name}: ${check.detail}`;
    })
    .join("\n");
}

export function doctorHasBlockingFailure(checks: DoctorCheck[]): boolean {
  return checks.some((check) => check.required && !check.ok);
}

export function formatCanaryResults(results: readonly DetectorCanaryResult[]): string {
  const passed = detectorCanariesPassed(results);
  return [
    `PSBT detector self-test: ${passed ? "PASSED" : "FAILED"}`,
    ...results.map(
      (result) =>
        `${result.detected ? "PASS" : "FAIL"}  ${result.id}: ${result.failureCode} at key type 0x${result.keyType.toString(16).padStart(2, "0")}`,
    ),
  ].join("\n");
}

export function formatAdapterConformance(report: AdapterConformanceReport): string {
  const lines = [`External adapter conformance: ${report.passed ? "PASSED" : "FAILED"}`];
  for (const adapter of report.adapters) {
    lines.push(`${adapter.passed ? "PASS" : "FAIL"}  ${adapter.id}`);
    for (const check of adapter.checks) {
      lines.push(`      ${check.passed ? "PASS" : "FAIL"}  ${check.name}: ${check.detail}`);
    }
  }
  return lines.join("\n");
}

function scenarioStatus(outcome: ProofResult["manifest"]["scenarios"][number]["outcome"]): string {
  switch (outcome) {
    case "passed":
      return "PASS";
    case "failed":
      return "FAIL";
    case "unsupported":
      return "UNSUP";
    case "skipped":
      return "SKIP";
  }
}

export function formatProofSummary(result: ProofResult): string {
  const findings = result.manifest.scenarios.flatMap((scenario) => scenario.findings ?? []);
  const lines = [
    `PSBT Interop Lab: ${result.manifest.outcome.toUpperCase()}${findings.length > 0 ? ` (${findings.length} ${findings.length === 1 ? "FINDING" : "FINDINGS"})` : ""}`,
    result.manifest.core
      ? `Core: ${result.manifest.core.subversion} (regtest height ${result.manifest.core.blocks}, ${result.manifest.core.connections} peers)`
      : "Core: not required by selected scenarios",
    "",
  ];
  for (const scenario of result.manifest.scenarios) {
    lines.push(`${scenarioStatus(scenario.outcome)}  ${scenario.id}`, `      ${scenario.summary}`);
    for (const finding of scenario.findings ?? []) {
      lines.push(`FIND  ${finding.id}: ${finding.implementation}`, `      ${finding.summary}`);
    }
  }
  lines.push("", `Artifacts: ${result.artifactDirectory}`);
  return lines.join("\n");
}

export function formatReplaySummary(summary: ReplaySummary): string {
  const lines = [
    `Replay verified: ${summary.runId}`,
    `Recorded outcome: ${summary.outcome.toUpperCase()}`,
    `Verified checkpoints: ${summary.verifiedCheckpoints}`,
  ];
  for (const scenario of summary.scenarios) {
    lines.push(`${scenarioStatus(scenario.outcome)}  ${scenario.id}: ${scenario.summary}`);
    for (const finding of scenario.findings ?? []) {
      lines.push(`FIND  ${finding.id}: ${finding.implementation}`, `      ${finding.summary}`);
    }
  }
  return lines.join("\n");
}

export function formatScenarioCatalog(scenarios: readonly ProofScenarioSummary[]): string {
  const categoryWidth = Math.max(
    "CATEGORY".length,
    ...scenarios.map((scenario) => scenario.category.length),
  );
  const lines = [`${"CATEGORY".padEnd(categoryWidth)}  SCENARIO`];
  for (const scenario of scenarios) {
    lines.push(
      `${scenario.category.padEnd(categoryWidth)}  ${scenario.id}`,
      `${"".padEnd(categoryWidth)}  ${scenario.title}`,
    );
  }
  return lines.join("\n");
}
