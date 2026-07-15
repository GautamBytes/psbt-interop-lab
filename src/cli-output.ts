import type { ReplaySummary } from "./runner/replay.js";
import type { ProofResult } from "./scenarios/proof.js";

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

export function formatProofSummary(result: ProofResult): string {
  const lines = [
    `PSBT Interop Lab: ${result.manifest.outcome.toUpperCase()}`,
    `Core: ${result.manifest.core.subversion} (regtest height ${result.manifest.core.blocks}, ${result.manifest.core.connections} peers)`,
    "",
  ];
  for (const scenario of result.manifest.scenarios) {
    lines.push(
      `${scenario.outcome === "passed" ? "PASS" : "FAIL"}  ${scenario.id}`,
      `      ${scenario.summary}`,
    );
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
    lines.push(
      `${scenario.outcome === "passed" ? "PASS" : "FAIL"}  ${scenario.id}: ${scenario.summary}`,
    );
  }
  return lines.join("\n");
}
