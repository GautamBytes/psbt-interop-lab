import type { PsbtSafeGuidanceCode, PsbtTransitionFailure } from "../psbt/invariants.js";
import type { ScenarioAssertionEvidence, ScenarioResult } from "../scenarios/definition.js";

export type ReportClassificationId =
  | "transaction-intent-mutation"
  | "psbtv2-modifiability-violation"
  | "signature-loss"
  | "metadata-loss"
  | "unexpected-field-loss"
  | "field-mutation"
  | "unexpected-field"
  | "core-policy-rejection"
  | "workflow-failure"
  | "capability-mismatch"
  | "implementation-divergence"
  | "known-regression";

export type ReportClassificationSeverity = "stop" | "review" | "info";
export type ReportRepairability =
  | "code-or-dependency-change"
  | "investigation-required"
  | "not-a-code-defect";
export type ReportClassificationConfidence = "high" | "medium" | "low";

export interface ReportClassification {
  readonly id: ReportClassificationId;
  readonly label: string;
  readonly severity: ReportClassificationSeverity;
  readonly observedAt: string;
  readonly repairability: ReportRepairability;
  readonly confidence: ReportClassificationConfidence;
  readonly summary: string;
  readonly evidence: readonly string[];
}

type ClassificationWithoutEvidence = Omit<ReportClassification, "evidence">;

interface GuidanceClassification {
  readonly id: ReportClassificationId;
  readonly label: string;
  readonly repairability: ReportRepairability;
}

const GUIDANCE_CLASSIFICATIONS: Readonly<Record<PsbtSafeGuidanceCode, GuidanceClassification>> = {
  TRANSACTION_INTENT_CHANGED: {
    id: "transaction-intent-mutation",
    label: "Transaction intent mutation",
    repairability: "code-or-dependency-change",
  },
  RESTORE_TX_MODIFIABLE_FLAGS: {
    id: "psbtv2-modifiability-violation",
    label: "PSBTv2 modifiability violation",
    repairability: "code-or-dependency-change",
  },
  RESTORE_EXTENSION_METADATA: {
    id: "metadata-loss",
    label: "Metadata loss",
    repairability: "code-or-dependency-change",
  },
  RESTORE_AND_RESIGN: {
    id: "signature-loss",
    label: "Signature loss",
    repairability: "code-or-dependency-change",
  },
  RESTORE_REMOVED_FIELD: {
    id: "unexpected-field-loss",
    label: "Unexpected field loss",
    repairability: "code-or-dependency-change",
  },
  REJECT_CHANGED_FIELD: {
    id: "field-mutation",
    label: "Unexpected field mutation",
    repairability: "code-or-dependency-change",
  },
  REVIEW_UNEXPECTED_FIELD: {
    id: "unexpected-field",
    label: "Unexpected field addition",
    repairability: "investigation-required",
  },
};

function locationLabel(failure: PsbtTransitionFailure): string {
  return failure.location.kind === "global"
    ? "global"
    : `${failure.location.kind}[${failure.location.index}]`;
}

function failureEvidence(failure: PsbtTransitionFailure, assertionName: string): string {
  const field = failure.field?.symbol ?? "unknown";
  const keyType = failure.field?.keyTypeHex ?? `0x${failure.keyType.toString(16).padStart(2, "0")}`;
  return [
    `assertion=${assertionName}`,
    `location=${locationLabel(failure)}`,
    `failure=${failure.code}`,
    `field=${field}`,
    `keyType=${keyType}`,
    `keySha256=${failure.completeKeySha256}`,
  ].join("; ");
}

function classifyFailure(
  failure: PsbtTransitionFailure,
  assertion: ScenarioAssertionEvidence,
): ClassificationWithoutEvidence {
  const observedAt = assertion.likelyImplementation ?? "undetermined";
  const guidance = failure.guidance;
  if (!guidance) {
    return {
      id: "workflow-failure",
      label: "Unclassified transition failure",
      severity: "review",
      observedAt,
      repairability: "investigation-required",
      confidence: "low",
      summary: "The transition failed without structured safety guidance.",
    };
  }
  const classification = GUIDANCE_CLASSIFICATIONS[guidance.code];
  return {
    ...classification,
    severity: guidance.severity,
    observedAt,
    confidence: "high",
    summary: guidance.summary,
  };
}

function addClassification(
  classifications: Map<string, ReportClassification>,
  classification: ClassificationWithoutEvidence,
  evidence: string,
): void {
  const key = `${classification.id}\0${classification.observedAt}`;
  const existing = classifications.get(key);
  if (existing) {
    if (!existing.evidence.includes(evidence)) {
      classifications.set(key, { ...existing, evidence: [...existing.evidence, evidence] });
    }
    return;
  }
  classifications.set(key, { ...classification, evidence: [evidence] });
}

export function classifyScenario(scenario: ScenarioResult): readonly ReportClassification[] {
  const classifications = new Map<string, ReportClassification>();

  for (const assertion of scenario.assertions) {
    for (const failure of assertion.failures ?? []) {
      addClassification(
        classifications,
        classifyFailure(failure, assertion),
        failureEvidence(failure, assertion.name),
      );
    }
    if (!assertion.passed && (assertion.failures?.length ?? 0) === 0) {
      addClassification(
        classifications,
        {
          id: "workflow-failure",
          label: "Workflow failure",
          severity: "review",
          observedAt: assertion.likelyImplementation ?? "undetermined",
          repairability: "investigation-required",
          confidence: assertion.likelyImplementation ? "medium" : "low",
          summary: "A workflow assertion failed without a field-level transition violation.",
        },
        `assertion:${assertion.name}`,
      );
    }
  }

  if (scenario.policyAccepted === false) {
    addClassification(
      classifications,
      {
        id: "core-policy-rejection",
        label: "Bitcoin Core policy rejection",
        severity: "stop",
        observedAt: "bitcoin-core",
        repairability: "investigation-required",
        confidence: "high",
        summary: "Bitcoin Core rejected the extracted transaction under regtest mempool policy.",
      },
      "core:testmempoolaccept",
    );
  }

  for (const missing of scenario.missingCapabilities ?? []) {
    addClassification(
      classifications,
      {
        id: "capability-mismatch",
        label: "Capability mismatch",
        severity: "info",
        observedAt: missing.adapter,
        repairability: "not-a-code-defect",
        confidence: "high",
        summary: "The implementation did not declare a capability required by this scenario.",
      },
      `${missing.kind}:${String(missing.value)}`,
    );
  }

  for (const finding of scenario.findings ?? []) {
    addClassification(
      classifications,
      {
        id: "implementation-divergence",
        label: "Implementation divergence",
        severity: "review",
        observedAt: finding.implementation,
        repairability: "investigation-required",
        confidence: "medium",
        summary:
          "The implementation behaved differently from another parser or the expected interoperability boundary.",
      },
      `finding:${finding.id}`,
    );
  }

  if (scenario.expectedFailure) {
    addClassification(
      classifications,
      {
        id: "known-regression",
        label: "Known regression specimen",
        severity: "info",
        observedAt: scenario.expectedFailure.implementation,
        repairability: "not-a-code-defect",
        confidence: "high",
        summary:
          "The scenario intentionally preserves a historical failure as a regression specimen.",
      },
      `expected-failure:${scenario.expectedFailure.errorClass}`,
    );
  }

  return [...classifications.values()];
}
