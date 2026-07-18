import type { PsbtTransitionFailure } from "../psbt/invariants.js";
import type { ScenarioAssertionEvidence, ScenarioResult } from "../scenarios/definition.js";

export type ReportClassificationId =
  | "transaction-intent-mutation"
  | "psbtv2-modifiability-violation"
  | "signature-loss"
  | "metadata-loss"
  | "required-field-loss"
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
  readonly likelyOwner: string;
  readonly repairability: ReportRepairability;
  readonly confidence: ReportClassificationConfidence;
  readonly summary: string;
  readonly evidence: readonly string[];
}

type ClassificationWithoutEvidence = Omit<ReportClassification, "evidence">;

const SIGNATURE_FIELDS = new Set([
  "PSBT_IN_PARTIAL_SIG",
  "PSBT_IN_TAP_KEY_SIG",
  "PSBT_IN_TAP_SCRIPT_SIG",
]);

function failureEvidence(failure: PsbtTransitionFailure): string {
  return `${failure.code}:${failure.field?.symbol ?? `0x${failure.keyType.toString(16).padStart(2, "0")}`}`;
}

function isMetadataField(failure: PsbtTransitionFailure): boolean {
  if (failure.field?.kind === "unknown" || failure.field?.kind === "proprietary") return true;
  const symbol = failure.field?.symbol ?? "";
  return (
    symbol.includes("BIP32_DERIVATION") || symbol.includes("PROPRIETARY") || symbol.includes("XPUB")
  );
}

function classifyFailure(
  failure: PsbtTransitionFailure,
  assertion: ScenarioAssertionEvidence,
): ClassificationWithoutEvidence {
  const likelyOwner = assertion.likelyImplementation ?? "undetermined";
  const confidence: ReportClassificationConfidence = assertion.likelyImplementation
    ? "high"
    : "medium";

  if (failure.code === "TRANSACTION_IDENTITY_CHANGED") {
    return {
      id: "transaction-intent-mutation",
      label: "Transaction intent mutation",
      severity: "stop",
      likelyOwner,
      repairability: "code-or-dependency-change",
      confidence,
      summary: "The transaction being authorized changed during a PSBT handoff.",
    };
  }
  if (failure.code === "TX_MODIFIABLE_INVALID_CHANGE") {
    return {
      id: "psbtv2-modifiability-violation",
      label: "PSBTv2 modifiability violation",
      severity: "stop",
      likelyOwner,
      repairability: "code-or-dependency-change",
      confidence,
      summary: "PSBTv2 transaction-modifiable flags changed in a direction BIP370 does not permit.",
    };
  }
  if (failure.code === "ENTRY_REMOVED" && SIGNATURE_FIELDS.has(failure.field?.symbol ?? "")) {
    return {
      id: "signature-loss",
      label: "Signature loss",
      severity: "stop",
      likelyOwner,
      repairability: "code-or-dependency-change",
      confidence,
      summary: "One or more existing signatures were removed during a handoff.",
    };
  }
  if (failure.code === "ENTRY_REMOVED" && isMetadataField(failure)) {
    return {
      id: "metadata-loss",
      label: "Metadata loss",
      severity: "stop",
      likelyOwner,
      repairability: "code-or-dependency-change",
      confidence,
      summary: "One or more PSBT metadata fields were removed during a handoff.",
    };
  }
  if (failure.code === "ENTRY_REMOVED") {
    return {
      id: "required-field-loss",
      label: "Required field loss",
      severity: "stop",
      likelyOwner,
      repairability: "code-or-dependency-change",
      confidence,
      summary: "An existing PSBT field was removed during a handoff.",
    };
  }
  if (failure.code === "ENTRY_CHANGED") {
    return {
      id: "field-mutation",
      label: "Unexpected field mutation",
      severity: "stop",
      likelyOwner,
      repairability: "code-or-dependency-change",
      confidence,
      summary: "An existing PSBT field changed unexpectedly during a handoff.",
    };
  }
  return {
    id: "unexpected-field",
    label: "Unexpected field addition",
    severity: "review",
    likelyOwner,
    repairability: "investigation-required",
    confidence,
    summary: "A PSBT field was added where the selected transition policy did not expect it.",
  };
}

function addClassification(
  classifications: Map<string, ReportClassification>,
  classification: ClassificationWithoutEvidence,
  evidence: string,
): void {
  const key = `${classification.id}\0${classification.likelyOwner}`;
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
        failureEvidence(failure),
      );
    }
    if (!assertion.passed && (assertion.failures?.length ?? 0) === 0) {
      addClassification(
        classifications,
        {
          id: "workflow-failure",
          label: "Workflow failure",
          severity: "review",
          likelyOwner: assertion.likelyImplementation ?? "undetermined",
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
        likelyOwner: "undetermined",
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
        likelyOwner: missing.adapter,
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
        likelyOwner: finding.implementation,
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
        likelyOwner: scenario.expectedFailure.implementation,
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
