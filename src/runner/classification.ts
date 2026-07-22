import {
  type ConformanceNormativeLevel,
  type ConformanceRuleConfidence,
  type ConformanceRuleId,
  type ConformanceRuleRepairability,
  type ConformanceRuleSeverity,
  getConformanceRule,
} from "../conformance/rules.js";
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

export type ReportClassificationSeverity = ConformanceRuleSeverity;
export type ReportRepairability = ConformanceRuleRepairability;
export type ReportClassificationConfidence = ConformanceRuleConfidence;

export interface ReportClassification {
  readonly id: ReportClassificationId;
  readonly ruleId: ConformanceRuleId;
  readonly label: string;
  readonly severity: ReportClassificationSeverity;
  readonly observedAt: string;
  readonly repairability: ReportRepairability;
  readonly confidence: ReportClassificationConfidence;
  readonly normativeLevel: ConformanceNormativeLevel;
  readonly sourceName: string;
  readonly sourceUrl: string;
  readonly sourceSection: string;
  readonly expected: string;
  readonly actual: readonly string[];
  readonly summary: string;
  readonly evidence: readonly string[];
}

type ClassificationWithoutCollections = Omit<ReportClassification, "actual" | "evidence"> & {
  readonly actual: string;
};

interface GuidanceClassification {
  readonly ruleId: ConformanceRuleId;
  readonly id: ReportClassificationId;
  readonly label: string;
}

const GUIDANCE_CLASSIFICATIONS: Readonly<Record<PsbtSafeGuidanceCode, GuidanceClassification>> = {
  TRANSACTION_INTENT_CHANGED: {
    ruleId: "lab.transaction-intent.unchanged",
    id: "transaction-intent-mutation",
    label: "Transaction intent mutation",
  },
  RESTORE_TX_MODIFIABLE_FLAGS: {
    ruleId: "lab.psbtv2.modifiability.valid",
    id: "psbtv2-modifiability-violation",
    label: "PSBTv2 modifiability violation",
  },
  RESTORE_EXTENSION_METADATA: {
    ruleId: "bip174.unknown-keypairs.preserved",
    id: "metadata-loss",
    label: "Metadata loss",
  },
  RESTORE_AND_RESIGN: {
    ruleId: "lab.signatures.preserved",
    id: "signature-loss",
    label: "Signature loss",
  },
  RESTORE_REMOVED_FIELD: {
    ruleId: "lab.fields.preserved",
    id: "unexpected-field-loss",
    label: "Unexpected field loss",
  },
  REJECT_CHANGED_FIELD: {
    ruleId: "lab.fields.immutable",
    id: "field-mutation",
    label: "Unexpected field mutation",
  },
  REVIEW_UNEXPECTED_FIELD: {
    ruleId: "lab.fields.no-unexpected-addition",
    id: "unexpected-field",
    label: "Unexpected field addition",
  },
};

function fromRule(
  ruleId: ConformanceRuleId,
  values: {
    readonly observedAt: string;
    readonly summary: string;
    readonly actual: string;
    readonly id?: ReportClassificationId;
    readonly label?: string;
    readonly severity?: ReportClassificationSeverity;
    readonly confidence?: ReportClassificationConfidence;
  },
): ClassificationWithoutCollections {
  const rule = getConformanceRule(ruleId);
  return {
    id: values.id ?? (rule.category as ReportClassificationId),
    ruleId,
    label: values.label ?? rule.title,
    severity: values.severity ?? rule.severity,
    observedAt: values.observedAt,
    repairability: rule.repairability,
    confidence: values.confidence ?? rule.confidence,
    normativeLevel: rule.normativeLevel,
    sourceName: rule.source.name,
    sourceUrl: rule.source.url,
    sourceSection: rule.source.section,
    expected: rule.expected,
    actual: values.actual,
    summary: values.summary,
  };
}

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

function requireActualBehavior(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${label} must include actual behavior`);
  }
  return value;
}

function classifyFailure(
  failure: PsbtTransitionFailure,
  assertion: ScenarioAssertionEvidence,
): ClassificationWithoutCollections {
  const observedAt = assertion.likelyImplementation ?? "undetermined";
  const guidance = failure.guidance;
  if (!guidance) {
    return fromRule("lab.workflow.completed", {
      id: "workflow-failure",
      label: "Unclassified transition failure",
      severity: "review",
      observedAt,
      confidence: "low",
      summary: "The transition failed without structured safety guidance.",
      actual: `${failure.code} at ${locationLabel(failure)}.`,
    });
  }
  const classification = GUIDANCE_CLASSIFICATIONS[guidance.code];
  return fromRule(classification.ruleId, {
    id: classification.id,
    label: classification.label,
    severity: guidance.severity,
    observedAt,
    confidence: "high",
    summary: guidance.summary,
    actual: guidance.summary,
  });
}

function addClassification(
  classifications: Map<string, ReportClassification>,
  classification: ClassificationWithoutCollections,
  evidence: string,
): void {
  const key = `${classification.id}\0${classification.ruleId}\0${classification.observedAt}`;
  const existing = classifications.get(key);
  if (existing) {
    classifications.set(key, {
      ...existing,
      actual: existing.actual.includes(classification.actual)
        ? existing.actual
        : [...existing.actual, classification.actual],
      evidence: existing.evidence.includes(evidence)
        ? existing.evidence
        : [...existing.evidence, evidence],
    });
    return;
  }
  classifications.set(key, {
    ...classification,
    actual: [classification.actual],
    evidence: [evidence],
  });
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
        fromRule("lab.workflow.completed", {
          id: "workflow-failure",
          label: "Workflow failure",
          severity: "review",
          observedAt: assertion.likelyImplementation ?? "undetermined",
          confidence: assertion.likelyImplementation ? "medium" : "low",
          summary: "A workflow assertion failed without a field-level transition violation.",
          actual: assertion.summary ?? `Assertion ${assertion.name} failed.`,
        }),
        `assertion:${assertion.name}`,
      );
    }
  }

  if (scenario.policyAccepted === false) {
    addClassification(
      classifications,
      fromRule("core.transaction.policy-accepted", {
        id: "core-policy-rejection",
        label: "Bitcoin Core policy rejection",
        observedAt: "bitcoin-core",
        summary: "Bitcoin Core rejected the extracted transaction under regtest mempool policy.",
        actual: "Bitcoin Core returned allowed=false for the extracted transaction.",
      }),
      "core:testmempoolaccept",
    );
  }

  for (const missing of scenario.missingCapabilities ?? []) {
    addClassification(
      classifications,
      fromRule("lab.capability.declared", {
        id: "capability-mismatch",
        label: "Capability mismatch",
        observedAt: missing.adapter,
        summary: "The implementation did not declare a capability required by this scenario.",
        actual: `Missing ${missing.kind} capability ${String(missing.value)}.`,
      }),
      `${missing.kind}:${String(missing.value)}`,
    );
  }

  for (const finding of scenario.findings ?? []) {
    const actual = requireActualBehavior(finding.actual, `Scenario finding ${finding.id}`);
    addClassification(
      classifications,
      fromRule(finding.ruleId, {
        observedAt: finding.implementation,
        summary: finding.summary,
        actual,
      }),
      `finding:${finding.id}`,
    );
    for (const evidence of finding.evidence ?? []) {
      addClassification(
        classifications,
        fromRule(finding.ruleId, {
          observedAt: finding.implementation,
          summary: finding.summary,
          actual,
        }),
        evidence,
      );
    }
  }

  if (scenario.expectedFailure) {
    addClassification(
      classifications,
      fromRule("lab.known-regression.recorded", {
        id: "known-regression",
        label: "Known regression specimen",
        observedAt: scenario.expectedFailure.implementation,
        summary:
          "The scenario intentionally preserves a historical failure as a regression specimen.",
        actual: `The specimen returned ${scenario.expectedFailure.errorClass}.`,
      }),
      `expected-failure:${scenario.expectedFailure.errorClass}`,
    );
  }

  return [...classifications.values()];
}
