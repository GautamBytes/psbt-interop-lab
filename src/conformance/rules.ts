export type ConformanceNormativeLevel =
  | "must"
  | "should"
  | "may"
  | "interoperability"
  | "house-policy";

export type ConformanceRuleSeverity = "stop" | "review" | "info";
export type ConformanceRuleRepairability =
  | "code-or-dependency-change"
  | "investigation-required"
  | "not-a-code-defect";
export type ConformanceRuleConfidence = "high" | "medium" | "low";

export interface ConformanceRule {
  readonly id: string;
  readonly title: string;
  readonly category: string;
  readonly normativeLevel: ConformanceNormativeLevel;
  readonly source: {
    readonly name: string;
    readonly url: string;
    readonly section: string;
  };
  readonly expected: string;
  readonly severity: ConformanceRuleSeverity;
  readonly repairability: ConformanceRuleRepairability;
  readonly confidence: ConformanceRuleConfidence;
}

const BIP174_URL = "https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki";
const BIP370_URL = "https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki";
const BIP371_URL = "https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki";
const CORE_POLICY_URL =
  "https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/testmempoolaccept/";
const LAB_POLICY_URL =
  "https://github.com/GautamBytes/psbt-interop-lab/blob/main/docs/conformance-policy.md";

function freezeRule<const Rule extends ConformanceRule>(rule: Rule): Readonly<Rule> {
  return Object.freeze({ ...rule, source: Object.freeze({ ...rule.source }) });
}

export const CONFORMANCE_RULES = Object.freeze({
  "bip174.map-keys.unique": freezeRule({
    id: "bip174.map-keys.unique",
    title: "Unique PSBT map keys",
    category: "implementation-divergence",
    normativeLevel: "must",
    source: { name: "BIP174", url: BIP174_URL, section: "Specification" },
    expected: "Every key in each PSBT map is unique.",
    severity: "review",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "bip174.unknown-keypairs.preserved": freezeRule({
    id: "bip174.unknown-keypairs.preserved",
    title: "Unknown PSBT keypair preservation",
    category: "metadata-loss",
    normativeLevel: "must",
    source: { name: "BIP174", url: BIP174_URL, section: "Key-value map" },
    expected: "Unknown and proprietary keypairs are preserved when a PSBT is reserialized.",
    severity: "stop",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "bip174.final-scriptsig.empty-omitted": freezeRule({
    id: "bip174.final-scriptsig.empty-omitted",
    title: "Empty final scriptSig omission",
    category: "implementation-divergence",
    normativeLevel: "must",
    source: { name: "BIP174", url: BIP174_URL, section: "Finalizer" },
    expected:
      "An empty final scriptSig is represented by omitting PSBT_IN_FINAL_SCRIPTSIG.",
    severity: "review",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "bip370.valid-vectors.accepted": freezeRule({
    id: "bip370.valid-vectors.accepted",
    title: "Valid PSBTv2 vectors accepted",
    category: "implementation-divergence",
    normativeLevel: "must",
    source: { name: "BIP370", url: BIP370_URL, section: "Test vectors" },
    expected:
      "PSBTv2 documents identified as valid by the official BIP370 vectors are accepted.",
    severity: "review",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "bip371.output-tap-bip32-derivation.finalization-cleanup": freezeRule({
    id: "bip371.output-tap-bip32-derivation.finalization-cleanup",
    title: "Taproot output derivation finalization cleanup",
    category: "implementation-divergence",
    normativeLevel: "should",
    source: { name: "BIP371", url: BIP371_URL, section: "Finalizer" },
    expected:
      "Taproot output derivation fields may be removed only as finalization cleanup after every input has final script data.",
    severity: "review",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "lab.transaction-intent.unchanged": freezeRule({
    id: "lab.transaction-intent.unchanged",
    title: "Transaction intent preservation",
    category: "transaction-intent-mutation",
    normativeLevel: "house-policy",
    source: { name: "PSBT Interop Lab", url: LAB_POLICY_URL, section: "Safety invariants" },
    expected: "A handoff does not change the committed unsigned transaction intent.",
    severity: "stop",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "lab.psbtv2.modifiability.valid": freezeRule({
    id: "lab.psbtv2.modifiability.valid",
    title: "PSBTv2 modifiability transition",
    category: "psbtv2-modifiability-violation",
    normativeLevel: "house-policy",
    source: { name: "PSBT Interop Lab", url: LAB_POLICY_URL, section: "Safety invariants" },
    expected:
      "PSBTv2 transaction-modifiable flags only change in ways accepted by the lab transition policy.",
    severity: "stop",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "lab.signatures.preserved": freezeRule({
    id: "lab.signatures.preserved",
    title: "Signature preservation",
    category: "signature-loss",
    normativeLevel: "house-policy",
    source: { name: "PSBT Interop Lab", url: LAB_POLICY_URL, section: "Safety invariants" },
    expected: "Existing partial and Taproot signatures are not removed by a handoff.",
    severity: "stop",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "lab.fields.preserved": freezeRule({
    id: "lab.fields.preserved",
    title: "Required field preservation",
    category: "unexpected-field-loss",
    normativeLevel: "house-policy",
    source: { name: "PSBT Interop Lab", url: LAB_POLICY_URL, section: "Safety invariants" },
    expected: "Fields required by the selected transition policy are not removed.",
    severity: "stop",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "lab.fields.immutable": freezeRule({
    id: "lab.fields.immutable",
    title: "Required field immutability",
    category: "field-mutation",
    normativeLevel: "house-policy",
    source: { name: "PSBT Interop Lab", url: LAB_POLICY_URL, section: "Safety invariants" },
    expected: "Existing fields required by the selected transition policy are not mutated.",
    severity: "stop",
    repairability: "code-or-dependency-change",
    confidence: "high",
  }),
  "lab.fields.no-unexpected-addition": freezeRule({
    id: "lab.fields.no-unexpected-addition",
    title: "Permitted field additions",
    category: "unexpected-field",
    normativeLevel: "house-policy",
    source: { name: "PSBT Interop Lab", url: LAB_POLICY_URL, section: "Safety invariants" },
    expected: "A handoff adds only fields permitted by the selected transition role.",
    severity: "review",
    repairability: "investigation-required",
    confidence: "high",
  }),
  "core.transaction.policy-accepted": freezeRule({
    id: "core.transaction.policy-accepted",
    title: "Bitcoin Core policy acceptance",
    category: "core-policy-rejection",
    normativeLevel: "interoperability",
    source: { name: "Bitcoin Core", url: CORE_POLICY_URL, section: "testmempoolaccept" },
    expected: "The extracted transaction is accepted by Bitcoin Core regtest mempool policy.",
    severity: "stop",
    repairability: "investigation-required",
    confidence: "high",
  }),
  "lab.workflow.completed": freezeRule({
    id: "lab.workflow.completed",
    title: "Interop workflow completion",
    category: "workflow-failure",
    normativeLevel: "interoperability",
    source: { name: "PSBT Interop Lab", url: LAB_POLICY_URL, section: "Operational results" },
    expected: "The selected interoperability workflow completes all required assertions.",
    severity: "review",
    repairability: "investigation-required",
    confidence: "low",
  }),
  "lab.capability.declared": freezeRule({
    id: "lab.capability.declared",
    title: "Adapter capability declaration",
    category: "capability-mismatch",
    normativeLevel: "interoperability",
    source: { name: "PSBT Interop Lab", url: LAB_POLICY_URL, section: "Operational results" },
    expected: "An adapter declares every capability required by the selected scenario.",
    severity: "info",
    repairability: "not-a-code-defect",
    confidence: "high",
  }),
  "lab.known-regression.recorded": freezeRule({
    id: "lab.known-regression.recorded",
    title: "Known regression specimen",
    category: "known-regression",
    normativeLevel: "interoperability",
    source: { name: "PSBT Interop Lab", url: LAB_POLICY_URL, section: "Operational results" },
    expected: "A historical regression specimen remains reproducible and explicitly identified.",
    severity: "info",
    repairability: "not-a-code-defect",
    confidence: "high",
  }),
} as const satisfies Record<string, ConformanceRule>);

export type ConformanceRuleId = keyof typeof CONFORMANCE_RULES;

export function getConformanceRule(id: ConformanceRuleId): ConformanceRule {
  const rule = CONFORMANCE_RULES[id];
  if (!rule) {
    throw new TypeError(`Unknown conformance rule: ${id}`);
  }
  return rule;
}
