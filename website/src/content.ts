import { publicConformanceRules } from "./generated/conformance-rules";

export const repositoryUrl = "https://github.com/GautamBytes/psbt-interop-lab";
export const npmUrl = "https://www.npmjs.com/package/psbt-interop-lab";
export const installCommand = "npx --yes psbt-interop-lab@0.7.0 quickstart";

export type ScenarioStatus = "pass" | "finding" | "supported";

export interface EvidenceRow {
  field: string;
  expected: string;
  actual: string;
  implementation: string;
  nextStep: string;
}

export interface ReportClassification {
  ruleId: keyof typeof publicConformanceRules;
  observedAt: string;
  evidence: string;
  actual: string;
}

export interface ReportScenario {
  id: string;
  shortLabel: string;
  title: string;
  status: ScenarioStatus;
  statusLabel: string;
  handoff: string;
  summary: string;
  implementations: readonly string[];
  evidence: EvidenceRow[];
  classification?: ReportClassification;
  replay: string;
}

export const implementations = [
  { name: "Bitcoin Core", version: "31.1", short: "BTC", tone: "orange" },
  { name: "rust-bitcoin", version: "0.32.102", short: "RS", tone: "neutral" },
  { name: "btcsuite PSBT", version: "1.2.0", short: "GO", tone: "blue" },
  { name: "bitcoinjs-lib", version: "7.0.1", short: "JS", tone: "yellow" },
  { name: "BDK Wallet", version: "3.1.0", short: "BDK", tone: "green" },
  { name: "rust-psbt PSBTv2", version: "0.3.0", short: "V2", tone: "violet" },
  { name: "libwally", version: "1.5.4", short: "LW", tone: "blue" },
  { name: "MuSig2 signer", version: "musig2 0.4.1", short: "M2", tone: "green" },
  { name: "HWI simulator", version: "JSON contract v1", short: "HWI", tone: "neutral" },
] as const;

export const reportScenarios: ReportScenario[] = [
  {
    id: "roundtrip",
    shortLabel: "Four-library roundtrip",
    title: "Metadata-rich P2WSH roundtrip",
    status: "pass",
    statusLabel: "Passed",
    handoff: "Core -> rust-bitcoin -> btcsuite -> bitcoinjs-lib",
    summary:
      "Transaction intent, known fields, unknown fields, and proprietary metadata remain semantically intact across the full handoff chain.",
    implementations: ["Bitcoin Core", "rust-bitcoin", "btcsuite PSBT", "bitcoinjs-lib"],
    evidence: [
      {
        field: "Unsigned transaction commitment",
        expected: "unchanged",
        actual: "unchanged",
        implementation: "all handoffs",
        nextStep: "No action required.",
      },
      {
        field: "Unknown and proprietary fields",
        expected: "exact union preserved",
        actual: "exact union preserved",
        implementation: "all handoffs",
        nextStep: "No action required.",
      },
      {
        field: "PSBT_OUT_BIP32_DERIVATION",
        expected: "preserved",
        actual: "preserved",
        implementation: "all handoffs",
        nextStep: "No action required.",
      },
    ],
    replay: "psbt-lab replay artifacts/<run-id>",
  },
  {
    id: "duplicate-key",
    shortLabel: "Duplicate global key",
    title: "Native parser duplicate-key probe",
    status: "finding",
    statusLabel: "Compatibility finding",
    handoff: "Malformed PSBT -> btcsuite PSBT 1.2.0 native parser",
    summary:
      "btcsuite accepts a duplicate global unsigned-transaction key. The lab keeps this divergence visible while requiring other native parsers to reject malformed input safely.",
    implementations: ["btcsuite PSBT"],
    classification: {
      ruleId: "bip174.map-keys.unique",
      observedAt: "btcsuite-go",
      evidence: "finding:btcsuite-go-duplicate-global-key-accepted",
      actual: "btcsuite PSBT 1.2.0 accepted a duplicate global unsigned-transaction key.",
    },
    evidence: [
      {
        field: "PSBT_GLOBAL_UNSIGNED_TX (0x00)",
        expected: "duplicate key rejected",
        actual: "duplicate key accepted",
        implementation: "btcsuite PSBT 1.2.0",
        nextStep: "Reject duplicate map keys before downstream use.",
      },
      {
        field: "Native parser process",
        expected: "bounded clean result",
        actual: "completed without crash",
        implementation: "btcsuite adapter",
        nextStep: "Track as compatibility behavior, not a crash.",
      },
      {
        field: "Report classification",
        expected: "finding remains explicit",
        actual: "CLI, JSON, Markdown, and HTML",
        implementation: "PSBT Interop Lab",
        nextStep: "Review before choosing a parser boundary.",
      },
    ],
    replay: "psbt-lab replay artifacts/<run-id>",
  },
  {
    id: "taproot",
    shortLabel: "Taproot key-path",
    title: "Taproot key-path signing handoff",
    status: "supported",
    statusLabel: "Covered",
    handoff: "Bitcoin Core -> current library signer -> Bitcoin Core",
    summary:
      "The suite checks Taproot key-path creation, roundtripping, signing, finalization, and policy acceptance on isolated regtest fixtures.",
    implementations: ["Bitcoin Core", "rust-bitcoin", "BDK Wallet"],
    evidence: [
      {
        field: "Taproot internal key",
        expected: "preserved",
        actual: "checked at every handoff",
        implementation: "capability-compatible adapters",
        nextStep: "Unsupported adapters are reported, never counted as passes.",
      },
      {
        field: "Unsigned transaction commitment",
        expected: "signer cannot mutate intent",
        actual: "run-scoped commitment enforced",
        implementation: "adapter protocol",
        nextStep: "Keep commitment protection enabled.",
      },
      {
        field: "Final transaction",
        expected: "Core policy accepted",
        actual: "verified on regtest",
        implementation: "Bitcoin Core 31.1",
        nextStep: "No mainnet broadcast path exists.",
      },
    ],
    replay: "psbt-lab replay artifacts/<run-id>",
  },
  {
    id: "psbtv2-finalization",
    shortLabel: "PSBTv2 finalization",
    title: "Explicit empty final-scriptSig divergence",
    status: "finding",
    statusLabel: "Compatibility finding",
    handoff: "libwally 1.5.4 -> rust-psbt PSBTv2 0.3.0 -> Bitcoin Core",
    summary:
      "A valid SegWit final witness exposes one standards divergence: rust-psbt requires an explicit empty final scriptSig where BIP174 requires that field to be omitted. libwally strictly rejects the explicit empty field as noncanonical, and Core still validates the extracted transaction.",
    implementations: ["Bitcoin Core", "rust-psbt PSBTv2", "libwally"],
    classification: {
      ruleId: "bip174.final-scriptsig.empty-omitted",
      observedAt: "rust-psbt-v2",
      evidence: "finding:rust-psbt-v2-final-scriptsig-required",
      actual:
        "rust-psbt-v2 required PSBT_IN_FINAL_SCRIPTSIG to be present with a zero-length value.",
    },
    evidence: [
      {
        field: "PSBT_IN_FINAL_SCRIPTSIG (0x07)",
        expected: publicConformanceRules["bip174.final-scriptsig.empty-omitted"].expected,
        actual: "rust-psbt-v2 requires the explicit empty field",
        implementation: "rust-psbt-v2",
        nextStep: "Accept the canonical omitted form during extraction.",
      },
      {
        field: "PSBT_IN_FINAL_SCRIPTWITNESS (0x08)",
        expected: "valid final witness preserved",
        actual: "preserved; libwally rejects the explicit empty scriptSig as noncanonical",
        implementation: "rust-psbt-v2 / libwally",
        nextStep: "Keep the witness as the transaction evidence.",
      },
      {
        field: "Extracted transaction",
        expected: "Bitcoin Core policy accepted",
        actual: "accepted on isolated regtest",
        implementation: "Bitcoin Core 31.1",
        nextStep: "Track the encoding mismatch as an interop finding.",
      },
    ],
    replay: "psbt-lab replay artifacts/<run-id>",
  },
  {
    id: "musig2",
    shortLabel: "BIP373 MuSig2",
    title: "Two-process MuSig2 key-path signing",
    status: "pass",
    statusLabel: "Passed",
    handoff: "Core -> Rust/JavaScript preservation -> signer 1 + signer 2 -> Core",
    summary:
      "Two isolated signer processes exchange BIP373 nonces and partial signatures, reject nonce reuse, verify both shares, and aggregate a Core-accepted BIP340 signature.",
    implementations: ["Bitcoin Core", "rust-bitcoin", "bitcoinjs-lib", "MuSig2 signer"],
    evidence: [
      {
        field: "BIP373 participant and nonce fields",
        expected: "ordered and preserved",
        actual: "preserved across both parsers",
        implementation: "rust-bitcoin / bitcoinjs-lib",
        nextStep: "Keep participant ordering bound to the aggregate key.",
      },
      {
        field: "Secret nonce lifecycle",
        expected: "one session, one use",
        actual: "in-memory and reuse rejected",
        implementation: "MuSig2 signer processes",
        nextStep: "Never persist or recycle production nonces.",
      },
      {
        field: "Aggregate signature",
        expected: "partials verified and Core accepted",
        actual: "BIP340 verification and regtest policy passed",
        implementation: "musig2 0.4.1 / Bitcoin Core 31.1",
        nextStep: "Add a second independent MuSig2 implementation next.",
      },
    ],
    replay: "psbt-lab replay artifacts/<run-id>",
  },
  {
    id: "hwi",
    shortLabel: "HWI simulator",
    title: "Simulator-backed hardware signing handoff",
    status: "pass",
    statusLabel: "Passed",
    handoff: "Core -> HWI adapter -> simulated device process -> Core",
    summary:
      "A separate HWI-compatible process enforces a fixed key origin and explicit confirmation, while the adapter accepts only the expected signature mutation.",
    implementations: ["Bitcoin Core", "HWI simulator"],
    evidence: [
      {
        field: "Device enumeration",
        expected: "one pinned simulator identity",
        actual: "fingerprint 73c5da0a",
        implementation: "HWI JSON process",
        nextStep: "Do not interpret this as physical-device attestation.",
      },
      {
        field: "User confirmation",
        expected: "refusal cancels signing",
        actual: "hwi.action_canceled",
        implementation: "simulated device process",
        nextStep: "Retain refusal as a required canary.",
      },
      {
        field: "Returned PSBT",
        expected: "signature-only mutation",
        actual: "validated before Core finalization",
        implementation: "HWI adapter / Bitcoin Core 31.1",
        nextStep: "Add vendor and USB coverage only with physical-device CI.",
      },
    ],
    replay: "psbt-lab replay artifacts/<run-id>",
  },
];

export const workflowSteps = [
  {
    number: "01",
    title: "Run real handoffs",
    body: "Deterministic regtest fixtures move through the same creator, updater, signer, combiner, and finalizer roles wallets use.",
  },
  {
    number: "02",
    title: "Compare semantically",
    body: "Every map is parsed field by field. Legal key reordering is recorded without hiding a changed amount, signature, sequence, or metadata field.",
  },
  {
    number: "03",
    title: "Replay exact evidence",
    body: "Private local artifacts preserve the checkpoints, facts, hashes, and implementation identities needed to reproduce a failure.",
  },
] as const;

export const docLinks = [
  {
    label: "Quick start",
    detail: "Prove one real handoff",
    href: "/docs#quick-start",
  },
  {
    label: "Scenario coverage",
    detail: "See all 47 bundled scenarios",
    href: "/docs#current-coverage",
  },
  { label: "Adapter kit", detail: "Bring another wallet or library", href: "/adapter-kit" },
  {
    label: "Architecture",
    detail: "Understand the system and trust boundaries",
    href: "/docs/architecture",
  },
  {
    label: "Conformance policy",
    detail: "Interpret sourced diagnostic rules",
    href: "/docs/conformance-policy",
  },
  {
    label: "Future work",
    detail: "Review planned compatibility and integration work",
    href: "/docs/future-work",
  },
  {
    label: "Official sources",
    detail: "Check specifications, versions, and pinned artifacts",
    href: "/docs/sources",
  },
  { label: "Security", detail: "Read the safety model", href: "/security" },
  {
    label: "Threat model",
    detail: "Inspect runtime and CI security boundaries",
    href: "/security/threat-model",
  },
  {
    label: "Adapter manifest schema",
    detail: "Inspect the third-party adapter contract",
    href: "/files/src/conformance/adapter-manifest.schema.json",
  },
  {
    label: "Custom suite schema",
    detail: "Inspect the fixture and scenario contract",
    href: "/files/src/custom/suite-manifest.schema.json",
  },
  {
    label: "Custom suite example",
    detail: "Start from a complete custom roundtrip",
    href: "/files/examples/custom-suite.json",
  },
  {
    label: "Website source",
    detail: "Browse the website application structure",
    href: "/files/website",
  },
] as const;
