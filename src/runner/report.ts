import type { RunManifest } from "./artifacts.js";

const SECRET_KEY = /(private|secret|password|mnemonic|seed|wif)/i;
const PSBT_VALUE = /cHNidP8[A-Za-z0-9+/]*={0,2}/g;
const LABELED_SECRET =
  /\b(private(?:\s+key)?|secret|password|mnemonic|seed|wif)\s*[:=]\s*[^\s,;]+/gi;
const WIF_VALUE = /\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b/g;
const EXTENDED_PRIVATE_KEY = /\b(?:xprv|tprv)[1-9A-HJ-NP-Za-km-z]{100,110}\b/g;

export function redactSensitiveText(value: string): string {
  return value
    .replace(PSBT_VALUE, "[redacted:psbt]")
    .replace(
      LABELED_SECRET,
      (match) => `${match.slice(0, match.search(/[:=]/) + 1)}[redacted:secret]`,
    )
    .replace(WIF_VALUE, "[redacted:secret]")
    .replace(EXTENDED_PRIVATE_KEY, "[redacted:secret]");
}

export function redactValue(value: unknown, key = "", depth = 0): unknown {
  if (depth > 20) {
    return "[redacted:depth-limit]";
  }
  if (SECRET_KEY.test(key)) {
    return "[redacted:secret]";
  }
  if (key.toLowerCase() === "psbt") {
    return "[redacted:psbt]";
  }
  if (typeof value === "string") {
    return redactSensitiveText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, "", depth + 1));
  }
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        redactValue(childValue, childKey, depth + 1),
      ]),
    );
  }
  return value;
}

export function generateMarkdownReport(manifest: RunManifest): string {
  const lines = [
    "# PSBT Interop Lab Proof",
    "",
    `Run: \`${manifest.runId}\``,
    `Outcome: **${manifest.outcome.toUpperCase()}**`,
    `Bitcoin Core: \`${manifest.core.subversion}\` on regtest at height ${manifest.core.blocks}`,
    "",
    "## Scenarios",
    "",
  ];
  for (const scenario of manifest.scenarios) {
    lines.push(
      `### ${scenario.title}`,
      "",
      `Scenario: \`${scenario.id}\``,
      `Outcome: **${scenario.outcome.toUpperCase()}**`,
      `Duration: ${scenario.durationMs.toFixed(3)} ms`,
      "",
      scenario.summary,
      "",
    );
    if (scenario.missingCapabilities) {
      lines.push(
        "Missing capabilities:",
        "",
        ...scenario.missingCapabilities.map(
          (missing) => `- \`${missing.adapter}\`: ${missing.kind} \`${missing.value}\``,
        ),
        "",
      );
    }
    if (scenario.assertions.length > 0) {
      lines.push("Assertions:", "");
      for (const assertion of scenario.assertions) {
        const diagnostics = [
          assertion.policy ? `policy=${assertion.policy}` : undefined,
          assertion.exactBytesEqual !== undefined
            ? `exact-bytes=${assertion.exactBytesEqual ? "yes" : "no"}`
            : undefined,
        ].filter((value): value is string => value !== undefined);
        lines.push(
          `- **${assertion.passed ? "PASS" : "FAIL"}** \`${assertion.name}\`${diagnostics.length > 0 ? ` (${diagnostics.join(", ")})` : ""}`,
        );
        for (const failure of assertion.failures ?? []) {
          const location =
            failure.location.kind === "global"
              ? "global"
              : `${failure.location.kind}[${failure.location.index}]`;
          lines.push(
            `  - \`${failure.code}\` at ${location}, key type \`0x${failure.keyType.toString(16).padStart(2, "0")}\``,
          );
        }
      }
      lines.push("");
    }
    if (scenario.expectedFailure) {
      lines.push(
        `Expected historical failure: \`${scenario.expectedFailure.implementation}\` returned \`${scenario.expectedFailure.errorClass}\`.`,
        "",
      );
    }
    if (scenario.transactionId) {
      lines.push(`Policy-accepted txid: \`${scenario.transactionId}\``, "");
    }
    if (scenario.skipReason) {
      lines.push(`Skip reason: ${scenario.skipReason}`, "");
    }
  }
  lines.push(
    "## Checkpoints",
    "",
    ...manifest.checkpoints.map(
      (checkpoint) =>
        `- \`${checkpoint.scenario}/${checkpoint.stage}\`: ${checkpoint.facts.byteLength} bytes, SHA256 \`${checkpoint.facts.sha256}\``,
    ),
    "",
    "Raw PSBTs are stored only in the private checkpoint files beside this report.",
  );
  return lines.join("\n");
}
