import type { RunManifest } from "./artifacts.js";

const SECRET_KEY = /(private|secret|password|mnemonic|seed|wif)/i;
const PSBT_VALUE = /^cHNidP8[A-Za-z0-9+/]*={0,2}$/;

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
  if (typeof value === "string" && PSBT_VALUE.test(value)) {
    return "[redacted:psbt]";
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
      `### ${scenario.id}`,
      "",
      `Outcome: **${scenario.outcome.toUpperCase()}**`,
      "",
      scenario.summary,
      "",
    );
    if (scenario.expectedFailure) {
      lines.push(
        `Expected historical failure: \`${scenario.expectedFailure.implementation}\` returned \`${scenario.expectedFailure.errorClass}\`.`,
        "",
      );
    }
    if (scenario.transactionId) {
      lines.push(`Policy-accepted txid: \`${scenario.transactionId}\``, "");
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
