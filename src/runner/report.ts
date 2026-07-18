import type { RunManifest } from "./artifacts.js";
import {
  classifyScenario,
  type ReportClassification,
  type ReportRepairability,
} from "./classification.js";

const SECRET_KEY = /(private|secret|password|mnemonic|seed|wif)/i;
const PSBT_VALUE = /cHNidP8[A-Za-z0-9+/]*={0,2}/g;
const LABELED_MULTIWORD_SECRET = /\b(mnemonic|seed(?:\s+phrase)?)\s*[:=]\s*[^,;\r\n]+/gi;
const LABELED_SECRET =
  /\b(private(?:\s+key)?|secret|password|mnemonic|seed|wif)\s*[:=]\s*[^\s,;]+/gi;
const WIF_VALUE = /\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b/g;
const EXTENDED_PRIVATE_KEY = /\b[xyzuvt]prv[1-9A-HJ-NP-Za-km-z]{100,110}\b/gi;

export function redactSensitiveText(value: string): string {
  return value
    .replace(PSBT_VALUE, "[redacted:psbt]")
    .replace(
      LABELED_MULTIWORD_SECRET,
      (match) => `${match.slice(0, match.search(/[:=]/) + 1)}[redacted:secret]`,
    )
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

export function generateJsonReport(manifest: RunManifest): unknown {
  return redactValue({
    ...manifest,
    scenarios: manifest.scenarios.map((scenario) => ({
      ...scenario,
      classifications: classifyScenario(scenario),
    })),
    note: "Raw PSBTs are intentionally stored only in private checkpoint files.",
  });
}

function repairabilityLabel(repairability: ReportRepairability): string {
  switch (repairability) {
    case "code-or-dependency-change":
      return "Code or dependency change";
    case "investigation-required":
      return "Investigation required";
    case "not-a-code-defect":
      return "Not classified as a code defect";
  }
}

function markdownClassification(classification: ReportClassification): string[] {
  return [
    `- **${classification.label}** (\`${classification.id}\`)`,
    `  - Severity: **${classification.severity.toUpperCase()}**`,
    `  - Likely owner: \`${classification.likelyOwner}\``,
    `  - Repairability: \`${classification.repairability}\``,
    `  - Confidence: \`${classification.confidence}\``,
    `  - ${classification.summary}`,
    `  - Evidence: ${classification.evidence.map((evidence) => `\`${evidence}\``).join(", ")}`,
  ];
}

export function generateMarkdownReport(manifest: RunManifest): string {
  const filtered =
    (manifest.selectors?.requested.scenarios?.length ?? 0) > 0 ||
    manifest.selectors?.requested.category !== undefined;
  const selection = filtered
    ? `Filtered run: requested ${manifest.selectors?.requested.scenarios?.map((id) => `\`${id}\``).join(", ") || "all scenarios"}${manifest.selectors?.requested.category ? ` in category \`${manifest.selectors.requested.category}\`` : ""}; executed ${manifest.selectors?.executed.scenarios.length ?? 0} scenario(s).`
    : undefined;
  const lines = [
    "# PSBT Interop Lab Proof",
    "",
    `Run: \`${manifest.runId}\``,
    `Outcome: **${manifest.outcome.toUpperCase()}**`,
    manifest.core
      ? `Bitcoin Core: \`${manifest.core.subversion}\` on regtest at height ${manifest.core.blocks}`
      : "Bitcoin Core: not required by selected scenarios",
    ...(selection ? [selection] : []),
    "",
    "## Scenarios",
    "",
  ];
  for (const scenario of manifest.scenarios) {
    const classifications = classifyScenario(scenario);
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
    if (classifications.length > 0) {
      lines.push("Classifications:", "", ...classifications.flatMap(markdownClassification), "");
    }
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
          assertion.likelyImplementation
            ? `likely-implementation=${assertion.likelyImplementation}`
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
          const field = failure.field;
          lines.push(
            field
              ? `  - \`${failure.code}\` at ${location}: \`${field.symbol}\` (${field.displayName}, \`${field.keyTypeHex}\`${field.bip ? `, ${field.bip}` : ""})`
              : `  - \`${failure.code}\` at ${location}, key type \`0x${failure.keyType.toString(16).padStart(2, "0")}\``,
          );
          if (failure.guidance) {
            lines.push(
              `    - Guidance **${failure.guidance.severity.toUpperCase()}** \`${failure.guidance.code}\`: ${failure.guidance.summary}`,
              ...failure.guidance.nextSteps.map((step) => `      - ${step}`),
            );
          }
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
    if (scenario.findings?.length) {
      lines.push(
        "Compatibility findings:",
        "",
        ...scenario.findings.map(
          (finding) => `- \`${finding.id}\` in \`${finding.implementation}\`: ${finding.summary}`,
        ),
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

function escapeHtml(value: string | number): string {
  return redactSensitiveText(String(value))
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function failureLocation(
  location: RunManifest["scenarios"][number]["assertions"][number]["failures"] extends
    | readonly (infer Failure)[]
    | undefined
    ? Failure extends { location: infer Location }
      ? Location
      : never
    : never,
): string {
  return location.kind === "global" ? "global" : `${location.kind}[${location.index}]`;
}

export function generateHtmlReport(manifest: RunManifest): string {
  const counts = {
    passed: manifest.scenarios.filter((scenario) => scenario.outcome === "passed").length,
    failed: manifest.scenarios.filter((scenario) => scenario.outcome === "failed").length,
    unsupported: manifest.scenarios.filter((scenario) => scenario.outcome === "unsupported").length,
    skipped: manifest.scenarios.filter((scenario) => scenario.outcome === "skipped").length,
    findings: manifest.scenarios.reduce(
      (count, scenario) => count + (scenario.findings?.length ?? 0),
      0,
    ),
  };
  const scenarios = manifest.scenarios
    .map((scenario) => {
      const classifications = classifyScenario(scenario);
      const classificationHtml = classifications
        .map(
          (
            classification,
          ) => `<li class="classification classification--${escapeHtml(classification.severity)}">
            <div><strong>${escapeHtml(classification.label)}</strong><code>${escapeHtml(classification.id)}</code></div>
            <dl>
              <div><dt>Severity</dt><dd>${escapeHtml(classification.severity.toUpperCase())}</dd></div>
              <div><dt>Likely owner</dt><dd><code>${escapeHtml(classification.likelyOwner)}</code></dd></div>
              <div><dt>Repairability</dt><dd>${escapeHtml(repairabilityLabel(classification.repairability))}</dd></div>
              <div><dt>Confidence</dt><dd>${escapeHtml(classification.confidence)}</dd></div>
            </dl>
            <p>${escapeHtml(classification.summary)}</p>
            <p class="classification__evidence">Evidence: ${classification.evidence.map((evidence) => `<code>${escapeHtml(evidence)}</code>`).join(" · ")}</p>
          </li>`,
        )
        .join("");
      const assertions = scenario.assertions
        .map((assertion) => {
          const diagnostics = [
            assertion.policy ? `policy ${assertion.policy}` : undefined,
            assertion.exactBytesEqual !== undefined
              ? `exact bytes ${assertion.exactBytesEqual ? "yes" : "no"}`
              : undefined,
            assertion.likelyImplementation
              ? `Likely implementation ${assertion.likelyImplementation}`
              : undefined,
          ].filter((value): value is string => value !== undefined);
          const failures = (assertion.failures ?? [])
            .map((failure) => {
              const field = failure.field;
              const fieldDescription = field
                ? `<code>${escapeHtml(field.symbol)}</code> (${escapeHtml(field.displayName)}, <code>${escapeHtml(field.keyTypeHex)}</code>${field.bip ? `, ${escapeHtml(field.bip)}` : ""})`
                : `key <code>0x${escapeHtml(failure.keyType.toString(16).padStart(2, "0"))}</code>`;
              const guidance = failure.guidance
                ? `<div class="guidance"><strong>${escapeHtml(failure.guidance.severity.toUpperCase())}</strong> <code>${escapeHtml(failure.guidance.code)}</code>: ${escapeHtml(failure.guidance.summary)}<ul>${failure.guidance.nextSteps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul></div>`
                : "";
              return `<li><code>${escapeHtml(failure.code)}</code> at ${escapeHtml(failureLocation(failure.location))}: ${fieldDescription}${guidance}</li>`;
            })
            .join("");
          return `<li class="assertion ${assertion.passed ? "pass" : "fail"}">
            <div><strong>${assertion.passed ? "PASS" : "FAIL"}</strong> <code>${escapeHtml(assertion.name)}</code>${diagnostics.length > 0 ? ` <span>${escapeHtml(diagnostics.join(" · "))}</span>` : ""}</div>
            ${assertion.summary ? `<p>${escapeHtml(assertion.summary)}</p>` : ""}
            ${failures ? `<ul class="failures">${failures}</ul>` : ""}
          </li>`;
        })
        .join("");
      const missing = (scenario.missingCapabilities ?? [])
        .map(
          (capability) =>
            `<li><code>${escapeHtml(capability.adapter)}</code> lacks ${escapeHtml(capability.kind)} <code>${escapeHtml(capability.value)}</code></li>`,
        )
        .join("");
      const findings = (scenario.findings ?? [])
        .map(
          (finding) =>
            `<li><code>${escapeHtml(finding.id)}</code> in <code>${escapeHtml(finding.implementation)}</code>: ${escapeHtml(finding.summary)}</li>`,
        )
        .join("");
      return `<article class="scenario">
        <header>
          <div><span class="badge ${escapeHtml(scenario.outcome)}">${escapeHtml(scenario.outcome.toUpperCase())}</span><span class="category">${escapeHtml(scenario.category)}</span></div>
          <h2>${escapeHtml(scenario.title)}</h2>
          <p class="scenario-id"><code>${escapeHtml(scenario.id)}</code> · ${escapeHtml(scenario.durationMs.toFixed(3))} ms</p>
        </header>
        <p>${escapeHtml(scenario.summary)}</p>
        ${classificationHtml ? `<section class="classification-section" aria-label="Scenario classifications"><h3>Classification</h3><ul class="classifications">${classificationHtml}</ul></section>` : ""}
        ${scenario.expectedFailure ? `<p class="expected">Expected failure: <code>${escapeHtml(scenario.expectedFailure.implementation)}</code> · <code>${escapeHtml(scenario.expectedFailure.errorClass)}</code></p>` : ""}
        ${findings ? `<h3>Compatibility findings</h3><ul class="findings">${findings}</ul>` : ""}
        ${missing ? `<h3>Missing capabilities</h3><ul>${missing}</ul>` : ""}
        ${assertions ? `<details open><summary>Assertions (${scenario.assertions.length})</summary><ul class="assertions">${assertions}</ul></details>` : ""}
      </article>`;
    })
    .join("\n");
  const adapters = manifest.adapters
    .map(
      (adapter) => `<tr>
        <td><code>${escapeHtml(adapter.name)}</code></td>
        <td>${escapeHtml(adapter.version)}</td>
        <td><code>${escapeHtml(adapter.sourceRevision ?? "not declared")}</code></td>
        <td><code>${escapeHtml(adapter.artifactDigest)}</code></td>
      </tr>`,
    )
    .join("\n");
  const checkpoints = manifest.checkpoints
    .map(
      (checkpoint) => `<tr>
        <td><code>${escapeHtml(checkpoint.scenario)}</code></td>
        <td><code>${escapeHtml(checkpoint.stage)}</code></td>
        <td>${escapeHtml(checkpoint.facts.byteLength)} bytes</td>
        <td><code>${escapeHtml(checkpoint.facts.sha256)}</code></td>
      </tr>`,
    )
    .join("\n");
  const runtimeSummary = manifest.core
    ? `${escapeHtml(manifest.core.subversion)} · regtest height ${escapeHtml(manifest.core.blocks)} · ${escapeHtml(manifest.core.connections)} peers`
    : "Bitcoin Core not required by selected scenarios";
  const filtered =
    (manifest.selectors?.requested.scenarios?.length ?? 0) > 0 ||
    manifest.selectors?.requested.category !== undefined;
  const selectionSummary = filtered
    ? `<p class="run-meta"><strong>Filtered run</strong> · requested ${escapeHtml(manifest.selectors?.requested.scenarios?.join(", ") || "all scenarios")}${manifest.selectors?.requested.category ? ` · category ${escapeHtml(manifest.selectors.requested.category)}` : ""} · executed ${escapeHtml(manifest.selectors?.executed.scenarios.length ?? 0)} scenario(s)</p>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <title>PSBT Interop Lab · ${escapeHtml(manifest.runId)}</title>
  <style>
    :root { color-scheme: light dark; --bg: #f5f6f7; --surface: #ffffff; --text: #17191c; --muted: #5d6670; --line: #d6d9de; --pass: #167346; --fail: #b42318; --warn: #9a5b00; --info: #0b7285; }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; letter-spacing: 0; }
    main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 64px; }
    h1 { margin: 0; font-size: 28px; line-height: 1.2; }
    h2 { margin: 8px 0 2px; font-size: 18px; line-height: 1.3; }
    h3 { margin: 18px 0 6px; font-size: 14px; }
    p { overflow-wrap: anywhere; }
    code { font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
    .run-header { border-bottom: 1px solid var(--line); padding-bottom: 24px; }
    .run-meta { color: var(--muted); margin: 8px 0 0; }
    .metrics { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 1px; margin: 24px 0; border: 1px solid var(--line); background: var(--line); }
    .metric { background: var(--surface); padding: 14px 16px; }
    .metric strong { display: block; font-size: 22px; }
    .metric span, .category, .scenario-id, .assertion span { color: var(--muted); }
    .section-title { margin: 32px 0 12px; font-size: 20px; }
    .scenario { background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: 18px; margin: 10px 0; }
    .scenario header { display: block; }
    .badge { display: inline-block; border: 1px solid currentColor; border-radius: 4px; padding: 2px 6px; margin-right: 8px; font-size: 11px; font-weight: 700; }
    .badge.passed, .assertion.pass strong { color: var(--pass); }
    .badge.failed, .assertion.fail strong { color: var(--fail); }
    .badge.unsupported { color: var(--warn); }
    .badge.skipped { color: var(--info); }
    .expected { border-left: 3px solid var(--warn); padding-left: 10px; }
    .findings { border-left: 3px solid var(--warn); padding-left: 28px; }
    .findings li { margin: 6px 0; }
    .classifications { display: grid; gap: 8px; list-style: none; padding: 0; margin: 8px 0 16px; }
    .classification { border: 1px solid var(--line); border-left-width: 3px; border-radius: 4px; padding: 10px 12px; }
    .classification--stop { border-left-color: var(--fail); }
    .classification--review { border-left-color: var(--warn); }
    .classification--info { border-left-color: var(--info); }
    .classification > div { display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: 12px; }
    .classification dl { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin: 10px 0; }
    .classification dl div { min-width: 0; }
    .classification dt { color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .classification dd { margin: 2px 0 0; overflow-wrap: anywhere; }
    .classification p { margin: 6px 0 0; }
    .classification__evidence { color: var(--muted); }
    details { border-top: 1px solid var(--line); margin-top: 16px; padding-top: 12px; }
    summary { cursor: pointer; font-weight: 650; }
    .assertions, .failures { list-style: none; padding: 0; margin: 10px 0 0; }
    .assertion { border-top: 1px solid var(--line); padding: 9px 0; }
    .assertion:first-child { border-top: 0; }
    .assertion p { color: var(--muted); margin: 4px 0; }
    .failures > li { margin: 6px 0; color: var(--fail); }
    .guidance { color: var(--text); margin: 6px 0 10px 16px; }
    .guidance ul { margin: 4px 0 0; padding-left: 20px; }
    .table-wrap { overflow-x: auto; border: 1px solid var(--line); background: var(--surface); }
    table { width: 100%; border-collapse: collapse; min-width: 720px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 12px; }
    tr:last-child td { border-bottom: 0; }
    @media (prefers-color-scheme: dark) { :root { --bg: #111315; --surface: #1a1d20; --text: #f1f3f5; --muted: #a6adb5; --line: #353a40; --pass: #65d69e; --fail: #ff8d85; --warn: #f3bd62; --info: #66c7d4; } }
    @media (max-width: 640px) { main { width: min(100% - 20px, 1180px); padding-top: 20px; } .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } .classification dl { grid-template-columns: repeat(2, minmax(0, 1fr)); } h1 { font-size: 23px; } }
  </style>
</head>
<body>
<main>
  <header class="run-header">
    <h1>PSBT Interop Lab</h1>
    <p class="run-meta">Run <code>${escapeHtml(manifest.runId)}</code> · ${runtimeSummary}</p>
    ${selectionSummary}
  </header>
  <section class="metrics" aria-label="Run totals">
    <div class="metric"><strong>${counts.passed}</strong><span>Passed</span></div>
    <div class="metric"><strong>${counts.failed}</strong><span>Failed</span></div>
    <div class="metric"><strong>${counts.unsupported}</strong><span>Unsupported</span></div>
    <div class="metric"><strong>${counts.skipped}</strong><span>Skipped</span></div>
    <div class="metric"><strong>${counts.findings}</strong><span>Findings</span></div>
  </section>
  <h2 class="section-title">Scenarios</h2>
  ${scenarios}
  <h2 class="section-title">Implementations</h2>
  <div class="table-wrap"><table><thead><tr><th>Name</th><th>Version</th><th>Source revision</th><th>Artifact digest</th></tr></thead><tbody>${adapters}</tbody></table></div>
  <h2 class="section-title">Private checkpoints</h2>
  <div class="table-wrap"><table><thead><tr><th>Scenario</th><th>Stage</th><th>Size</th><th>SHA256</th></tr></thead><tbody>${checkpoints}</tbody></table></div>
</main>
</body>
</html>`;
}
