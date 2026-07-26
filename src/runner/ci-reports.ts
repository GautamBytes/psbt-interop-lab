import { randomBytes } from "node:crypto";
import { chmod, type FileHandle, mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { ScenarioResult } from "../scenarios/definition.js";
import type { RunManifest } from "./artifacts.js";
import { redactSensitiveText } from "./report.js";

export interface CiReportOptions {
  readonly junit?: string;
  readonly sarif?: string;
}

function escapeXml(value: string | number): string {
  return redactSensitiveText(String(value))
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function scenarioFailureDetail(scenario: ScenarioResult): string {
  const details = [
    scenario.summary,
    ...(scenario.infrastructureError
      ? [`${scenario.infrastructureError.errorClass}: ${scenario.infrastructureError.message}`]
      : []),
    ...scenario.assertions
      .filter((assertion) => !assertion.passed)
      .map((assertion) => `${assertion.name}: ${assertion.summary ?? "assertion failed"}`),
    ...(scenario.findings ?? []).map(
      (finding) => `${finding.ruleId}: ${finding.summary} (${finding.actual})`,
    ),
  ];
  return details.map((detail) => redactSensitiveText(detail)).join("\n");
}

export function generateJunitReport(manifest: RunManifest): string {
  const failedScenarios = manifest.scenarios.filter(
    ({ outcome }) => outcome === "failed" || outcome === "unsupported",
  ).length;
  const skipped = manifest.scenarios.filter(({ outcome }) => outcome === "skipped").length;
  const needsRunPolicyFailure = manifest.outcome === "failed" && failedScenarios === 0;
  const failures = failedScenarios + (needsRunPolicyFailure ? 1 : 0);
  const tests = manifest.scenarios.length + (needsRunPolicyFailure ? 1 : 0);
  const durationSeconds =
    manifest.scenarios.reduce((total, scenario) => total + scenario.durationMs, 0) / 1000;
  const cases = manifest.scenarios.map((scenario) => {
    const attributes = [
      `classname="${escapeXml(scenario.category)}"`,
      `name="${escapeXml(scenario.title)}"`,
      `time="${(scenario.durationMs / 1000).toFixed(6)}"`,
    ].join(" ");
    if (scenario.outcome === "failed") {
      return `  <testcase ${attributes}>\n    <failure message="${escapeXml(scenario.summary)}">${escapeXml(scenarioFailureDetail(scenario))}</failure>\n  </testcase>`;
    }
    if (scenario.outcome === "unsupported") {
      return `  <testcase ${attributes}>\n    <failure type="capability.unsupported" message="${escapeXml(scenario.summary)}">${escapeXml(scenarioFailureDetail(scenario))}</failure>\n  </testcase>`;
    }
    if (scenario.outcome === "skipped") {
      return `  <testcase ${attributes}>\n    <skipped message="${escapeXml(scenario.summary)}" />\n  </testcase>`;
    }
    return `  <testcase ${attributes} />`;
  });
  if (needsRunPolicyFailure) {
    cases.push(
      '  <testcase classname="run-policy" name="PSBT Interop Lab run outcome" time="0.000000">\n    <failure type="run.failed" message="The PSBT Interop Lab command failed">The run manifest is failed even though no scenario emitted a failure. Inspect skipped scenarios and the replayable run manifest.</failure>\n  </testcase>',
    );
  }

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuite name="psbt-interop-lab" tests="${tests}" failures="${failures}" skipped="${skipped}" time="${durationSeconds.toFixed(6)}">`,
    `  <properties><property name="runId" value="${escapeXml(manifest.runId)}" /></properties>`,
    ...cases,
    "</testsuite>",
    "",
  ].join("\n");
}

interface SarifRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
}

interface SarifResult {
  readonly ruleId: string;
  readonly level: "error" | "warning";
  readonly message: { readonly text: string };
  readonly properties: Readonly<Record<string, string>>;
}

function assertionRuleId(name: string): string {
  const normalized = name.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return `psbt-lab.assertion.${normalized || "failed"}`;
}

function addSarifError(
  rules: Map<string, SarifRule>,
  results: SarifResult[],
  ruleId: string,
  name: string,
  description: string,
  message: string,
  properties: Readonly<Record<string, string>>,
): void {
  rules.set(ruleId, {
    id: ruleId,
    name,
    shortDescription: { text: description },
  });
  results.push({
    ruleId,
    level: "error",
    message: { text: redactSensitiveText(message) },
    properties,
  });
}

export function generateSarifReport(manifest: RunManifest): string {
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const scenario of manifest.scenarios) {
    for (const finding of scenario.findings ?? []) {
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.id,
        shortDescription: { text: redactSensitiveText(finding.summary) },
      });
      results.push({
        ruleId: finding.ruleId,
        level: "warning",
        message: {
          text: redactSensitiveText(`${finding.summary} Observed: ${finding.actual}`),
        },
        properties: {
          scenario: scenario.id,
          category: scenario.category,
          implementation: redactSensitiveText(finding.implementation),
          finding: finding.id,
        },
      });
    }

    const failedAssertions = scenario.assertions.filter(({ passed }) => !passed);
    for (const assertion of failedAssertions) {
      const ruleId = assertionRuleId(assertion.name);
      rules.set(ruleId, {
        id: ruleId,
        name: assertion.name,
        shortDescription: { text: `PSBT interoperability assertion ${assertion.name}` },
      });
      results.push({
        ruleId,
        level: "error",
        message: {
          text: redactSensitiveText(assertion.summary ?? scenario.summary),
        },
        properties: {
          scenario: scenario.id,
          category: scenario.category,
          assertion: assertion.name,
          ...(assertion.likelyImplementation
            ? { implementation: redactSensitiveText(assertion.likelyImplementation) }
            : {}),
        },
      });
    }

    if (scenario.outcome === "unsupported") {
      addSarifError(
        rules,
        results,
        "psbt-lab.scenario.unsupported",
        "unsupported-scenario",
        "A required interoperability scenario was unsupported",
        scenario.summary,
        {
          scenario: scenario.id,
          category: scenario.category,
          outcome: scenario.outcome,
        },
      );
    } else if (scenario.outcome === "failed" && failedAssertions.length === 0) {
      addSarifError(
        rules,
        results,
        "psbt-lab.scenario.failed",
        "failed-scenario",
        "An interoperability scenario failed without assertion evidence",
        scenarioFailureDetail(scenario),
        {
          scenario: scenario.id,
          category: scenario.category,
          outcome: scenario.outcome,
        },
      );
    }
  }

  if (manifest.outcome === "failed" && !results.some(({ level }) => level === "error")) {
    addSarifError(
      rules,
      results,
      "psbt-lab.run.failed",
      "failed-run",
      "The PSBT Interop Lab command failed",
      "The run manifest is failed even though no scenario emitted an error result. Inspect skipped scenarios and the replayable run manifest.",
      { runId: manifest.runId, outcome: manifest.outcome },
    );
  }

  return `${JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "PSBT Interop Lab",
              version: "0.8.0",
              informationUri: "https://github.com/GautamBytes/psbt-interop-lab",
              rules: [...rules.values()],
            },
          },
          results,
          properties: {
            runId: manifest.runId,
            outcome: manifest.outcome,
          },
        },
      ],
    },
    null,
    2,
  )}\n`;
}

async function atomicWrite(path: string, contents: string): Promise<void> {
  const resolved = resolve(path);
  await mkdir(dirname(resolved), { recursive: true, mode: 0o700 });
  const temporary = `${resolved}.tmp-${randomBytes(8).toString("hex")}`;
  let handle: FileHandle | undefined = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(contents, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, resolved);
    await chmod(resolved, 0o600);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function writeCiReports(
  manifest: RunManifest,
  options: CiReportOptions,
): Promise<void> {
  if (options.junit) await atomicWrite(options.junit, generateJunitReport(manifest));
  if (options.sarif) await atomicWrite(options.sarif, generateSarifReport(manifest));
}
