import { parseAdapterHelloCapabilities } from "../protocol/schema.js";
import {
  ADAPTER_PROTOCOL,
  type AdapterHelloCapabilities,
  type AdapterResponse,
} from "../protocol/types.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { assertPsbtTransition } from "../psbt/invariants.js";
import type { AvailableRuntimeAdapter, RuntimeProvider } from "../runtime/provider.js";
import { LOCAL_PARSE_FIXTURES, type LocalParseFixture } from "./fixtures.js";

export type ParseMatrixCellStatus = "passed" | "failed" | "unsupported";

export interface ParseMatrixCell {
  readonly adapterId: string;
  readonly fixtureId: string;
  readonly status: ParseMatrixCellStatus;
  readonly detail: string;
}

export interface ParseMatrixReport {
  readonly runtime: string;
  readonly outcome: "passed" | "partial" | "failed";
  readonly fixtures: readonly Pick<
    LocalParseFixture,
    "id" | "title" | "source" | "psbtVersion" | "sha256"
  >[];
  readonly cells: readonly ParseMatrixCell[];
  readonly summary: Readonly<Record<ParseMatrixCellStatus, number>>;
}

function assertIdentity(adapter: AvailableRuntimeAdapter, response: AdapterResponse): void {
  const actual = response.implementation;
  for (const key of ["name", "version", "sourceRevision", "artifactDigest"] as const) {
    if (actual[key] !== adapter.expected[key]) {
      throw new Error(`Adapter identity ${key} did not match the local runtime manifest`);
    }
  }
}

function failureCell(
  adapterId: string,
  fixtureId: string,
  response: Exclude<AdapterResponse, { status: "ok" }>,
): ParseMatrixCell {
  return {
    adapterId,
    fixtureId,
    status: response.status === "unsupported" ? "unsupported" : "failed",
    detail: `${response.error.class}: ${response.error.message}`,
  };
}

function requireOutputString(response: AdapterResponse, key: string): string {
  if (response.status !== "ok") throw new Error("Expected a successful adapter response");
  const value = response.output[key];
  if (typeof value !== "string") throw new Error(`Adapter output ${key} must be a string`);
  return value;
}

async function runFixture(
  adapter: AvailableRuntimeAdapter,
  adapterIndex: number,
  fixture: LocalParseFixture,
  fixtureIndex: number,
): Promise<ParseMatrixCell> {
  try {
    const parsed = await adapter.process.request(
      {
        protocol: ADAPTER_PROTOCOL,
        id: `local-${adapterIndex}-parse-${fixtureIndex}`,
        operation: "native-parse",
        payload: { psbt: fixture.psbt },
      },
      adapter.timeoutMs,
    );
    assertIdentity(adapter, parsed);
    if (parsed.status !== "ok") return failureCell(adapter.id, fixture.id, parsed);
    if (
      requireOutputString(parsed, "nativeParser") !== adapter.expected.name ||
      parsed.output["psbtVersion"] !== fixture.psbtVersion
    ) {
      throw new Error("Adapter native parser identity or PSBT version did not match");
    }

    const roundtrip = await adapter.process.request(
      {
        protocol: ADAPTER_PROTOCOL,
        id: `local-${adapterIndex}-roundtrip-${fixtureIndex}`,
        operation: "roundtrip",
        payload: { psbt: fixture.psbt },
      },
      adapter.timeoutMs,
    );
    assertIdentity(adapter, roundtrip);
    if (roundtrip.status !== "ok") return failureCell(adapter.id, fixture.id, roundtrip);
    const returned = parsePsbtDocument(requireOutputString(roundtrip, "psbt"));
    const source = parsePsbtDocument(fixture.psbt);
    const transition = assertPsbtTransition("roundtrip", source, returned);
    if (!transition.ok) throw new Error("Roundtrip changed protected PSBT fields");
    return {
      adapterId: adapter.id,
      fixtureId: fixture.id,
      status: "passed",
      detail: transition.exactBytesEqual
        ? "Native parse and byte-identical roundtrip passed"
        : "Native parse and semantic roundtrip passed",
    };
  } catch (error) {
    return {
      adapterId: adapter.id,
      fixtureId: fixture.id,
      status: "failed",
      detail: error instanceof Error ? error.message : "Unknown local adapter failure",
    };
  }
}

export async function runParseMatrix(provider: RuntimeProvider): Promise<ParseMatrixReport> {
  try {
    for (const fixture of LOCAL_PARSE_FIXTURES) {
      const parsed = parsePsbtDocument(fixture.psbt);
      if (parsed.sha256 !== fixture.sha256 || parsed.psbtVersion !== fixture.psbtVersion) {
        throw new Error(`Frozen fixture ${fixture.id} failed its checksum or version commitment`);
      }
    }

    const cells: ParseMatrixCell[] = [];
    const adapters = await provider.adapters();
    for (const [adapterIndex, adapter] of adapters.entries()) {
      if (adapter.availability === "unsupported") {
        for (const fixture of LOCAL_PARSE_FIXTURES) {
          cells.push({
            adapterId: adapter.id,
            fixtureId: fixture.id,
            status: "unsupported",
            detail: adapter.reason,
          });
        }
        continue;
      }

      let capabilities: AdapterHelloCapabilities;
      try {
        const hello = await adapter.process.request(
          {
            protocol: ADAPTER_PROTOCOL,
            id: `local-${adapterIndex}-hello`,
            operation: "hello",
            payload: {},
          },
          adapter.timeoutMs,
        );
        assertIdentity(adapter, hello);
        if (hello.status !== "ok") {
          for (const fixture of LOCAL_PARSE_FIXTURES) {
            cells.push(failureCell(adapter.id, fixture.id, hello));
          }
          continue;
        }
        capabilities = parseAdapterHelloCapabilities(hello.output);
      } catch (error) {
        for (const fixture of LOCAL_PARSE_FIXTURES) {
          cells.push({
            adapterId: adapter.id,
            fixtureId: fixture.id,
            status: "failed",
            detail: error instanceof Error ? error.message : "Adapter hello failed",
          });
        }
        continue;
      }

      for (const [fixtureIndex, fixture] of LOCAL_PARSE_FIXTURES.entries()) {
        if (
          !capabilities.roles.includes("parser") ||
          !capabilities.operations.includes("native-parse") ||
          !capabilities.operations.includes("roundtrip") ||
          !capabilities.psbtVersions.includes(fixture.psbtVersion)
        ) {
          cells.push({
            adapterId: adapter.id,
            fixtureId: fixture.id,
            status: "unsupported",
            detail: `Adapter does not declare parser roundtrip support for PSBTv${fixture.psbtVersion}`,
          });
          continue;
        }
        cells.push(await runFixture(adapter, adapterIndex, fixture, fixtureIndex));
      }
    }

    const summary = {
      passed: cells.filter(({ status }) => status === "passed").length,
      failed: cells.filter(({ status }) => status === "failed").length,
      unsupported: cells.filter(({ status }) => status === "unsupported").length,
    };
    return {
      runtime: provider.runtime,
      outcome: summary.failed > 0 ? "failed" : summary.unsupported > 0 ? "partial" : "passed",
      fixtures: LOCAL_PARSE_FIXTURES.map(({ psbt: _psbt, ...fixture }) => fixture),
      cells,
      summary,
    };
  } finally {
    await provider.close();
  }
}

export function formatParseMatrix(report: ParseMatrixReport): string {
  const lines = [
    `Local parser matrix: ${report.outcome}`,
    `passed=${report.summary.passed} failed=${report.summary.failed} unsupported=${report.summary.unsupported}`,
  ];
  for (const cell of report.cells) {
    lines.push(`${cell.status.toUpperCase()} ${cell.adapterId} ${cell.fixtureId}: ${cell.detail}`);
  }
  return lines.join("\n");
}
