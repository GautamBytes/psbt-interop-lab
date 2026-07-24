import { describe, expect, test, vi } from "vitest";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import type { RuntimeAdapter, RuntimeProvider } from "../../src/runtime/provider.js";

const IMPLEMENTATION = {
  name: "fixture-parser",
  version: "1.0.0",
  sourceRevision: "fixture-parser-v1",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

function response(request: AdapterRequest): AdapterResponse {
  if (request.operation === "hello") {
    return {
      protocol: "psbt-lab.adapter/0.2",
      id: request.id,
      status: "ok",
      implementation: IMPLEMENTATION,
      output: {
        operations: ["hello", "native-parse", "roundtrip"],
        roles: ["parser"],
        psbtVersions: [0, 2],
        scriptTypes: ["p2wpkh"],
        operationScriptTypes: { roundtrip: ["p2wpkh"] },
      },
    };
  }
  if (request.operation === "native-parse") {
    const psbt = request.payload["psbt"];
    if (typeof psbt !== "string") throw new TypeError("Expected a PSBT fixture");
    const parsed = parsePsbtDocument(psbt);
    return {
      protocol: "psbt-lab.adapter/0.2",
      id: request.id,
      status: "ok",
      implementation: IMPLEMENTATION,
      output: {
        nativeParser: "fixture-parser",
        psbtVersion: parsed.psbtVersion,
        inputs: parsed.inputCount,
        outputs: parsed.outputCount,
      },
    };
  }
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: request.id,
    status: "ok",
    implementation: IMPLEMENTATION,
    output: { psbt: request.payload["psbt"] ?? "", byteIdentical: true, psbtVersion: 0 },
  };
}

function provider(overrides: Partial<RuntimeAdapter>[] = []): RuntimeProvider {
  const process = {
    request: vi.fn(async (request: AdapterRequest) => response(request)),
    close: vi.fn(async () => undefined),
  };
  const available: RuntimeAdapter = {
    id: "fixture-parser",
    availability: "available",
    process,
    timeoutMs: 5_000,
    expected: IMPLEMENTATION,
  };
  const unsupported: RuntimeAdapter = {
    id: "native-rust",
    availability: "unsupported",
    reason: "No verified native bundle is published for this platform",
  };
  return {
    runtime: "local",
    adapters: vi.fn(async () =>
      overrides.length === 0 ? [available, unsupported] : (overrides as RuntimeAdapter[]),
    ),
    close: vi.fn(async () => undefined),
  };
}

describe("local parse matrix", () => {
  test("runs every frozen fixture through parse and roundtrip without counting unavailable as pass", async () => {
    const matrix = await import("../../src/local/parse-matrix.js").catch(() => undefined);
    expect(matrix, "the local parse matrix is missing").toBeDefined();
    if (!matrix) return;
    const runtime = provider();

    const report = await matrix.runParseMatrix(runtime);

    expect(report.runtime).toBe("local");
    expect(report.fixtures.map(({ psbtVersion }: { psbtVersion: number }) => psbtVersion)).toEqual([
      0, 2,
    ]);
    expect(
      report.cells.filter(({ status }: { status: string }) => status === "passed"),
    ).toHaveLength(2);
    expect(
      report.cells.filter(({ status }: { status: string }) => status === "unsupported"),
    ).toHaveLength(2);
    expect(report.summary).toEqual({ passed: 2, failed: 0, unsupported: 2 });
    expect(report.outcome).toBe("partial");
    expect(runtime.close).toHaveBeenCalledOnce();
  });

  test("keeps an adapter-declared unsupported operation unsupported", async () => {
    const matrix = await import("../../src/local/parse-matrix.js");
    const process = {
      request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
        if (request.operation === "hello") return response(request);
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "unsupported",
          implementation: IMPLEMENTATION,
          error: { class: "operation.unsupported", message: "not available" },
        };
      }),
      close: vi.fn(async () => undefined),
    };

    const report = await matrix.runParseMatrix(
      provider([
        {
          id: "fixture-parser",
          availability: "available",
          process,
          timeoutMs: 5_000,
          expected: IMPLEMENTATION,
        },
      ]),
    );

    expect(report.summary).toEqual({ passed: 0, failed: 0, unsupported: 2 });
    expect(report.outcome).toBe("partial");
  });

  test("reports parser rejection as failure and closes the provider", async () => {
    const matrix = await import("../../src/local/parse-matrix.js");
    const process = {
      request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
        if (request.operation === "hello") return response(request);
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "rejected",
          implementation: IMPLEMENTATION,
          error: { class: "psbt.parse_failed", message: "rejected fixture" },
        };
      }),
      close: vi.fn(async () => undefined),
    };
    const runtime = provider([
      {
        id: "fixture-parser",
        availability: "available",
        process,
        timeoutMs: 5_000,
        expected: IMPLEMENTATION,
      },
    ]);

    const report = await matrix.runParseMatrix(runtime);

    expect(report.summary.failed).toBe(2);
    expect(report.outcome).toBe("failed");
    expect(runtime.close).toHaveBeenCalledOnce();
  });

  test("restarts after a fixture transport failure and continues later cells", async () => {
    const matrix = await import("../../src/local/parse-matrix.js");
    let failedOnce = false;
    const process = {
      request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
        if (request.operation === "hello") return response(request);
        if (request.operation === "native-parse" && !failedOnce) {
          failedOnce = true;
          throw new Error("adapter emitted malformed JSON");
        }
        return response(request);
      }),
      restart: vi.fn(async () => undefined),
      close: vi.fn(async () => undefined),
    };
    const runtime = provider([
      {
        id: "fixture-parser",
        availability: "available",
        process,
        timeoutMs: 5_000,
        expected: IMPLEMENTATION,
      },
    ]);

    const report = await matrix.runParseMatrix(runtime);

    expect(process.restart).toHaveBeenCalledTimes(1);
    expect(report.summary).toEqual({ passed: 1, failed: 1, unsupported: 0 });
    expect(report.cells.map(({ status }) => status)).toEqual(["failed", "passed"]);
    expect(report.outcome).toBe("failed");
    expect(runtime.close).toHaveBeenCalledOnce();
  });
});
