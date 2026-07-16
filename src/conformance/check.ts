import { AdapterProcess, type AdapterProcessOptions } from "../protocol/adapter-process.js";
import { parseAdapterHelloCapabilities } from "../protocol/schema.js";
import {
  ADAPTER_PROTOCOL,
  type AdapterHelloCapabilities,
  type AdapterImplementation,
  type AdapterResponse,
  type JsonValue,
} from "../protocol/types.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { assertPsbtTransition } from "../psbt/invariants.js";
import type {
  AdapterManifest,
  ExpectedExternalAdapter,
  ExternalAdapterDefinition,
} from "./manifest.js";

export const ADAPTER_CONFORMANCE_SCHEMA = "psbt-lab.conformance/0.1" as const;
const VALID_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const INVALID_PSBT = "bm90IGEgcHNidA==";

export interface AdapterConformanceCheck {
  readonly name: string;
  readonly passed: boolean;
  readonly detail: string;
}

export interface AdapterConformanceResult {
  readonly id: string;
  readonly passed: boolean;
  readonly implementation?: AdapterImplementation;
  readonly capabilities?: AdapterHelloCapabilities;
  readonly checks: readonly AdapterConformanceCheck[];
}

export interface AdapterConformanceReport {
  readonly schema: typeof ADAPTER_CONFORMANCE_SCHEMA;
  readonly passed: boolean;
  readonly adapters: readonly AdapterConformanceResult[];
}

export interface AdapterConformanceDependencies {
  createProcess(options: AdapterProcessOptions): AdapterProcess;
}

const DEFAULT_DEPENDENCIES: AdapterConformanceDependencies = {
  createProcess: (options) => new AdapterProcess(options),
};

function responseImplementation(response: AdapterResponse): AdapterImplementation {
  return response.implementation;
}

function identityMatches(
  implementation: AdapterImplementation,
  expected: ExpectedExternalAdapter,
): boolean {
  return (
    implementation.name === expected.name &&
    implementation.version === expected.version &&
    implementation.sourceRevision === expected.sourceRevision &&
    (expected.artifactDigest === undefined ||
      implementation.artifactDigest === expected.artifactDigest)
  );
}

async function checkAdapter(
  definition: ExternalAdapterDefinition,
  dependencies: AdapterConformanceDependencies,
  index: number,
): Promise<AdapterConformanceResult> {
  const checks: AdapterConformanceCheck[] = [];
  const process = dependencies.createProcess(definition.process);
  let implementation: AdapterImplementation | undefined;
  let capabilities: AdapterHelloCapabilities | undefined;
  const request = async (
    operation: "hello" | "native-parse" | "roundtrip",
    payload: Record<string, JsonValue>,
  ) =>
    process.request(
      {
        protocol: ADAPTER_PROTOCOL,
        id: `conformance-${index}-${checks.length + 1}`,
        operation,
        payload,
      },
      definition.timeoutMs,
    );

  try {
    const hello = await request("hello", {});
    implementation = responseImplementation(hello);
    const helloPassed = hello.status === "ok";
    checks.push({
      name: "hello",
      passed: helloPassed,
      detail: helloPassed ? "Adapter returned a valid protocol response" : "Adapter rejected hello",
    });
    checks.push({
      name: "identity",
      passed: identityMatches(implementation, definition.expected),
      detail: identityMatches(implementation, definition.expected)
        ? "Implementation identity matches the manifest"
        : "Implementation identity does not match the manifest",
    });
    if (hello.status !== "ok") {
      return { id: definition.id, passed: false, implementation, checks };
    }
    try {
      capabilities = parseAdapterHelloCapabilities(hello.output);
      const baseline =
        capabilities.operations.includes("hello") &&
        capabilities.operations.includes("native-parse") &&
        capabilities.operations.includes("roundtrip") &&
        capabilities.roles.includes("parser");
      checks.push({
        name: "baseline-capabilities",
        passed: baseline,
        detail: baseline
          ? "Adapter declares parser, native-parse, and roundtrip capabilities"
          : "Adapter must declare hello, native-parse, roundtrip, and parser",
      });
      if (!baseline) {
        return { id: definition.id, passed: false, implementation, capabilities, checks };
      }
    } catch (error) {
      checks.push({
        name: "baseline-capabilities",
        passed: false,
        detail: error instanceof Error ? error.message : "Invalid capabilities",
      });
      return { id: definition.id, passed: false, implementation, checks };
    }

    const valid = await request("native-parse", { psbt: VALID_PSBT });
    const validPassed =
      valid.status === "ok" && valid.output["nativeParser"] === implementation.name;
    checks.push({
      name: "native-parse-valid",
      passed: validPassed,
      detail: validPassed
        ? "Native parser accepted the valid PSBT"
        : "Native parser did not accept the valid PSBT",
    });

    const invalid = await request("native-parse", { psbt: INVALID_PSBT });
    const invalidPassed =
      invalid.status === "rejected" && invalid.error.class === "psbt.native_parse_failed";
    checks.push({
      name: "native-parse-invalid",
      passed: invalidPassed,
      detail: invalidPassed
        ? "Native parser rejected malformed PSBT bytes"
        : "Native parser did not reject malformed PSBT bytes with the stable class",
    });

    const roundtrip = await request("roundtrip", { psbt: VALID_PSBT });
    let roundtripPassed = false;
    if (roundtrip.status === "ok" && typeof roundtrip.output["psbt"] === "string") {
      const transition = assertPsbtTransition(
        "roundtrip",
        parsePsbtDocument(VALID_PSBT),
        parsePsbtDocument(roundtrip.output["psbt"]),
      );
      roundtripPassed = transition.ok;
    }
    checks.push({
      name: "roundtrip-preservation",
      passed: roundtripPassed,
      detail: roundtripPassed
        ? "Roundtrip preserved every PSBT field"
        : "Roundtrip changed or rejected the valid PSBT",
    });
  } catch (error) {
    checks.push({
      name: "process",
      passed: false,
      detail: error instanceof Error ? error.message : "Adapter conformance process failed",
    });
  } finally {
    await process.close();
  }
  const passed = checks.length > 0 && checks.every((check) => check.passed);
  return {
    id: definition.id,
    passed,
    ...(implementation === undefined ? {} : { implementation }),
    ...(capabilities === undefined ? {} : { capabilities }),
    checks,
  };
}

export async function runAdapterConformance(
  manifest: AdapterManifest,
  dependencies: AdapterConformanceDependencies = DEFAULT_DEPENDENCIES,
): Promise<AdapterConformanceReport> {
  const adapters: AdapterConformanceResult[] = [];
  for (const [index, definition] of manifest.adapters.entries()) {
    adapters.push(await checkAdapter(definition, dependencies, index + 1));
  }
  return {
    schema: ADAPTER_CONFORMANCE_SCHEMA,
    passed: adapters.length > 0 && adapters.every((adapter) => adapter.passed),
    adapters,
  };
}
