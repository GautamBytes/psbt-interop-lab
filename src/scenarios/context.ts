import type { RpcCaller } from "../core/fixtures.js";
import type {
  AdapterOperation,
  AdapterRequest,
  AdapterResponse,
  JsonValue,
} from "../protocol/types.js";
import { ADAPTER_PROTOCOL } from "../protocol/types.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { assertPsbtTransition, type PsbtTransitionPolicy } from "../psbt/invariants.js";
import type { CheckpointRecord } from "../runner/artifacts.js";
import type { ScenarioAssertionEvidence } from "./definition.js";
import { ScenarioAssertionError } from "./engine.js";

export interface AdapterRequestClient {
  request(request: AdapterRequest, timeoutMs: number): Promise<AdapterResponse>;
}

export interface CheckpointWriter {
  checkpoint(scenario: string, stage: string, psbt: string): Promise<CheckpointRecord>;
}

export interface ScenarioExecutionContextOptions {
  readonly rpc: RpcCaller;
  readonly artifacts: CheckpointWriter;
  readonly adapters: ReadonlyMap<string, AdapterRequestClient>;
  readonly adapterTimeoutMs: number;
}

export interface CoreFinalizeResult {
  readonly complete: boolean;
  readonly hex?: string;
}

export interface CoreFinalizePsbtResult {
  readonly complete: boolean;
  readonly psbt?: string;
}

export interface CorePolicyResult {
  readonly allowed: boolean;
  readonly txid?: string;
  readonly rejectReason?: string;
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} returned an invalid object`);
  }
  return value as Record<string, unknown>;
}

function parseFinalizeResult(value: unknown): CoreFinalizeResult {
  const object = asObject(value, "finalizepsbt");
  if (typeof object["complete"] !== "boolean") {
    throw new Error("finalizepsbt omitted its completion status");
  }
  if (object["hex"] !== undefined && typeof object["hex"] !== "string") {
    throw new Error("finalizepsbt returned invalid transaction hex");
  }
  return {
    complete: object["complete"],
    ...(typeof object["hex"] === "string" ? { hex: object["hex"] } : {}),
  };
}

function parseFinalizePsbtResult(value: unknown): CoreFinalizePsbtResult {
  const object = asObject(value, "finalizepsbt");
  if (typeof object["complete"] !== "boolean") {
    throw new Error("finalizepsbt omitted its completion status");
  }
  if (object["psbt"] !== undefined && typeof object["psbt"] !== "string") {
    throw new Error("finalizepsbt returned an invalid finalized PSBT");
  }
  return {
    complete: object["complete"],
    ...(typeof object["psbt"] === "string" ? { psbt: object["psbt"] } : {}),
  };
}

function parsePolicyResult(value: unknown): CorePolicyResult {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new Error("testmempoolaccept returned an unexpected result count");
  }
  const object = asObject(value[0], "testmempoolaccept");
  if (typeof object["allowed"] !== "boolean") {
    throw new Error("testmempoolaccept omitted its policy decision");
  }
  return {
    allowed: object["allowed"],
    ...(typeof object["txid"] === "string" ? { txid: object["txid"] } : {}),
    ...(typeof object["reject-reason"] === "string"
      ? { rejectReason: object["reject-reason"] }
      : {}),
  };
}

export class ScenarioExecutionContext {
  readonly #rpc: RpcCaller;
  readonly #artifacts: CheckpointWriter;
  readonly #adapters: ReadonlyMap<string, AdapterRequestClient>;
  readonly #adapterTimeoutMs: number;
  readonly #checkpoints: CheckpointRecord[] = [];
  #requestCounter = 0;

  #likelyImplementation(name: string): string | undefined {
    const normalized = name.toLowerCase();
    const adapters = [...this.#adapters.keys()].sort((left, right) => right.length - left.length);
    const exact = adapters.find((adapter) => normalized.includes(adapter.toLowerCase()));
    if (exact) return exact;
    const aliases: Readonly<Record<string, string>> = {
      rust: "rust-bitcoin",
      bdk: "bdkpython",
      btcsuite: "btcsuite-go",
      bitcoinjs: "bitcoinjs-lib",
    };
    const prefix = normalized.split("-")[0];
    const aliased = prefix ? aliases[prefix] : undefined;
    if (aliased && this.#adapters.has(aliased)) return aliased;
    return normalized.startsWith("core-") ? "bitcoin-core" : undefined;
  }

  constructor(options: ScenarioExecutionContextOptions) {
    if (!Number.isSafeInteger(options.adapterTimeoutMs) || options.adapterTimeoutMs <= 0) {
      throw new TypeError("Adapter timeout must be a positive safe integer");
    }
    this.#rpc = options.rpc;
    this.#artifacts = options.artifacts;
    this.#adapters = options.adapters;
    this.#adapterTimeoutMs = options.adapterTimeoutMs;
  }

  get rpc(): RpcCaller {
    return this.#rpc;
  }

  get checkpoints(): readonly CheckpointRecord[] {
    return this.#checkpoints;
  }

  async request(
    adapterName: string,
    operation: AdapterOperation,
    payload: Record<string, JsonValue>,
  ): Promise<AdapterResponse> {
    const adapter = this.#adapters.get(adapterName);
    if (!adapter) {
      throw new Error(`Adapter ${adapterName} is not available`);
    }
    this.#requestCounter += 1;
    return adapter.request(
      {
        protocol: ADAPTER_PROTOCOL,
        id: `request-${this.#requestCounter}`,
        operation,
        payload,
      },
      this.#adapterTimeoutMs,
    );
  }

  outputString(response: AdapterResponse, key: string, operation: string): string {
    if (response.status !== "ok") {
      const message = `${response.implementation.name} ${operation} failed: ${response.error.class}: ${response.error.message}`;
      if (response.status === "crashed" || response.status === "timeout") {
        throw new Error(message);
      }
      throw new ScenarioAssertionError(message, [
        {
          name: `${operation}-adapter-response`,
          passed: false,
          summary: `${response.implementation.name} returned ${response.status}`,
        },
      ]);
    }
    const value = response.output[key];
    if (typeof value !== "string") {
      throw new ScenarioAssertionError(
        `${response.implementation.name} omitted string output ${key}`,
        [
          {
            name: `${operation}-adapter-output`,
            passed: false,
            summary: `Missing string output ${key}`,
          },
        ],
      );
    }
    return value;
  }

  transitionEvidence(
    policy: PsbtTransitionPolicy,
    name: string,
    beforePsbt: string,
    afterPsbt: string,
  ): ScenarioAssertionEvidence {
    const result = assertPsbtTransition(
      policy,
      parsePsbtDocument(beforePsbt),
      parsePsbtDocument(afterPsbt),
    );
    const likelyImplementation = this.#likelyImplementation(name);
    return {
      name,
      policy,
      passed: result.ok,
      exactBytesEqual: result.exactBytesEqual,
      failures: result.failures,
      ...(likelyImplementation ? { likelyImplementation } : {}),
    };
  }

  requireTransition(
    policy: PsbtTransitionPolicy,
    name: string,
    beforePsbt: string,
    afterPsbt: string,
  ): ScenarioAssertionEvidence {
    const evidence = this.transitionEvidence(policy, name, beforePsbt, afterPsbt);
    if (!evidence.passed) {
      throw new ScenarioAssertionError(`${name} violated the ${policy} transition policy`, [
        evidence,
      ]);
    }
    return evidence;
  }

  requireAddedInputField(
    name: string,
    beforePsbt: string,
    afterPsbt: string,
    keyTypes: readonly number[],
    inputIndexes?: readonly number[],
  ): ScenarioAssertionEvidence {
    if (
      keyTypes.length === 0 ||
      keyTypes.some((keyType) => !Number.isSafeInteger(keyType) || keyType < 0 || keyType > 0xff)
    ) {
      throw new TypeError("Expected input field types must be non-empty bytes");
    }
    const before = parsePsbtDocument(beforePsbt);
    const after = parsePsbtDocument(afterPsbt);
    const targetIndexes =
      inputIndexes ?? Array.from({ length: after.inputCount }, (_, index) => index);
    if (
      targetIndexes.length === 0 ||
      new Set(targetIndexes).size !== targetIndexes.length ||
      targetIndexes.some(
        (index) => !Number.isSafeInteger(index) || index < 0 || index >= after.inputCount,
      )
    ) {
      throw new TypeError("Expected input indexes must be unique in-range integers");
    }

    const addedAtIndex = (index: number): boolean => {
      const beforeMap = before.maps.find(
        (map) => map.location.kind === "input" && map.location.index === index,
      );
      const afterMap = after.maps.find(
        (map) => map.location.kind === "input" && map.location.index === index,
      );
      if (!afterMap) return false;
      const beforeKeys = new Set(
        (beforeMap?.entries ?? []).map((entry) => entry.completeKey.toString("hex")),
      );
      return afterMap.entries.some(
        (entry) =>
          keyTypes.includes(entry.keyType) && !beforeKeys.has(entry.completeKey.toString("hex")),
      );
    };

    const passed = inputIndexes
      ? targetIndexes.every((index) => addedAtIndex(index))
      : targetIndexes.some((index) => addedAtIndex(index));
    const evidence: ScenarioAssertionEvidence = {
      name,
      passed,
      summary: passed
        ? "Expected input fields were added"
        : "The adapter did not add the expected input fields",
    };
    if (!passed) {
      throw new ScenarioAssertionError(evidence.summary ?? name, [evidence]);
    }
    return evidence;
  }

  requireInputFieldPresence(
    name: string,
    psbt: string,
    keyTypes: readonly number[],
    inputIndexes: readonly number[],
  ): ScenarioAssertionEvidence {
    return this.#requireInputFieldState(name, psbt, keyTypes, inputIndexes, true);
  }

  requireInputFieldAbsence(
    name: string,
    psbt: string,
    keyTypes: readonly number[],
    inputIndexes: readonly number[],
  ): ScenarioAssertionEvidence {
    return this.#requireInputFieldState(name, psbt, keyTypes, inputIndexes, false);
  }

  #requireInputFieldState(
    name: string,
    psbt: string,
    keyTypes: readonly number[],
    inputIndexes: readonly number[],
    expectedPresent: boolean,
  ): ScenarioAssertionEvidence {
    if (
      keyTypes.length === 0 ||
      keyTypes.some((keyType) => !Number.isSafeInteger(keyType) || keyType < 0 || keyType > 0xff)
    ) {
      throw new TypeError("Expected input field types must be non-empty bytes");
    }
    const document = parsePsbtDocument(psbt);
    if (
      inputIndexes.length === 0 ||
      new Set(inputIndexes).size !== inputIndexes.length ||
      inputIndexes.some(
        (index) => !Number.isSafeInteger(index) || index < 0 || index >= document.inputCount,
      )
    ) {
      throw new TypeError("Expected input indexes must be unique in-range integers");
    }
    const matches = inputIndexes.every((index) => {
      const input = document.maps.find(
        (map) => map.location.kind === "input" && map.location.index === index,
      );
      const present = input?.entries.some((entry) => keyTypes.includes(entry.keyType)) ?? false;
      return present === expectedPresent;
    });
    const evidence: ScenarioAssertionEvidence = {
      name,
      passed: matches,
      summary: matches
        ? `Selected inputs have the expected field ${expectedPresent ? "presence" : "absence"}`
        : `Selected inputs do not have the expected field ${expectedPresent ? "presence" : "absence"}`,
    };
    if (!matches) {
      throw new ScenarioAssertionError(evidence.summary ?? name, [evidence]);
    }
    return evidence;
  }

  async checkpoint(scenario: string, stage: string, psbt: string): Promise<CheckpointRecord> {
    const checkpoint = await this.#artifacts.checkpoint(scenario, stage, psbt);
    this.#checkpoints.push(checkpoint);
    return checkpoint;
  }

  async finalizeWithCore(psbt: string): Promise<CoreFinalizeResult> {
    return parseFinalizeResult(
      await this.#rpc.call("finalizepsbt", {
        psbt,
        extract: true,
      }),
    );
  }

  async finalizePsbtWithCore(psbt: string): Promise<CoreFinalizePsbtResult> {
    return parseFinalizePsbtResult(
      await this.#rpc.call("finalizepsbt", {
        psbt,
        extract: false,
      }),
    );
  }

  async policyCheck(finalized: CoreFinalizeResult): Promise<CorePolicyResult> {
    if (!finalized.complete || !finalized.hex) {
      return { allowed: false, rejectReason: "PSBT was not complete" };
    }
    return parsePolicyResult(
      await this.#rpc.call("testmempoolaccept", { rawtxs: [finalized.hex] }),
    );
  }
}
