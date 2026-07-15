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

export class ScenarioExecutionContext {
  readonly #rpc: RpcCaller;
  readonly #artifacts: CheckpointWriter;
  readonly #adapters: ReadonlyMap<string, AdapterRequestClient>;
  readonly #adapterTimeoutMs: number;
  readonly #checkpoints: CheckpointRecord[] = [];
  #requestCounter = 0;

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
    return {
      name,
      policy,
      passed: result.ok,
      exactBytesEqual: result.exactBytesEqual,
      failures: result.failures,
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

  async checkpoint(scenario: string, stage: string, psbt: string): Promise<CheckpointRecord> {
    const checkpoint = await this.#artifacts.checkpoint(scenario, stage, psbt);
    this.#checkpoints.push(checkpoint);
    return checkpoint;
  }
}
