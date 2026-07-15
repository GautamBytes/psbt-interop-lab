import type {
  AdapterOperation,
  AdapterRole,
  AdapterScriptType,
  PsbtVersion,
} from "../protocol/types.js";
import type { PsbtTransitionFailure, PsbtTransitionPolicy } from "../psbt/invariants.js";

export type ScenarioOutcome = "passed" | "failed" | "unsupported" | "skipped";

export interface AdapterCapabilityRequirement {
  readonly adapter: string;
  readonly operations?: readonly AdapterOperation[];
  readonly roles?: readonly AdapterRole[];
  readonly psbtVersions?: readonly PsbtVersion[];
  readonly scriptTypes?: readonly AdapterScriptType[];
  readonly features?: readonly string[];
}

export interface ScenarioAssertionEvidence {
  readonly name: string;
  readonly passed: boolean;
  readonly policy?: PsbtTransitionPolicy;
  readonly exactBytesEqual?: boolean;
  readonly failures?: readonly PsbtTransitionFailure[];
  readonly summary?: string;
}

export interface ScenarioExecutionOutput {
  readonly summary?: string;
  readonly assertions: readonly ScenarioAssertionEvidence[];
  readonly expectedFailure?: {
    readonly implementation: string;
    readonly errorClass: string;
  };
  readonly policyAccepted?: boolean;
  readonly transactionId?: string;
}

export interface ScenarioDefinition<Context> {
  readonly id: string;
  readonly title: string;
  readonly category: string;
  readonly summary: string;
  readonly requirements: readonly AdapterCapabilityRequirement[];
  readonly skip?: (context: Context) => string | undefined | Promise<string | undefined>;
  readonly run: (context: Context) => Promise<ScenarioExecutionOutput>;
}

export type MissingCapabilityKind =
  | "adapter"
  | "identity"
  | "operation"
  | "role"
  | "psbtVersion"
  | "scriptType"
  | "feature";

export interface MissingCapability {
  readonly adapter: string;
  readonly kind: MissingCapabilityKind;
  readonly value: string | number;
}

export interface ScenarioResult extends ScenarioExecutionOutput {
  readonly id: string;
  readonly title: string;
  readonly category: string;
  readonly outcome: ScenarioOutcome;
  readonly summary: string;
  readonly durationMs: number;
  readonly missingCapabilities?: readonly MissingCapability[];
  readonly skipReason?: string;
}
