import type { AdapterResponse, JsonValue } from "../protocol/types.js";
import { type PsbtDocument, type PsbtDocumentMap, parsePsbtDocument } from "../psbt/document.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const ADAPTER = "rust-psbt-v2";
const TX_MODIFIABLE = 0x06;
const FALLBACK_LOCKTIME = 0x03;
const PREVIOUS_TXID = 0x0e;
const OUTPUT_INDEX = 0x0f;
const SEQUENCE = 0x10;
const REQUIRED_TIME_LOCKTIME = 0x11;
const REQUIRED_HEIGHT_LOCKTIME = 0x12;
const OUTPUT_AMOUNT = 0x03;
const OUTPUT_SCRIPT = 0x04;
const MAX_SEQUENCE = 0xffff_fffe;
const P2WPKH_ZERO = `0014${"00".repeat(20)}`;
const P2WPKH_ONE = `0014${"11".repeat(20)}`;
const FIRST_TXID = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SECOND_TXID = "f0e0d0c0b0a09080706050403020100ffeeddbbccaa998877665544332211000";

const REQUIREMENTS = [
  {
    adapter: ADAPTER,
    operations: ["construct"],
    roles: ["constructor", "updater"],
    psbtVersions: [2],
    features: ["bip370-constructor", "bip370-locktime"],
  },
] as const;

function outputNumber(response: AdapterResponse, key: string): number | undefined {
  if (response.status !== "ok") return undefined;
  const value = response.output[key];
  return typeof value === "number" && Number.isSafeInteger(value) ? value : undefined;
}

function outputString(response: AdapterResponse, key: string): string | undefined {
  if (response.status !== "ok") return undefined;
  const value = response.output[key];
  return typeof value === "string" ? value : undefined;
}

function requiredPsbt(response: AdapterResponse, action: string): string {
  const psbt = outputString(response, "psbt");
  if (!psbt) {
    const detail =
      response.status === "ok"
        ? "missing psbt output"
        : `${response.status}: ${response.error.class}`;
    throw new Error(`${ADAPTER} ${action} failed: ${detail}`);
  }
  return psbt;
}

function mapAt(
  document: PsbtDocument,
  kind: "global" | "input" | "output",
  index = 0,
): PsbtDocumentMap {
  const map = document.maps.find(({ location }) => {
    if (location.kind !== kind) return false;
    return location.kind === "global" || location.index === index;
  });
  if (!map) throw new Error(`PSBTv2 omitted ${kind} map ${index}`);
  return map;
}

function hasFields(map: PsbtDocumentMap, keyTypes: readonly number[]): boolean {
  const present = new Set(map.entries.map(({ keyType }) => keyType));
  return keyTypes.every((keyType) => present.has(keyType));
}

function le32(map: PsbtDocumentMap, keyType: number): number | undefined {
  const entry = map.entries.find(
    (candidate) => candidate.keyType === keyType && candidate.keyData.byteLength === 0,
  );
  return entry?.value.byteLength === 4 ? entry.value.readUInt32LE(0) : undefined;
}

function fieldValue(map: PsbtDocumentMap, keyType: number): Buffer | undefined {
  const matches = map.entries.filter(
    (candidate) => candidate.keyType === keyType && candidate.keyData.byteLength === 0,
  );
  return matches.length === 1 ? matches[0]?.value : undefined;
}

function le64(map: PsbtDocumentMap, keyType: number): bigint | undefined {
  const value = fieldValue(map, keyType);
  return value?.byteLength === 8 ? value.readBigUInt64LE(0) : undefined;
}

function inputMatches(map: PsbtDocumentMap, displayTxid: string, outputIndex: number): boolean {
  const serializedTxid = fieldValue(map, PREVIOUS_TXID);
  return (
    serializedTxid?.equals(Buffer.from(displayTxid, "hex").reverse()) === true &&
    le32(map, OUTPUT_INDEX) === outputIndex
  );
}

function outputMatches(map: PsbtDocumentMap, amountSats: number, scriptHex: string): boolean {
  return (
    le64(map, OUTPUT_AMOUNT) === BigInt(amountSats) &&
    fieldValue(map, OUTPUT_SCRIPT)?.equals(Buffer.from(scriptHex, "hex")) === true
  );
}

function modifiableFlags(document: PsbtDocument): number {
  const entry = mapAt(document, "global").entries.find(
    (candidate) => candidate.keyType === TX_MODIFIABLE && candidate.keyData.byteLength === 0,
  );
  return entry?.value.byteLength === 1 ? (entry.value[0] ?? 0) : 0;
}

function determineLocktime(psbt: string): { value?: number; type?: "none" | "height" | "time" } {
  const document = parsePsbtDocument(psbt);
  const inputs = Array.from({ length: document.inputCount }, (_, index) =>
    mapAt(document, "input", index),
  );
  const locks = inputs.map((input) => ({
    height: le32(input, REQUIRED_HEIGHT_LOCKTIME),
    time: le32(input, REQUIRED_TIME_LOCKTIME),
  }));
  const requiresHeight = locks.some(
    ({ height, time }) => height !== undefined && time === undefined,
  );
  const requiresTime = locks.some(({ height, time }) => time !== undefined && height === undefined);
  if (requiresHeight && requiresTime) return {};
  if (locks.every(({ height, time }) => height === undefined && time === undefined)) {
    const fallback = le32(mapAt(document, "global"), FALLBACK_LOCKTIME) ?? 0;
    return {
      value: fallback,
      type: fallback === 0 ? "none" : fallback < 500_000_000 ? "height" : "time",
    };
  }
  if (requiresTime) {
    return {
      value: Math.max(...locks.flatMap(({ time }) => (time === undefined ? [] : [time]))),
      type: "time",
    };
  }
  return {
    value: Math.max(...locks.flatMap(({ height }) => (height === undefined ? [] : [height]))),
    type: "height",
  };
}

function locktimeEvidence(
  name: string,
  response: AdapterResponse,
  expectedValue: number,
  expectedType: "height" | "time",
): ScenarioAssertionEvidence {
  const psbt = outputString(response, "psbt");
  const derived = psbt ? determineLocktime(psbt) : {};
  const reportedValue = outputNumber(response, "locktime");
  const reportedType = outputString(response, "locktimeType");
  const passed =
    derived.value === expectedValue &&
    derived.type === expectedType &&
    reportedValue === expectedValue &&
    reportedType === expectedType;
  return {
    name,
    passed,
    likelyImplementation: ADAPTER,
    summary: passed
      ? `Serialized BIP370 fields and adapter facts selected ${expectedType} locktime ${expectedValue}`
      : `Expected ${expectedType} locktime ${expectedValue}; derived ${derived.value ?? "conflict"} and adapter reported ${reportedValue ?? "missing"}`,
  };
}

async function construct(
  context: ScenarioExecutionContext,
  payload: Record<string, JsonValue>,
): Promise<AdapterResponse> {
  return context.request(ADAPTER, "construct", payload);
}

function createPayload(fallbackLocktime = 0): Record<string, JsonValue> {
  return {
    action: "create",
    inputsModifiable: true,
    outputsModifiable: true,
    fallbackLocktime,
  };
}

function inputPayload(
  psbt: string,
  previousTxid: string,
  locktime: {
    readonly outputIndex?: number;
    readonly height?: number;
    readonly time?: number;
    readonly sequence?: number;
  } = {},
): Record<string, JsonValue> {
  return {
    action: "add-input",
    psbt,
    previousTxid,
    outputIndex: locktime.outputIndex ?? 0,
    ...(locktime.sequence === undefined ? {} : { sequence: locktime.sequence }),
    ...(locktime.height === undefined ? {} : { requiredHeightLocktime: locktime.height }),
    ...(locktime.time === undefined ? {} : { requiredTimeLocktime: locktime.time }),
  };
}

export function createPsbtv2ConstructorScenario(): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "psbtv2-constructor-workflow",
    title: "PSBTv2 constructor add, remove, update, and seal workflow",
    category: "psbtv2-constructor",
    summary:
      "rust-psbt-v2 creates a modifiable PSBTv2, mutates its maps and counts, then seals both scopes.",
    requirements: REQUIREMENTS,
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const created = await construct(context, createPayload());
      const createdPsbt = requiredPsbt(created, "create");
      const createdDocument = parsePsbtDocument(createdPsbt);
      assertions.push({
        name: "constructor-created-modifiable-psbtv2",
        passed:
          createdDocument.psbtVersion === 2 &&
          createdDocument.inputCount === 0 &&
          createdDocument.outputCount === 0 &&
          modifiableFlags(createdDocument) === 3,
        likelyImplementation: ADAPTER,
      });

      const firstInput = await construct(
        context,
        inputPayload(createdPsbt, FIRST_TXID, { outputIndex: 3 }),
      );
      const firstInputPsbt = requiredPsbt(firstInput, "add-input");
      const firstOutput = await construct(context, {
        action: "add-output",
        psbt: firstInputPsbt,
        amountSats: 50_000,
        scriptHex: P2WPKH_ZERO,
      });
      const firstOutputPsbt = requiredPsbt(firstOutput, "add-output");
      const secondInput = await construct(
        context,
        inputPayload(firstOutputPsbt, SECOND_TXID, { outputIndex: 7 }),
      );
      const secondInputPsbt = requiredPsbt(secondInput, "add-input");
      const secondOutput = await construct(context, {
        action: "add-output",
        psbt: secondInputPsbt,
        amountSats: 40_000,
        scriptHex: P2WPKH_ONE,
      });
      const secondOutputPsbt = requiredPsbt(secondOutput, "add-output");
      const populated = parsePsbtDocument(secondOutputPsbt);
      assertions.push({
        name: "constructor-required-map-fields",
        passed:
          populated.inputCount === 2 &&
          populated.outputCount === 2 &&
          hasFields(mapAt(populated, "input", 0), [PREVIOUS_TXID, OUTPUT_INDEX]) &&
          hasFields(mapAt(populated, "input", 1), [PREVIOUS_TXID, OUTPUT_INDEX]) &&
          hasFields(mapAt(populated, "output", 0), [OUTPUT_AMOUNT, OUTPUT_SCRIPT]) &&
          hasFields(mapAt(populated, "output", 1), [OUTPUT_AMOUNT, OUTPUT_SCRIPT]) &&
          inputMatches(mapAt(populated, "input", 0), FIRST_TXID, 3) &&
          inputMatches(mapAt(populated, "input", 1), SECOND_TXID, 7) &&
          outputMatches(mapAt(populated, "output", 0), 50_000, P2WPKH_ZERO) &&
          outputMatches(mapAt(populated, "output", 1), 40_000, P2WPKH_ONE),
        likelyImplementation: ADAPTER,
      });

      const sequenced = await construct(context, {
        action: "set-sequence",
        psbt: secondOutputPsbt,
        index: 1,
        sequence: MAX_SEQUENCE,
      });
      const sequencedPsbt = requiredPsbt(sequenced, "set-sequence");
      const removedInput = await construct(context, {
        action: "remove-input",
        psbt: sequencedPsbt,
        index: 0,
      });
      const removedInputPsbt = requiredPsbt(removedInput, "remove-input");
      const removedOutput = await construct(context, {
        action: "remove-output",
        psbt: removedInputPsbt,
        index: 0,
      });
      const removedOutputPsbt = requiredPsbt(removedOutput, "remove-output");
      const reduced = parsePsbtDocument(removedOutputPsbt);
      assertions.push(
        {
          name: "constructor-sequence-updated",
          passed: le32(mapAt(reduced, "input", 0), SEQUENCE) === MAX_SEQUENCE,
          likelyImplementation: ADAPTER,
        },
        {
          name: "constructor-counts-after-removal",
          passed:
            reduced.inputCount === 1 &&
            reduced.outputCount === 1 &&
            outputNumber(removedOutput, "inputs") === 1 &&
            outputNumber(removedOutput, "outputs") === 1,
          likelyImplementation: ADAPTER,
        },
        {
          name: "constructor-surviving-data-preserved",
          passed:
            inputMatches(mapAt(reduced, "input", 0), SECOND_TXID, 7) &&
            outputMatches(mapAt(reduced, "output", 0), 40_000, P2WPKH_ONE),
          likelyImplementation: ADAPTER,
        },
      );

      const sealed = await construct(context, {
        action: "seal",
        psbt: removedOutputPsbt,
        scope: "all",
      });
      const sealedPsbt = requiredPsbt(sealed, "seal");
      const sealedDocument = parsePsbtDocument(sealedPsbt);
      assertions.push({
        name: "constructor-scopes-sealed",
        passed: (modifiableFlags(sealedDocument) & 0x03) === 0,
        likelyImplementation: ADAPTER,
      });
      const rejected = await construct(context, inputPayload(sealedPsbt, "33".repeat(32)));
      assertions.push({
        name: "constructor-sealed-mutation-rejected",
        passed: rejected.status === "rejected" && rejected.error.class === "psbt.not_modifiable",
        likelyImplementation: ADAPTER,
      });
      await context.checkpoint("psbtv2-constructor-workflow", "sealed", sealedPsbt);

      return {
        summary: "rust-psbt-v2 completed and sealed a PSBTv2 constructor lifecycle.",
        assertions,
      };
    },
  };
}

export function createPsbtv2LocktimeScenario(): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "psbtv2-locktime-workflow",
    title: "PSBTv2 BIP370 locktime selection workflow",
    category: "psbtv2-constructor",
    summary:
      "rust-psbt-v2 selects fallback, height, time, and dual-domain locktimes and rejects a conflict.",
    requirements: REQUIREMENTS,
    async run(context) {
      const fallbackCreated = await construct(context, createPayload(99));
      const fallback = await construct(
        context,
        inputPayload(requiredPsbt(fallbackCreated, "create"), "44".repeat(32)),
      );

      const heightCreated = await construct(context, createPayload());
      const heightOne = await construct(
        context,
        inputPayload(requiredPsbt(heightCreated, "create"), "55".repeat(32), {
          height: 100,
        }),
      );
      const heightTwo = await construct(
        context,
        inputPayload(requiredPsbt(heightOne, "add-input"), "66".repeat(32), {
          height: 250,
        }),
      );

      const timeCreated = await construct(context, createPayload());
      const timeOne = await construct(
        context,
        inputPayload(requiredPsbt(timeCreated, "create"), "77".repeat(32), {
          time: 500_000_100,
        }),
      );
      const timeTwo = await construct(
        context,
        inputPayload(requiredPsbt(timeOne, "add-input"), "88".repeat(32), {
          time: 500_000_200,
        }),
      );

      const bothCreated = await construct(context, createPayload());
      const bothOne = await construct(
        context,
        inputPayload(requiredPsbt(bothCreated, "create"), "aa".repeat(32), {
          height: 300,
          time: 500_000_300,
        }),
      );
      const bothTwo = await construct(
        context,
        inputPayload(requiredPsbt(bothOne, "add-input"), "bb".repeat(32), {
          height: 350,
          time: 500_000_350,
        }),
      );

      const conflict = await construct(
        context,
        inputPayload(requiredPsbt(heightOne, "add-input"), "99".repeat(32), {
          time: 500_000_100,
        }),
      );
      const assertions: ScenarioAssertionEvidence[] = [
        locktimeEvidence("locktime-fallback-selected", fallback, 99, "height"),
        locktimeEvidence("locktime-maximum-height-selected", heightTwo, 250, "height"),
        locktimeEvidence("locktime-maximum-time-selected", timeTwo, 500_000_200, "time"),
        locktimeEvidence("locktime-height-tie-break-selected", bothTwo, 350, "height"),
        {
          name: "locktime-conflict-rejected",
          passed:
            conflict.status === "rejected" && conflict.error.class === "psbt.locktime_conflict",
          likelyImplementation: ADAPTER,
        },
      ];
      return {
        summary: "rust-psbt-v2 matched the BIP370 locktime selection algorithm.",
        assertions,
      };
    },
  };
}
