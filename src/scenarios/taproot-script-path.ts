import type { PsbtFixture } from "../core/fixtures.js";
import type { AdapterOperation } from "../protocol/types.js";
import { readCompactSize } from "../psbt/compact-size.js";
import { type PsbtMapLocation, parsePsbtDocument } from "../psbt/document.js";
import type { ScenarioExecutionContext } from "./context.js";
import type {
  ScenarioAssertionEvidence,
  ScenarioDefinition,
  ScenarioFinding,
} from "./definition.js";

const TAPROOT_SCRIPT_SIGNATURE = 0x14;
const TAPROOT_LEAF_SCRIPT = 0x15;
const TAPROOT_BIP32_DERIVATION = 0x16;
const TAPROOT_OUTPUT_BIP32_DERIVATION = 0x07;
const TAPROOT_INTERNAL_KEY = 0x17;
const TAPROOT_MERKLE_ROOT = 0x18;
const FINAL_SCRIPT_WITNESS = 0x08;
const SCALAR_TWO_XONLY = Buffer.from(
  "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  "hex",
);

interface HandoffDirection {
  readonly id: string;
  readonly title: string;
  readonly signer: "rust-bitcoin" | "bdk-wallet-current";
  readonly finalizer: "rust-bitcoin" | "bdk-wallet-current";
  readonly finalizeOperation: "finalize" | "finalize-inputs";
}

interface MutableEntry {
  readonly keyType: number;
  readonly keyData: Buffer;
  readonly value: Buffer;
}

const DIRECTIONS: readonly HandoffDirection[] = [
  {
    id: "taproot-scriptpath-rust-to-bdk",
    title: "Taproot script-path rust-bitcoin to BDK handoff",
    signer: "rust-bitcoin",
    finalizer: "bdk-wallet-current",
    finalizeOperation: "finalize",
  },
  {
    id: "taproot-scriptpath-bdk-to-rust",
    title: "Taproot script-path BDK to rust-bitcoin handoff",
    signer: "bdk-wallet-current",
    finalizer: "rust-bitcoin",
    finalizeOperation: "finalize-inputs",
  },
];

function assertFixture(fixture: PsbtFixture): void {
  if (
    fixture.id !== "p2tr-scriptpath" ||
    fixture.inputCount < 1 ||
    fixture.scriptTypes.some((scriptType) => scriptType !== "p2tr-scriptpath")
  ) {
    throw new TypeError("Taproot script-path scenarios require the p2tr-scriptpath fixture");
  }
}

function finalizePayload(
  fixture: PsbtFixture,
  psbt: string,
  operation: HandoffDirection["finalizeOperation"],
): Record<string, string | number[]> {
  return {
    psbt,
    network: "regtest",
    fixtureId: fixture.id,
    ...(operation === "finalize-inputs"
      ? { inputIndexes: Array.from({ length: fixture.inputCount }, (_, index) => index) }
      : {}),
  };
}

function decodeWitness(value: Buffer): readonly Buffer[] {
  const count = readCompactSize(value, 0);
  if (count.value !== 3) throw new TypeError("Taproot script-path witness must have three items");
  const items: Buffer[] = [];
  let offset = count.nextOffset;
  for (let index = 0; index < count.value; index += 1) {
    const length = readCompactSize(value, offset);
    offset = length.nextOffset;
    if (length.value > value.byteLength - offset) {
      throw new TypeError("Taproot script-path witness item is truncated");
    }
    items.push(Buffer.from(value.subarray(offset, offset + length.value)));
    offset += length.value;
  }
  if (offset !== value.byteLength)
    throw new TypeError("Taproot script-path witness has trailing data");
  return items;
}

function requireExactScriptPathWitness(
  name: string,
  fixturePsbt: string,
  finalizedPsbt: string,
  inputIndexes: readonly number[],
): ScenarioAssertionEvidence {
  try {
    const fixture = parsePsbtDocument(fixturePsbt);
    const finalized = parsePsbtDocument(finalizedPsbt);
    for (const index of inputIndexes) {
      const fixtureInput = fixture.maps.find(
        ({ location }) => location.kind === "input" && location.index === index,
      );
      const finalizedInput = finalized.maps.find(
        ({ location }) => location.kind === "input" && location.index === index,
      );
      const leaves = fixtureInput?.entries.filter(({ keyType }) => keyType === TAPROOT_LEAF_SCRIPT);
      const witnesses = finalizedInput?.entries.filter(
        ({ keyType }) => keyType === FINAL_SCRIPT_WITNESS,
      );
      if (leaves?.length !== 1 || witnesses?.length !== 1) {
        throw new TypeError("Expected one committed leaf and one final witness");
      }
      const leaf = leaves[0];
      const finalWitness = witnesses[0];
      if (!leaf || !finalWitness) {
        throw new TypeError("Expected one committed leaf and one final witness");
      }
      const witness = decodeWitness(Buffer.from(finalWitness.value));
      const expectedScript = leaf.value.subarray(0, -1);
      if (
        witness[0]?.byteLength !== 64 ||
        !witness[1]?.equals(expectedScript) ||
        !witness[2]?.equals(leaf.keyData)
      ) {
        throw new TypeError("Final witness is not the committed default-sighash script path");
      }
    }
    return {
      name,
      passed: true,
      summary: "Final witness uses the exact committed Taproot leaf script and control block",
    };
  } catch (error) {
    return {
      name,
      passed: false,
      summary: error instanceof Error ? error.message : "Final script-path witness is invalid",
    };
  }
}

function createHandoffScenario(
  fixture: PsbtFixture,
  direction: HandoffDirection,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: direction.id,
    title: direction.title,
    category: "taproot-scriptpath",
    summary: `${direction.signer} signs the deterministic Taproot leaf and ${direction.finalizer} finalizes and returns the PSBT.`,
    requirements: [
      {
        adapter: direction.signer,
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: ["p2tr-scriptpath"],
        features: ["fixture-commitment-sha256"],
      },
      {
        adapter: direction.finalizer,
        operations: [direction.finalizeOperation],
        roles: ["finalizer"],
        psbtVersions: [0],
        scriptTypes: ["p2tr-scriptpath"],
        features: ["fixture-commitment-sha256"],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const findings: ScenarioFinding[] = [];
      await context.checkpoint(direction.id, "core-created", fixture.initialPsbt);

      const signResponse = await context.request(direction.signer, "sign", {
        psbt: fixture.initialPsbt,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const signedPsbt = context.outputString(signResponse, "psbt", "sign");
      assertions.push(
        context.requireTransition(
          "sign",
          `${direction.signer}-preserved-bip371-while-signing`,
          fixture.initialPsbt,
          signedPsbt,
          direction.signer,
        ),
      );
      assertions.push(
        context.requireAddedInputField(
          `${direction.signer}-added-leaf-signature`,
          fixture.initialPsbt,
          signedPsbt,
          [TAPROOT_SCRIPT_SIGNATURE],
          Array.from({ length: fixture.inputCount }, (_, index) => index),
        ),
      );
      await context.checkpoint(direction.id, `${direction.signer}-signed`, signedPsbt);

      const finalizeResponse = await context.request(
        direction.finalizer,
        direction.finalizeOperation,
        finalizePayload(fixture, signedPsbt, direction.finalizeOperation),
      );
      const finalizedPsbt = context.outputString(
        finalizeResponse,
        "psbt",
        direction.finalizeOperation,
      );
      const finalizationTransition = context.transitionEvidence(
        "finalize",
        `${direction.finalizer}-finalization-transition`,
        signedPsbt,
        finalizedPsbt,
        direction.finalizer,
      );
      const bdkRemovedOnlyOutputOrigins =
        direction.finalizer === "bdk-wallet-current" &&
        finalizationTransition.failures !== undefined &&
        finalizationTransition.failures.length > 0 &&
        finalizationTransition.failures.every(
          (failure) =>
            failure.code === "ENTRY_REMOVED" &&
            failure.location.kind === "output" &&
            failure.keyType === TAPROOT_OUTPUT_BIP32_DERIVATION,
        );
      if (bdkRemovedOnlyOutputOrigins) {
        assertions.push({
          name: "bdk-finalization-output-origin-divergence-recorded",
          passed: true,
          likelyImplementation: "bdk-wallet-current",
          summary:
            "BDK finalized the script path but removed Taproot output key-origin metadata; the lab kept the loss visible as a bounded compatibility finding",
        });
        findings.push({
          id: "bdk-taproot-finalize-removes-output-origins",
          implementation: "bdk-wallet-current",
          summary:
            "Finalization removed PSBT_OUT_TAP_BIP32_DERIVATION entries even though the transaction and exact script-path witness remained valid.",
        });
      } else {
        assertions.push(finalizationTransition);
      }
      const inputIndexes = Array.from({ length: fixture.inputCount }, (_, index) => index);
      assertions.push(
        context.requireInputFieldPresence(
          `${direction.finalizer}-returned-final-witness`,
          finalizedPsbt,
          [FINAL_SCRIPT_WITNESS],
          inputIndexes,
        ),
      );
      assertions.push(
        requireExactScriptPathWitness(
          `${direction.finalizer}-returned-exact-script-path-witness`,
          fixture.initialPsbt,
          finalizedPsbt,
          inputIndexes,
        ),
      );
      assertions.push(
        context.requireInputFieldAbsence(
          `${direction.finalizer}-removed-taproot-signing-metadata`,
          finalizedPsbt,
          [
            TAPROOT_SCRIPT_SIGNATURE,
            TAPROOT_LEAF_SCRIPT,
            TAPROOT_BIP32_DERIVATION,
            TAPROOT_INTERNAL_KEY,
            TAPROOT_MERKLE_ROOT,
          ],
          inputIndexes,
        ),
      );
      await context.checkpoint(direction.id, `${direction.finalizer}-finalized`, finalizedPsbt);

      const extracted = await context.finalizeWithCore(finalizedPsbt);
      const policy = await context.policyCheck(extracted);
      assertions.push({
        name: "core-extracted-finalized-psbt",
        passed: extracted.complete && typeof extracted.hex === "string",
        summary: extracted.complete
          ? "Core extracted the adapter-finalized transaction"
          : "Core could not extract the adapter-finalized transaction",
      });
      assertions.push({
        name: "core-policy-accepted",
        passed: policy.allowed,
        summary: policy.allowed
          ? "Core accepted the script-path transaction under regtest policy"
          : `Core rejected the transaction${policy.rejectReason ? `: ${policy.rejectReason}` : ""}`,
      });

      return {
        summary: `${direction.signer} signed and ${direction.finalizer} finalized the Taproot script path.`,
        assertions,
        ...(findings.length > 0 ? { findings } : {}),
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}

export function createTaprootScriptPathHandoffScenarios(
  fixture: PsbtFixture,
): readonly ScenarioDefinition<ScenarioExecutionContext>[] {
  assertFixture(fixture);
  return DIRECTIONS.map((direction) => createHandoffScenario(fixture, direction));
}

function encodeCompactSize(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("Invalid CompactSize value");
  if (value < 0xfd) return Buffer.from([value]);
  if (value <= 0xffff) {
    const encoded = Buffer.alloc(3);
    encoded[0] = 0xfd;
    encoded.writeUInt16LE(value, 1);
    return encoded;
  }
  if (value <= 0xffff_ffff) {
    const encoded = Buffer.alloc(5);
    encoded[0] = 0xfe;
    encoded.writeUInt32LE(value, 1);
    return encoded;
  }
  const encoded = Buffer.alloc(9);
  encoded[0] = 0xff;
  encoded.writeBigUInt64LE(BigInt(value), 1);
  return encoded;
}

function serializeEntry(entry: MutableEntry): Buffer {
  const key = Buffer.concat([Buffer.from([entry.keyType]), entry.keyData]);
  return Buffer.concat([
    encodeCompactSize(key.byteLength),
    key,
    encodeCompactSize(entry.value.byteLength),
    entry.value,
  ]);
}

function mutatePsbt(
  psbt: string,
  transform: (entry: MutableEntry, location: PsbtMapLocation) => MutableEntry | undefined,
): string {
  const document = parsePsbtDocument(psbt);
  const maps = document.maps.map((map) => {
    const entries = map.entries.flatMap((entry) => {
      const transformed = transform(
        {
          keyType: entry.keyType,
          keyData: Buffer.from(entry.keyData),
          value: Buffer.from(entry.value),
        },
        map.location,
      );
      return transformed ? [serializeEntry(transformed)] : [];
    });
    return Buffer.concat([...entries, Buffer.from([0])]);
  });
  return Buffer.concat([Buffer.from("70736274ff", "hex"), ...maps]).toString("base64");
}

export interface TaprootScriptPathCanary {
  readonly id: "wrong-leaf" | "wrong-control-block" | "dropped-leaf-metadata";
  readonly psbt: string;
}

export function createTaprootScriptPathCanaries(
  fixture: PsbtFixture,
): readonly TaprootScriptPathCanary[] {
  assertFixture(fixture);
  const targetLeaf = (entry: MutableEntry, location: PsbtMapLocation): boolean =>
    location.kind === "input" && location.index === 0 && entry.keyType === TAPROOT_LEAF_SCRIPT;
  const wrongLeaf = mutatePsbt(fixture.initialPsbt, (entry, location) => {
    if (!targetLeaf(entry, location) || entry.value.byteLength < 2) return entry;
    const value = Buffer.from(entry.value);
    value[value.byteLength - 2] = (value[value.byteLength - 2] as number) ^ 0x01;
    return { ...entry, value };
  });
  const wrongControlBlock = mutatePsbt(fixture.initialPsbt, (entry, location) => {
    if (!targetLeaf(entry, location) || entry.keyData.byteLength < 33) return entry;
    const keyData = Buffer.from(entry.keyData);
    SCALAR_TWO_XONLY.copy(keyData, 1);
    return { ...entry, keyData };
  });
  const droppedLeafMetadata = mutatePsbt(fixture.initialPsbt, (entry, location) =>
    targetLeaf(entry, location) ? undefined : entry,
  );
  return [
    { id: "wrong-leaf", psbt: wrongLeaf },
    { id: "wrong-control-block", psbt: wrongControlBlock },
    { id: "dropped-leaf-metadata", psbt: droppedLeafMetadata },
  ];
}

export function createTaprootScriptPathCanaryScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  const adapters = ["rust-bitcoin", "bdk-wallet-current"] as const;
  const canaries = createTaprootScriptPathCanaries(fixture);
  return {
    id: "taproot-scriptpath-negative-canaries",
    title: "Taproot script-path metadata rejection canaries",
    category: "taproot-scriptpath",
    summary:
      "Both native signers reject a wrong leaf, wrong control block, and dropped leaf metadata.",
    requirements: adapters.map((adapter) => ({
      adapter,
      operations: ["sign"] as readonly AdapterOperation[],
      roles: ["signer"] as const,
      psbtVersions: [0] as const,
      scriptTypes: ["p2tr-scriptpath"] as const,
      features: ["fixture-commitment-sha256"] as const,
    })),
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      for (const adapter of adapters) {
        for (const canary of canaries) {
          const response = await context.request(adapter, "sign", {
            psbt: canary.psbt,
            network: "regtest",
            fixtureId: fixture.id,
          });
          const passed =
            response.status === "rejected" && response.error.class === "policy.psbt_not_authorized";
          assertions.push({
            name: `${adapter}-rejected-${canary.id}`,
            passed,
            likelyImplementation: adapter,
            summary: passed
              ? `${adapter} rejected the malformed BIP371 metadata`
              : `${adapter} did not reject the malformed BIP371 metadata as policy`,
          });
        }
      }
      return { assertions };
    },
  };
}
