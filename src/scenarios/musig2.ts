import { FIXTURE_PUBLIC_KEYS, MUSIG2_AGGREGATE_PUBLIC_KEY } from "../core/fixture-profiles.js";
import type { PsbtFixture } from "../core/fixtures.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { applyPsbtMutations } from "../psbt/mutation.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

export const MUSIG2_SIGNER_ONE = "musig2-rust-signer-1";
export const MUSIG2_SIGNER_TWO = "musig2-rust-signer-2";

const PARTICIPANT_FIELD = 0x1a;
const PUBLIC_NONCE_FIELD = 0x1b;
const PARTIAL_SIGNATURE_FIELD = 0x1c;
const TAP_KEY_SIGNATURE_FIELD = 0x13;

export function initializeBip373ParticipantFields(psbt: string): string {
  return applyPsbtMutations(psbt, [
    {
      kind: "set-entry",
      location: { kind: "input", index: 0 },
      keyType: PARTICIPANT_FIELD,
      keyDataHex: MUSIG2_AGGREGATE_PUBLIC_KEY,
      valueHex: `${FIXTURE_PUBLIC_KEYS.scalar1}${FIXTURE_PUBLIC_KEYS.scalar2}`,
    },
  ]);
}

function countInputFields(psbt: string, keyType: number): number {
  const input = parsePsbtDocument(psbt).maps.find(
    (map) => map.location.kind === "input" && map.location.index === 0,
  );
  return input?.entries.filter((entry) => entry.keyType === keyType).length ?? 0;
}

function fieldCountEvidence(
  name: string,
  psbt: string,
  keyType: number,
  expected: number,
): ScenarioAssertionEvidence {
  const actual = countInputFields(psbt, keyType);
  return {
    name,
    passed: actual === expected,
    summary: `Expected ${expected} field(s) of type 0x${keyType.toString(16)}; observed ${actual}.`,
  };
}

function requireOk(
  context: ScenarioExecutionContext,
  response: Awaited<ReturnType<ScenarioExecutionContext["request"]>>,
  operation: string,
): string {
  return context.outputString(response, "psbt", operation);
}

async function preserveBip373Fields(
  context: ScenarioExecutionContext,
  assertions: ScenarioAssertionEvidence[],
  psbt: string,
  stage: string,
): Promise<string> {
  const rustRoundtrip = requireOk(
    context,
    await context.request("rust-bitcoin", "roundtrip", { psbt }),
    "roundtrip",
  );
  assertions.push(
    context.requireTransition(
      "roundtrip",
      `rust-bitcoin-preserved-bip373-${stage}`,
      psbt,
      rustRoundtrip,
      "rust-bitcoin",
    ),
  );
  const bitcoinjsRoundtrip = requireOk(
    context,
    await context.request("bitcoinjs-lib", "roundtrip", { psbt: rustRoundtrip }),
    "roundtrip",
  );
  assertions.push(
    context.requireTransition(
      "roundtrip",
      `bitcoinjs-preserved-bip373-${stage}`,
      rustRoundtrip,
      bitcoinjsRoundtrip,
      "bitcoinjs-lib",
    ),
  );
  return bitcoinjsRoundtrip;
}

export function createMusig2Scenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "bip373-musig2-keypath",
    title: "BIP373 MuSig2 nonce exchange and Taproot finalization",
    category: "musig2",
    summary:
      "Preserves BIP373 fields across independent parsers, completes both MuSig2 rounds, verifies partial signatures, and proves the aggregate spend with Bitcoin Core.",
    requirements: [
      {
        adapter: "rust-bitcoin",
        operations: ["roundtrip"],
        roles: ["parser"],
        psbtVersions: [0],
        scriptTypes: ["p2tr-keypath"],
      },
      {
        adapter: "bitcoinjs-lib",
        operations: ["roundtrip"],
        roles: ["parser"],
        psbtVersions: [0],
        scriptTypes: ["p2tr-keypath"],
      },
      ...([MUSIG2_SIGNER_ONE, MUSIG2_SIGNER_TWO] as const).map((adapter) => ({
        adapter,
        operations: [
          "roundtrip",
          "musig2-nonce",
          "musig2-partial-sign",
          "musig2-aggregate",
        ] as const,
        roles: ["parser", "updater", "signer", "combiner", "finalizer"] as const,
        psbtVersions: [0] as const,
        scriptTypes: ["p2tr-keypath"] as const,
        features: [
          "bip373-musig2-v1",
          "bip327-csprng-nonce-v1",
          "fixture-commitment-sha256",
          "network-free",
        ] as const,
      })),
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const participantPsbt = initializeBip373ParticipantFields(fixture.initialPsbt);
      await context.checkpoint("bip373-musig2-keypath", "participants", participantPsbt);
      assertions.push(
        fieldCountEvidence("participant-set-added", participantPsbt, PARTICIPANT_FIELD, 1),
      );

      const bitcoinjsRoundtrip = await preserveBip373Fields(
        context,
        assertions,
        participantPsbt,
        "participants",
      );

      const sessionId = `musig2-${fixture.unsignedTxSha256.slice(7, 23)}`;
      const nonceOne = requireOk(
        context,
        await context.request(MUSIG2_SIGNER_ONE, "musig2-nonce", {
          psbt: bitcoinjsRoundtrip,
          fixtureId: fixture.id,
          sessionId,
        }),
        "musig2-nonce",
      );
      const reuse = await context.request(MUSIG2_SIGNER_ONE, "musig2-nonce", {
        psbt: nonceOne,
        fixtureId: fixture.id,
        sessionId,
      });
      assertions.push({
        name: "secret-nonce-reuse-refused",
        passed: reuse.status === "rejected" && reuse.error.class === "musig2.nonce_reuse",
        likelyImplementation: MUSIG2_SIGNER_ONE,
        summary:
          reuse.status === "rejected"
            ? `Repeated session was rejected as ${reuse.error.class}.`
            : `Repeated session returned ${reuse.status}.`,
      });
      const nonceTwo = requireOk(
        context,
        await context.request(MUSIG2_SIGNER_TWO, "musig2-nonce", {
          psbt: nonceOne,
          fixtureId: fixture.id,
          sessionId,
        }),
        "musig2-nonce",
      );
      const preservedNonces = await preserveBip373Fields(
        context,
        assertions,
        nonceTwo,
        "public-nonces",
      );
      await context.checkpoint(
        "bip373-musig2-keypath",
        "public-nonces",
        preservedNonces,
        "structure",
      );
      assertions.push(
        fieldCountEvidence("complete-public-nonce-set", preservedNonces, PUBLIC_NONCE_FIELD, 2),
      );

      const partialOne = requireOk(
        context,
        await context.request(MUSIG2_SIGNER_ONE, "musig2-partial-sign", {
          psbt: preservedNonces,
          fixtureId: fixture.id,
          sessionId,
        }),
        "musig2-partial-sign",
      );
      const partialTwo = requireOk(
        context,
        await context.request(MUSIG2_SIGNER_TWO, "musig2-partial-sign", {
          psbt: partialOne,
          fixtureId: fixture.id,
          sessionId,
        }),
        "musig2-partial-sign",
      );
      const preservedPartials = await preserveBip373Fields(
        context,
        assertions,
        partialTwo,
        "partial-signatures",
      );
      await context.checkpoint(
        "bip373-musig2-keypath",
        "partial-signatures",
        preservedPartials,
        "structure",
      );
      assertions.push(
        fieldCountEvidence(
          "complete-partial-signature-set",
          preservedPartials,
          PARTIAL_SIGNATURE_FIELD,
          2,
        ),
      );

      const aggregated = requireOk(
        context,
        await context.request(MUSIG2_SIGNER_ONE, "musig2-aggregate", {
          psbt: preservedPartials,
          fixtureId: fixture.id,
        }),
        "musig2-aggregate",
      );
      await context.checkpoint(
        "bip373-musig2-keypath",
        "aggregate-signature",
        aggregated,
        "structure",
      );
      assertions.push(
        fieldCountEvidence(
          "aggregate-taproot-key-signature",
          aggregated,
          TAP_KEY_SIGNATURE_FIELD,
          1,
        ),
      );

      const finalized = await context.finalizeWithCore(aggregated);
      const policy = await context.policyCheck(finalized);
      assertions.push({
        name: "core-accepted-musig2-transaction",
        passed: finalized.complete && policy.allowed,
        summary: policy.allowed
          ? "Bitcoin Core finalized and accepted the MuSig2 transaction."
          : `Bitcoin Core rejected the MuSig2 transaction: ${policy.rejectReason ?? "unknown reason"}.`,
      });
      return {
        summary:
          "BIP373 participant, nonce, and partial-signature fields survived the handoffs and produced a Core-accepted aggregate Taproot spend.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}
