import { FIXTURE_PUBLIC_KEYS } from "../core/fixture-profiles.js";
import type { PsbtFixture } from "../core/fixtures.js";
import { readCompactSize } from "../psbt/compact-size.js";
import { parsePsbtDocument } from "../psbt/document.js";
import type { CorePolicyResult, ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const ROUNDTRIP_CHAIN = ["bdkpython", "rust-bitcoin", "btcsuite-go", "bitcoinjs-lib"] as const;

function coreAssertions(
  complete: boolean,
  hasTransaction: boolean,
  policy: CorePolicyResult,
): ScenarioAssertionEvidence[] {
  return [
    {
      name: "core-finalized",
      passed: complete && hasTransaction,
      summary: complete ? "Core finalized the PSBT" : "Core could not finalize the PSBT",
    },
    {
      name: "core-policy-accepted",
      passed: policy.allowed,
      summary: policy.allowed
        ? "Core accepted the extracted transaction"
        : `Core rejected the transaction${policy.rejectReason ? `: ${policy.rejectReason}` : ""}`,
    },
  ];
}

function partialSignatureEvidence(
  name: string,
  encoded: string,
  expectedPublicKeys: readonly string[],
): ScenarioAssertionEvidence {
  const input = parsePsbtDocument(encoded).maps.find(
    (map) => map.location.kind === "input" && map.location.index === 0,
  );
  const actual = (input?.entries ?? [])
    .filter((entry) => entry.keyType === 0x02)
    .map((entry) => entry.keyData.toString("hex"))
    .sort();
  const expected = [...expectedPublicKeys].sort();
  const passed =
    actual.length === expected.length && actual.every((key, index) => key === expected[index]);
  return {
    name,
    passed,
    summary: passed
      ? `Input 0 contains exactly ${expected.length} expected partial signature${expected.length === 1 ? "" : "s"}`
      : `Input 0 signature keys differ: expected ${expected.join(", ")}, received ${actual.join(", ") || "none"}`,
  };
}

export function exactFieldUnionEvidence(
  sources: readonly string[],
  combined: string,
): ScenarioAssertionEvidence {
  const entries = (encoded: string): Map<string, string> => {
    const output = new Map<string, string>();
    for (const documentMap of parsePsbtDocument(encoded).maps) {
      const location =
        documentMap.location.kind === "global"
          ? "global"
          : `${documentMap.location.kind}:${documentMap.location.index}`;
      for (const entry of documentMap.entries) {
        output.set(`${location}:${entry.completeKey.toString("hex")}`, entry.value.toString("hex"));
      }
    }
    return output;
  };

  try {
    const expected = new Map<string, string>();
    for (const source of sources) {
      for (const [key, value] of entries(source)) {
        const existing = expected.get(key);
        if (existing !== undefined && existing !== value) {
          return {
            name: "combined-exact-field-union",
            passed: false,
            summary: "Signed source copies contain a conflicting value for the same PSBT field",
          };
        }
        expected.set(key, value);
      }
    }
    const actual = entries(combined);
    const passed =
      actual.size === expected.size &&
      [...expected].every(([key, value]) => actual.get(key) === value);
    return {
      name: "combined-exact-field-union",
      passed,
      summary: passed
        ? "Combined PSBT contains exactly the union of both signed source copies"
        : "Combined PSBT is missing a source field or contains a field outside the exact union",
    };
  } catch (error) {
    return {
      name: "combined-exact-field-union",
      passed: false,
      summary: error instanceof Error ? error.message : "Could not compare combined PSBT fields",
    };
  }
}

export function createRoundtripChainScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "four-library-roundtrip-chain",
    title: "Four-library roundtrip and signing chain",
    category: "multi-library-handoff",
    summary:
      "The same PSBT passes through four implementations before signing and Core validation.",
    requirements: [
      ...ROUNDTRIP_CHAIN.map((adapter) => ({
        adapter,
        operations: ["roundtrip"] as const,
        roles: ["parser"] as const,
        psbtVersions: [0] as const,
        scriptTypes: ["p2wsh"] as const,
      })),
      {
        adapter: "bitcoinjs-lib",
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        features: ["fixture-commitment-sha256"],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      await context.checkpoint("four-library-roundtrip-chain", "core-created", fixture.initialPsbt);
      let current = fixture.initialPsbt;
      for (const adapter of ROUNDTRIP_CHAIN) {
        const before = current;
        const response = await context.request(adapter, "roundtrip", { psbt: before });
        current = context.outputString(response, "psbt", "roundtrip");
        assertions.push(
          context.requireTransition("roundtrip", `${adapter}-roundtrip`, before, current, adapter),
        );
      }

      const signResponse = await context.request("bitcoinjs-lib", "sign", {
        psbt: current,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const signed = context.outputString(signResponse, "psbt", "sign");
      assertions.push(
        context.requireTransition(
          "sign",
          "bitcoinjs-lib-signing-transition",
          current,
          signed,
          "bitcoinjs-lib",
        ),
      );
      assertions.push(
        context.requireAddedInputField(
          "bitcoinjs-lib-added-signature",
          current,
          signed,
          [0x02, 0x13, 0x14],
        ),
      );
      await context.checkpoint("four-library-roundtrip-chain", "bitcoinjs-lib-signed", signed);

      const finalized = await context.finalizeWithCore(signed);
      const policy = await context.policyCheck(finalized);
      assertions.push(
        ...coreAssertions(finalized.complete, typeof finalized.hex === "string", policy),
      );
      return {
        summary:
          finalized.complete && policy.allowed
            ? "BDK, rust-bitcoin, btcsuite, and bitcoinjs-lib preserved the PSBT before bitcoinjs-lib signed it and Core accepted it."
            : "The four-library handoff did not end in a complete policy-accepted transaction.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}

export function createParallelCombineScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "parallel-sign-and-combine",
    title: "Parallel rust-bitcoin and btcsuite signing",
    category: "parallel-signing",
    summary:
      "Two libraries sign different inputs on independent copies before bitcoinjs-lib combines their contributions and Core validates them.",
    requirements: [
      {
        adapter: "rust-bitcoin",
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        features: ["fixture-commitment-sha256"],
      },
      {
        adapter: "btcsuite-go",
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        features: ["fixture-commitment-sha256"],
      },
      {
        adapter: "bitcoinjs-lib",
        operations: ["combine"],
        roles: ["combiner"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
      },
    ],
    async run(context) {
      if (fixture.inputCount < 2) {
        throw new Error("Parallel signing requires a fixture with at least two inputs");
      }
      const assertions: ScenarioAssertionEvidence[] = [];
      await context.checkpoint("parallel-sign-and-combine", "core-created", fixture.initialPsbt);
      const signedCopies: string[] = [];

      for (const [inputIndex, adapter] of ["rust-bitcoin", "btcsuite-go"].entries()) {
        const response = await context.request(adapter, "sign", {
          psbt: fixture.initialPsbt,
          network: "regtest",
          fixtureId: fixture.id,
          inputIndexes: [inputIndex],
        });
        const signed = context.outputString(response, "psbt", "sign");
        assertions.push(
          context.requireTransition(
            "sign",
            `${adapter}-signing-transition`,
            fixture.initialPsbt,
            signed,
            adapter,
          ),
        );
        assertions.push(
          context.requireAddedInputField(
            `${adapter}-added-signature`,
            fixture.initialPsbt,
            signed,
            [0x02, 0x13, 0x14],
            [inputIndex],
          ),
        );
        assertions.push(
          context.requireInputFieldAbsence(
            `${adapter}-did-not-sign-other-input`,
            signed,
            [0x02, 0x13, 0x14],
            [inputIndex === 0 ? 1 : 0],
          ),
        );
        signedCopies.push(signed);
      }

      const combineResponse = await context.request("bitcoinjs-lib", "combine", {
        psbts: signedCopies,
      });
      const combined = context.outputString(combineResponse, "psbt", "combine");
      for (const [index, signed] of signedCopies.entries()) {
        assertions.push(
          context.requireTransition(
            "combine",
            `combined-copy-${index + 1}`,
            signed,
            combined,
            "bitcoinjs-lib",
          ),
        );
      }
      assertions.push(
        context.requireAddedInputField(
          "combined-union-of-both-signatures",
          fixture.initialPsbt,
          combined,
          [0x02, 0x13, 0x14],
          [0, 1],
        ),
      );
      assertions.push(exactFieldUnionEvidence(signedCopies, combined));
      await context.checkpoint("parallel-sign-and-combine", "bitcoinjs-lib-combined", combined);

      const finalized = await context.finalizeWithCore(combined);
      const policy = await context.policyCheck(finalized);
      assertions.push(
        ...coreAssertions(finalized.complete, typeof finalized.hex === "string", policy),
      );
      return {
        summary:
          finalized.complete && policy.allowed
            ? "rust-bitcoin signed input 0, btcsuite signed input 1, bitcoinjs-lib preserved both contributions, and Core accepted the result."
            : "The independently signed copies did not combine into a complete policy-accepted transaction.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}

export function createSameInputMultisigScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  const nested = fixture.id === "p2sh-p2wsh-2-of-3";
  const scenarioId = nested ? "nested-p2sh-p2wsh-2-of-3-multisig" : "same-input-2-of-3-multisig";
  const scriptType = nested ? "p2sh-p2wsh" : "p2wsh";
  return {
    id: scenarioId,
    title: nested
      ? "Nested P2SH-P2WSH cross-library 2-of-3 signing"
      : "Cross-library 2-of-3 multisig signing",
    category: "cross-library-multisig",
    summary:
      "Rust and JavaScript add distinct signatures to independent copies of one 2-of-3 input before combining and Core validation.",
    requirements: [
      {
        adapter: "rust-bitcoin",
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: [scriptType],
        features: ["fixture-commitment-sha256"],
      },
      {
        adapter: "bitcoinjs-lib",
        operations: ["sign", "combine"],
        roles: ["signer", "combiner"],
        psbtVersions: [0],
        scriptTypes: [scriptType],
        features: ["fixture-commitment-sha256"],
      },
    ],
    async run(context) {
      if (
        (fixture.id !== "p2wsh-2-of-3" && fixture.id !== "p2sh-p2wsh-2-of-3") ||
        fixture.inputCount !== 1
      ) {
        throw new Error("Same-input multisig requires a single-input 2-of-3 fixture");
      }
      const assertions: ScenarioAssertionEvidence[] = [];
      await context.checkpoint(scenarioId, "core-created", fixture.initialPsbt);

      const rustResponse = await context.request("rust-bitcoin", "sign", {
        psbt: fixture.initialPsbt,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const rustSigned = context.outputString(rustResponse, "psbt", "sign");
      assertions.push(
        context.requireTransition(
          "sign",
          "rust-bitcoin-signing-transition",
          fixture.initialPsbt,
          rustSigned,
          "rust-bitcoin",
        ),
      );
      assertions.push(
        partialSignatureEvidence("rust-bitcoin-added-scalar-1", rustSigned, [
          FIXTURE_PUBLIC_KEYS.scalar1,
        ]),
      );

      const bitcoinjsResponse = await context.request("bitcoinjs-lib", "sign", {
        psbt: fixture.initialPsbt,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const bitcoinjsSigned = context.outputString(bitcoinjsResponse, "psbt", "sign");
      assertions.push(
        context.requireTransition(
          "sign",
          "bitcoinjs-lib-signing-transition",
          fixture.initialPsbt,
          bitcoinjsSigned,
          "bitcoinjs-lib",
        ),
      );
      assertions.push(
        partialSignatureEvidence("bitcoinjs-lib-added-scalar-2", bitcoinjsSigned, [
          FIXTURE_PUBLIC_KEYS.scalar2,
        ]),
      );

      const combineResponse = await context.request("bitcoinjs-lib", "combine", {
        psbts: [rustSigned, bitcoinjsSigned],
      });
      const combined = context.outputString(combineResponse, "psbt", "combine");
      assertions.push(
        context.requireTransition(
          "combine",
          "combined-rust-copy",
          rustSigned,
          combined,
          "bitcoinjs-lib",
        ),
      );
      assertions.push(
        context.requireTransition(
          "combine",
          "combined-bitcoinjs-copy",
          bitcoinjsSigned,
          combined,
          "bitcoinjs-lib",
        ),
      );
      assertions.push(
        partialSignatureEvidence("combined-two-distinct-signatures", combined, [
          FIXTURE_PUBLIC_KEYS.scalar1,
          FIXTURE_PUBLIC_KEYS.scalar2,
        ]),
      );
      assertions.push(exactFieldUnionEvidence([rustSigned, bitcoinjsSigned], combined));
      await context.checkpoint(scenarioId, "combined", combined);

      const finalized = await context.finalizeWithCore(combined);
      const policy = await context.policyCheck(finalized);
      assertions.push(
        ...coreAssertions(finalized.complete, typeof finalized.hex === "string", policy),
      );
      return {
        summary:
          finalized.complete && policy.allowed
            ? "rust-bitcoin and bitcoinjs-lib contributed distinct signatures to one multisig input, and Core accepted the combined transaction."
            : "The independently signed multisig copies did not produce a policy-accepted transaction.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}

export function enrichPsbtWithIntentMetadata(fixture: PsbtFixture): string {
  if (
    fixture.id !== "intent-rich-p2wpkh" ||
    fixture.inputCount !== 1 ||
    fixture.outputCount !== 2
  ) {
    throw new Error("Intent enrichment requires the intent-rich-p2wpkh fixture");
  }
  const document = parsePsbtDocument(fixture.initialPsbt);
  const input = document.maps.find(
    (map) => map.location.kind === "input" && map.location.index === 0,
  );
  if (document.psbtVersion !== 0 || !input) {
    throw new Error("Intent fixture does not contain one valid PSBTv0 input map");
  }

  const encodedEntry = (key: Buffer, value: Buffer): Buffer => {
    if (key.byteLength === 0 || key.byteLength >= 0xfd || value.byteLength >= 0xfd) {
      throw new Error("Intent metadata exceeds the bounded one-byte encoding");
    }
    return Buffer.concat([
      Buffer.from([key.byteLength]),
      key,
      Buffer.from([value.byteLength]),
      value,
    ]);
  };
  const sighash = Buffer.alloc(4);
  sighash.writeUInt32LE(1);
  const derivation = Buffer.from("751e76e8", "hex");
  const sighashEntry = input.entries.find(
    (entry) => entry.keyType === 0x03 && entry.keyData.byteLength === 0,
  );
  const derivationEntry = input.entries.find(
    (entry) =>
      entry.keyType === 0x06 && entry.keyData.toString("hex") === FIXTURE_PUBLIC_KEYS.scalar1,
  );
  if (
    (sighashEntry && !sighashEntry.value.equals(sighash)) ||
    (derivationEntry && !derivationEntry.value.equals(derivation))
  ) {
    throw new Error("Intent fixture contains conflicting signing metadata");
  }
  const additions = Buffer.concat([
    ...(sighashEntry ? [] : [encodedEntry(Buffer.from([0x03]), sighash)]),
    ...(derivationEntry
      ? []
      : [
          encodedEntry(
            Buffer.concat([Buffer.from([0x06]), Buffer.from(FIXTURE_PUBLIC_KEYS.scalar1, "hex")]),
            derivation,
          ),
        ]),
  ]);

  const bytes = Buffer.from(fixture.initialPsbt, "base64");
  const chunks: Buffer[] = [bytes.subarray(0, 5)];
  let offset = 5;
  for (const map of document.maps) {
    let separator = offset;
    while (separator < bytes.byteLength) {
      const keyLength = readCompactSize(bytes, separator);
      if (keyLength.value === 0) break;
      const valueLengthOffset = keyLength.nextOffset + keyLength.value;
      const valueLength = readCompactSize(bytes, valueLengthOffset);
      separator = valueLength.nextOffset + valueLength.value;
    }
    if (separator >= bytes.byteLength) throw new Error("Intent fixture map lacks a separator");
    chunks.push(bytes.subarray(offset, separator));
    if (map.location.kind === "input" && map.location.index === 0) chunks.push(additions);
    chunks.push(Buffer.from([0]));
    offset = separator + 1;
  }
  if (offset !== bytes.byteLength) throw new Error("Intent fixture contains trailing map data");
  const enriched = Buffer.concat(chunks).toString("base64");
  parsePsbtDocument(enriched);
  return enriched;
}

function transactionIntentEvidence(encoded: string): ScenarioAssertionEvidence {
  try {
    const document = parsePsbtDocument(encoded);
    const transaction = document.maps
      .find((map) => map.location.kind === "global")
      ?.entries.find((entry) => entry.keyType === 0x00 && entry.keyData.byteLength === 0)?.value;
    if (!transaction) throw new Error("missing PSBTv0 unsigned transaction");
    let offset = 0;
    const version = transaction.readInt32LE(offset);
    offset += 4;
    const inputCount = readCompactSize(transaction, offset);
    offset = inputCount.nextOffset;
    const sequences: number[] = [];
    for (let index = 0; index < inputCount.value; index += 1) {
      offset += 36;
      const scriptLength = readCompactSize(transaction, offset);
      offset = scriptLength.nextOffset + scriptLength.value;
      sequences.push(transaction.readUInt32LE(offset));
      offset += 4;
    }
    const outputCount = readCompactSize(transaction, offset);
    offset = outputCount.nextOffset;
    for (let index = 0; index < outputCount.value; index += 1) {
      offset += 8;
      const scriptLength = readCompactSize(transaction, offset);
      offset = scriptLength.nextOffset + scriptLength.value;
    }
    const locktime = transaction.readUInt32LE(offset);
    offset += 4;
    const passed =
      document.psbtVersion === 0 &&
      version === 2 &&
      inputCount.value === 1 &&
      sequences.length === 1 &&
      sequences[0] === 0xffff_fffc &&
      outputCount.value === 2 &&
      locktime === 42 &&
      offset === transaction.byteLength;
    return {
      name: "expected-version-locktime-sequence-outputs",
      passed,
      summary: passed
        ? "Transaction version, RBF sequence, two outputs, and non-zero locktime match the intent fixture"
        : "Transaction intent fields do not match the expected deterministic values",
    };
  } catch (error) {
    return {
      name: "expected-version-locktime-sequence-outputs",
      passed: false,
      summary: error instanceof Error ? error.message : "Could not parse transaction intent",
    };
  }
}

function intentMetadataEvidence(encoded: string): ScenarioAssertionEvidence {
  const input = parsePsbtDocument(encoded).maps.find(
    (map) => map.location.kind === "input" && map.location.index === 0,
  );
  const sighash = input?.entries.find(
    (entry) => entry.keyType === 0x03 && entry.keyData.byteLength === 0,
  );
  const derivation = input?.entries.find(
    (entry) =>
      entry.keyType === 0x06 && entry.keyData.toString("hex") === FIXTURE_PUBLIC_KEYS.scalar1,
  );
  const passed =
    sighash?.value.toString("hex") === "01000000" &&
    derivation?.value.toString("hex") === "751e76e8";
  return {
    name: "explicit-sighash-and-derivation",
    passed,
    summary: passed
      ? "Explicit SIGHASH_ALL and deterministic BIP32 derivation metadata are preserved"
      : "Explicit sighash or derivation metadata is missing or changed",
  };
}

export function createTransactionIntentScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  const parsers = ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib"] as const;
  return {
    id: "transaction-intent-preservation",
    title: "Transaction intent preservation",
    category: "transaction-intent",
    summary:
      "Three implementations must preserve multiple outputs, RBF sequence, locktime, sighash, and derivation metadata before signing and Core validation.",
    requirements: parsers.map((adapter) => ({
      adapter,
      operations:
        adapter === "rust-bitcoin" ? (["roundtrip", "sign"] as const) : (["roundtrip"] as const),
      roles: adapter === "rust-bitcoin" ? (["parser", "signer"] as const) : (["parser"] as const),
      psbtVersions: [0] as const,
      scriptTypes: ["p2wpkh"] as const,
      ...(adapter === "rust-bitcoin" ? { features: ["fixture-commitment-sha256"] as const } : {}),
    })),
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const enriched = enrichPsbtWithIntentMetadata(fixture);
      assertions.push(transactionIntentEvidence(enriched), intentMetadataEvidence(enriched));
      await context.checkpoint("transaction-intent-preservation", "intent-enriched", enriched);
      let current = enriched;
      for (const adapter of parsers) {
        const before = current;
        const response = await context.request(adapter, "roundtrip", { psbt: before });
        current = context.outputString(response, "psbt", "roundtrip");
        assertions.push(
          context.requireTransition(
            "roundtrip",
            `${adapter}-preserved-intent`,
            before,
            current,
            adapter,
          ),
        );
      }
      assertions.push(transactionIntentEvidence(current), intentMetadataEvidence(current));

      const signResponse = await context.request("rust-bitcoin", "sign", {
        psbt: current,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const signed = context.outputString(signResponse, "psbt", "sign");
      assertions.push(
        context.requireTransition(
          "sign",
          "rust-bitcoin-signing-transition",
          current,
          signed,
          "rust-bitcoin",
        ),
      );
      assertions.push(
        partialSignatureEvidence("rust-bitcoin-added-intent-signature", signed, [
          FIXTURE_PUBLIC_KEYS.scalar1,
        ]),
        transactionIntentEvidence(signed),
        intentMetadataEvidence(signed),
      );
      await context.checkpoint("transaction-intent-preservation", "signed", signed);

      const finalized = await context.finalizeWithCore(signed);
      const policy = await context.policyCheck(finalized);
      assertions.push(
        ...coreAssertions(finalized.complete, typeof finalized.hex === "string", policy),
      );
      return {
        summary:
          finalized.complete && policy.allowed
            ? "All handoffs preserved the transaction intent and Core accepted the signed transaction."
            : "The intent-rich transaction did not remain complete and policy-accepted.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}
