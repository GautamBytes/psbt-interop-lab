import { describe, expect, test, vi } from "vitest";
import type {
  AdapterImplementation,
  AdapterRequest,
  AdapterResponse,
} from "../../src/protocol/types.js";
import { BIP371_VALID_VECTORS } from "../../src/psbt/bip371-vectors.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { assertPsbtTransition } from "../../src/psbt/invariants.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import {
  acceptsTaprootTreeNormalization,
  createPsbtv2TaprootHandoffScenarios,
} from "../../src/scenarios/psbtv2-taproot.js";

const KEY_PATH_V2 =
  "cHNidP8BAgQCAAAAAQQBAQEFAQEBBgEDAfsEAgAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXAQ4gJ3RKur8wJ/4NbPI6lu7i77GI71IwGVRYWIPmm2YkskIBDwQAAAAAIRb+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMhkAdystp1YAAIABAACAAAAAgAEAAAAAAAAAARcg/jSQZMmNbiqFP6PJsSvYswShnBlcYO+n7iOTBG0/ojIAIgIDa3cqbbdNh1PJioJ5WN5seKszEhCfN9PgMESEJC7Oc9gYdystp1QAAIABAACAAAAAgAAAAAAAAAAAAQMISOYFKgEAAAABBBYAFHaOHutM9CCGYDP4Cs7/D5cgdElpAA==";

function compactSize(value: number): Buffer {
  if (value < 0xfd) return Buffer.from([value]);
  if (value <= 0xffff) {
    const encoded = Buffer.alloc(3);
    encoded[0] = 0xfd;
    encoded.writeUInt16LE(value, 1);
    return encoded;
  }
  throw new Error("Test fixture CompactSize exceeds 16 bits");
}

function serializeEntry(keyType: number, keyData: Buffer, value: Buffer): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  return Buffer.concat([compactSize(key.byteLength), key, compactSize(value.byteLength), value]);
}

function transformOutputTree(
  psbt: string,
  transform: (tree: Buffer) => Buffer | undefined,
): string {
  const document = parsePsbtDocument(psbt);
  const maps = document.maps.map((map) => {
    const entries = map.entries.flatMap((entry) => {
      const value =
        map.location.kind === "output" && entry.keyType === 0x06
          ? transform(Buffer.from(entry.value))
          : Buffer.from(entry.value);
      return value === undefined
        ? []
        : [serializeEntry(entry.keyType, Buffer.from(entry.keyData), value)];
    });
    return Buffer.concat([...entries, Buffer.from([0])]);
  });
  return Buffer.concat([Buffer.from("70736274ff", "hex"), ...maps]).toString("base64");
}

function evidence(before: string, after: string) {
  const result = assertPsbtTransition(
    "roundtrip",
    parsePsbtDocument(before),
    parsePsbtDocument(after),
  );
  return {
    name: "taproot-tree-test",
    passed: result.ok,
    failures: result.failures,
  };
}

function implementation(name: string): AdapterImplementation {
  return {
    name: name === "libwally" ? "libwally-core" : name,
    version: name === "libwally" ? "1.5.4" : "0.1.0",
    sourceRevision: `${name}-test`,
    artifactDigest: `sha256:${(name === "libwally" ? "a" : "b").repeat(64)}`,
  };
}

function response(
  request: AdapterRequest,
  name: string,
  output: Record<string, string | number | boolean>,
): AdapterResponse {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: request.id,
    status: "ok",
    implementation: implementation(name),
    output,
  };
}

function context() {
  const source = BIP371_VALID_VECTORS[0].base64;
  const requests: AdapterRequest[] = [];
  const adapter = (name: "rust-psbt-v2" | "libwally") => ({
    request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
      requests.push(request);
      if (request.operation === "convert") {
        const targetVersion = Number(request.payload["targetVersion"]);
        return response(request, name, {
          psbt: targetVersion === 2 ? KEY_PATH_V2 : source,
          sourceVersion: targetVersion === 2 ? 0 : 2,
          psbtVersion: targetVersion,
        });
      }
      return response(request, name, {
        psbt: String(request.payload["psbt"]),
        psbtVersion: 2,
        byteIdentical: true,
      });
    }),
  });
  return {
    requests,
    value: new ScenarioExecutionContext({
      rpc: { call: vi.fn() } as never,
      artifacts: {
        checkpoint: vi.fn(async (scenario: string, stage: string, psbt: string) => ({
          scenario,
          stage,
          psbtPath: `checkpoints/${scenario}/${stage}.psbt`,
          factsPath: `checkpoints/${scenario}/${stage}.facts.json`,
          facts: extractWireFacts(psbt),
        })),
      },
      adapters: new Map([
        ["rust-psbt-v2", adapter("rust-psbt-v2")],
        ["libwally", adapter("libwally")],
      ]),
      adapterTimeoutMs: 1_000,
    }),
  };
}

describe("PSBTv2 Taproot handoffs", () => {
  test("exports both adapter directions with Taproot capability requirements", () => {
    const scenarios = createPsbtv2TaprootHandoffScenarios();

    expect(scenarios.map(({ id }) => id)).toEqual([
      "psbtv2-taproot-rust-to-libwally",
      "psbtv2-taproot-libwally-to-rust",
    ]);
    expect(scenarios.every(({ category }) => category === "psbtv2-taproot")).toBe(true);
    expect(scenarios.flatMap(({ requirements }) => requirements)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          adapter: "rust-psbt-v2",
          scriptTypes: ["p2tr-keypath", "p2tr-scriptpath"],
        }),
        expect.objectContaining({
          adapter: "libwally",
          scriptTypes: ["p2tr-keypath", "p2tr-scriptpath"],
        }),
      ]),
    );
  });

  test.each(createPsbtv2TaprootHandoffScenarios([BIP371_VALID_VECTORS[0]]))(
    "$id preserves the Taproot fields through conversion and both roundtrips",
    async (scenario) => {
      const execution = context();
      const result = await scenario.run(execution.value);

      expect(result.assertions.every(({ passed }) => passed)).toBe(true);
      expect(execution.requests.map(({ operation }) => operation)).toEqual([
        "convert",
        "roundtrip",
        "roundtrip",
        "convert",
      ]);
    },
  );

  test("accepts only Merkle-equivalent output-tree reordering", () => {
    const original = BIP371_VALID_VECTORS[4].base64;
    const reordered = transformOutputTree(original, (tree) =>
      Buffer.concat([tree.subarray(37, 74), tree.subarray(0, 37), tree.subarray(74)]),
    );
    const changedLeaf = transformOutputTree(original, (tree) => {
      const changed = Buffer.from(tree);
      changed[10] = (changed[10] ?? 0) ^ 0x01;
      return changed;
    });
    const removedTree = transformOutputTree(original, () => undefined);

    expect(
      acceptsTaprootTreeNormalization(evidence(original, reordered), original, reordered),
    ).toBe(true);
    expect(
      acceptsTaprootTreeNormalization(evidence(original, changedLeaf), original, changedLeaf),
    ).toBe(false);
    expect(
      acceptsTaprootTreeNormalization(evidence(original, removedTree), original, removedTree),
    ).toBe(false);
    expect(
      acceptsTaprootTreeNormalization(
        {
          name: "non-tree-change",
          passed: false,
          failures: [
            {
              code: "ENTRY_CHANGED",
              location: { kind: "input", index: 0 },
              keyType: 0x17,
              completeKeySha256: "sha256:test",
              keyBytes: 1,
            },
          ],
        },
        original,
        original,
      ),
    ).toBe(false);
  });
});
