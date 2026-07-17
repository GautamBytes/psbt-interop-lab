import { describe, expect, test } from "vitest";
import type { PreparedFixtures, PsbtFixture } from "../../src/core/fixtures.js";
import type { NegotiatedAdapter } from "../../src/protocol/types.js";

function fixture(
  id: PsbtFixture["id"],
  scriptType: PsbtFixture["scriptTypes"][number],
): PsbtFixture {
  return {
    id,
    initialPsbt:
      "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=",
    outpoints: [],
    inputCount: 1,
    outputCount: 1,
    feeSats: 1_000,
    scriptTypes: [scriptType],
    inputDescriptors: ["fixture"],
    outputDescriptor: "fixture",
    psbtVersion: 0,
    transactionId: "a".repeat(64),
    psbtSha256: "b".repeat(64),
    unsignedTxSha256: `sha256:${"c".repeat(64)}`,
  };
}

function fixtures(): PreparedFixtures {
  return {
    happy: fixture("happy-path", "p2wsh"),
    profiles: {
      p2wpkh: fixture("p2wpkh", "p2wpkh"),
      "p2wsh-single-key": fixture("p2wsh-single-key", "p2wsh"),
      "p2wsh-2-of-3": fixture("p2wsh-2-of-3", "p2wsh"),
      "p2tr-keypath": fixture("p2tr-keypath", "p2tr-keypath"),
    },
  } as PreparedFixtures;
}

function externalAdapter(registryId = "wallet-alias"): NegotiatedAdapter {
  return {
    registryId,
    implementation: {
      name: "actual-wallet-library",
      version: "2.0.0",
      sourceRevision: "actual-wallet-v2.0.0",
      artifactDigest: `sha256:${"d".repeat(64)}`,
    },
    capabilities: {
      operations: ["hello", "native-parse", "roundtrip", "sign"],
      roles: ["parser", "signer"],
      psbtVersions: [0],
      scriptTypes: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      operationScriptTypes: {
        roundtrip: ["p2wpkh", "p2wsh", "p2tr-keypath"],
        sign: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      },
      features: ["fixture-commitment-sha256"],
    },
  };
}

describe("external adapter matrix scenarios", () => {
  test("adds parse/roundtrip and compatible signing for all three built-in script fixtures", async () => {
    const matrix = await import("../../src/conformance/matrix.js").catch(() => undefined);
    expect(matrix, "the external matrix scenario boundary is missing").toBeDefined();
    if (!matrix) return;

    const definitions = matrix.createExternalAdapterScenarios(
      fixtures(),
      new Map([["wallet-alias", externalAdapter()]]),
    );

    expect(definitions).toHaveLength(6);
    expect(definitions.map(({ category }) => category)).toEqual([
      "external-adapter-roundtrip",
      "external-adapter-signing",
      "external-adapter-roundtrip",
      "external-adapter-signing",
      "external-adapter-roundtrip",
      "external-adapter-signing",
    ]);
    expect(
      definitions.every(({ requirements }) => requirements[0]?.adapter === "wallet-alias"),
    ).toBe(true);
  });

  test("omits signing scenarios when the adapter does not declare compatible signing", async () => {
    const matrix = await import("../../src/conformance/matrix.js").catch(() => undefined);
    expect(matrix, "the external matrix scenario boundary is missing").toBeDefined();
    if (!matrix) return;
    const parser = externalAdapter();
    parser.capabilities.operations = ["hello", "native-parse", "roundtrip"];
    parser.capabilities.roles = ["parser"];
    parser.capabilities.operationScriptTypes = {
      roundtrip: ["p2wpkh", "p2wsh", "p2tr-keypath"],
    };
    parser.capabilities.features = [];

    const definitions = matrix.createExternalAdapterScenarios(
      fixtures(),
      new Map([["wallet-alias", parser]]),
    );

    expect(definitions).toHaveLength(3);
    expect(definitions.every(({ category }) => category === "external-adapter-roundtrip")).toBe(
      true,
    );
  });

  test("keeps generated scenario ids safe for maximum-length manifest ids", async () => {
    const matrix = await import("../../src/conformance/matrix.js").catch(() => undefined);
    expect(matrix, "the external matrix scenario boundary is missing").toBeDefined();
    if (!matrix) return;
    const registryId = "a".repeat(64);

    const definitions = matrix.createExternalAdapterScenarios(
      fixtures(),
      new Map([[registryId, externalAdapter(registryId)]]),
    );

    expect(new Set(definitions.map(({ id }) => id)).size).toBe(definitions.length);
    expect(definitions.every(({ id }) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id))).toBe(true);
  });
});
