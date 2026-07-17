import { describe, expect, test } from "vitest";
import { compileUserFixturePlans } from "../../src/custom/fixtures.js";
import type { UserFixtureSpec } from "../../src/custom/manifest.js";

function fixture(id: string): UserFixtureSpec {
  return {
    id,
    inputs: [{ descriptor: "p2wpkh", sequence: 0xffff_fffc }],
    outputs: [
      { descriptor: "p2wpkh", amountSats: 100_000 },
      { descriptor: "p2tr-keypath", remainder: true },
    ],
    feeSats: 15_000,
    locktime: 42,
    transactionVersion: 2,
  };
}

describe("custom fixture compiler", () => {
  test("sorts plans and derives script types from public descriptor templates", () => {
    const plans = compileUserFixturePlans([fixture("z-last"), fixture("a-first")]);

    expect(plans.map(({ id }) => id)).toEqual(["a-first", "z-last"]);
    expect(plans[0]).toMatchObject({
      inputDescriptorIds: ["p2wpkh"],
      outputDescriptorIds: ["p2wpkh", "p2tr-keypath"],
      scriptTypes: ["p2wpkh"],
      outputAmounts: [100_000, null],
      sequences: [0xffff_fffc],
      feeSats: 15_000,
      locktime: 42,
      transactionVersion: 2,
      specSha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    });
  });

  test("produces a stable semantic specification hash", () => {
    const original = fixture("stable");
    const reordered = {
      transactionVersion: 2 as const,
      locktime: 42,
      feeSats: 15_000,
      outputs: [
        { amountSats: 100_000, descriptor: "p2wpkh" as const },
        { remainder: true as const, descriptor: "p2tr-keypath" as const },
      ],
      inputs: [{ sequence: 0xffff_fffc, descriptor: "p2wpkh" as const }],
      id: "stable",
    };

    expect(compileUserFixturePlans([original])[0]?.specSha256).toBe(
      compileUserFixturePlans([reordered])[0]?.specSha256,
    );
  });

  test.each(["happy-path", "p2wpkh", "bdk-finalize-regression"])(
    "rejects collision with built-in fixture id %s",
    (id) => {
      expect(() => compileUserFixturePlans([fixture(id)])).toThrow(/built-in fixture id/i);
    },
  );

  test("requires exactly one remainder output so the requested fee remains exact", () => {
    expect(() =>
      compileUserFixturePlans([
        {
          ...fixture("no-remainder"),
          outputs: [{ descriptor: "p2wpkh", amountSats: 100_000 }],
        },
      ]),
    ).toThrow(/exactly one remainder/i);
  });
});
