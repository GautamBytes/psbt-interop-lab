import { describe, expect, test } from "vitest";
import { minimizeMutationRecipes } from "../../src/psbt/minimize.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../../src/psbt/mutation.js";

const PSBT =
  "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";

describe("minimizeMutationRecipes", () => {
  test("removes operations that are not needed to preserve the predicate", async () => {
    const recipes: PsbtMutationRecipe[] = [
      { kind: "append-bytes", valueHex: "00" },
      { kind: "append-bytes", valueHex: "deadbeef" },
      { kind: "append-bytes", valueHex: "00" },
    ];

    const minimized = await minimizeMutationRecipes(PSBT, recipes, async (mutated) =>
      Buffer.from(mutated, "base64").includes(Buffer.from("deadbeef", "hex")),
    );

    expect(minimized).toEqual([{ kind: "append-bytes", valueHex: "deadbeef" }]);
    expect(
      await Promise.resolve(Buffer.from(applyPsbtMutations(PSBT, minimized), "base64")),
    ).toEqual(expect.any(Buffer));
  });

  test("rejects a predicate that is not reproduced by the original recipe", async () => {
    await expect(
      minimizeMutationRecipes(PSBT, [{ kind: "append-bytes", valueHex: "00" }], async () => false),
    ).rejects.toThrow(/does not reproduce/);
  });
});
