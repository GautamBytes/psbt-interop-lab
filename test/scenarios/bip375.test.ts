import { describe, expect, test } from "vitest";
import { createBip375ReferenceScenario } from "../../src/scenarios/bip375.js";

describe("BIP375 reference scenario", () => {
  test("reports the complete official corpus by validation stage", async () => {
    const scenario = createBip375ReferenceScenario();
    const result = await scenario.run({} as never);

    expect(scenario).toMatchObject({
      id: "bip375-official-reference-vectors",
      category: "silent-payment-conformance",
      requirements: [],
    });
    expect(result.summary).toBe("All 41 official BIP375 vectors matched their expected outcomes.");
    expect(result.assertions).toHaveLength(5);
    expect(result.assertions.every(({ passed }) => passed)).toBe(true);
  });
});
