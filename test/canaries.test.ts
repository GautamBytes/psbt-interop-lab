import { describe, expect, test } from "vitest";
import { detectorCanariesPassed, runDetectorCanaries } from "../src/canaries.js";
import { formatCanaryResults } from "../src/cli-output.js";

describe("detector canaries", () => {
  test("catches representative PSBT corruption instead of producing false greens", () => {
    const results = runDetectorCanaries();

    expect(results.map(({ id }) => id)).toEqual([
      "proprietary-field-drop",
      "unknown-field-drop-during-signing",
      "output-amount-change",
      "sequence-change",
      "signature-removal",
    ]);
    expect(results.every(({ detected }) => detected)).toBe(true);
    expect(detectorCanariesPassed(results)).toBe(true);
    expect(results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "proprietary-field-drop",
          failureCode: "ENTRY_REMOVED",
          keyType: 0xfc,
        }),
        expect.objectContaining({
          id: "unknown-field-drop-during-signing",
          failureCode: "ENTRY_REMOVED",
          keyType: 0x50,
        }),
        expect.objectContaining({
          id: "output-amount-change",
          failureCode: "TRANSACTION_IDENTITY_CHANGED",
          keyType: 0x00,
        }),
        expect.objectContaining({
          id: "sequence-change",
          failureCode: "TRANSACTION_IDENTITY_CHANGED",
          keyType: 0x00,
        }),
        expect.objectContaining({
          id: "signature-removal",
          failureCode: "ENTRY_REMOVED",
          keyType: 0x02,
        }),
      ]),
    );
  });

  test("prints the exact detector and expected failure class", () => {
    const output = formatCanaryResults(runDetectorCanaries());

    expect(output).toContain("PSBT detector self-test: PASSED");
    expect(output).toContain("PASS  output-amount-change");
    expect(output).toContain("TRANSACTION_IDENTITY_CHANGED");
  });

  test("fails closed when a required canary is missing, duplicated, or altered", () => {
    const complete = runDetectorCanaries();
    const duplicate = [complete[0] as (typeof complete)[number], ...complete.slice(0, -1)];
    const altered = complete.map((result, index) =>
      index === 0 ? { ...result, failureCode: "ENTRY_CHANGED" as const } : result,
    );

    expect(detectorCanariesPassed([])).toBe(false);
    expect(detectorCanariesPassed(complete.slice(1))).toBe(false);
    expect(detectorCanariesPassed(duplicate)).toBe(false);
    expect(detectorCanariesPassed(altered)).toBe(false);
    expect(formatCanaryResults([])).toContain("PSBT detector self-test: FAILED");
  });
});
