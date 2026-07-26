import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { parseCustomSuiteManifest } from "../../src/custom/manifest.js";
import { promoteDifferentialCase } from "../../src/fuzz/promotion.js";
import { LOCAL_PARSE_FIXTURES } from "../../src/local/fixtures.js";

describe("promoteDifferentialCase", () => {
  test("emits a safe custom suite v0.2 parser regression", () => {
    const fixture = LOCAL_PARSE_FIXTURES[0];
    if (!fixture) throw new Error("Missing local parse fixture");
    const suite = promoteDifferentialCase({
      fixture,
      seed: 42,
      caseIndex: 3,
      recipes: [{ kind: "truncate", byteLength: 10 }],
      outcomes: {
        lab: { classification: "rejected", detail: "truncated map" },
        "rust-bitcoin": { classification: "rejected", detail: "parse failed" },
        "permissive-parser": {
          classification: "accepted",
          detail: "accepted malformed input",
          facts: { psbtVersion: 0, inputs: 0, outputs: 0 },
        },
      },
    });

    expect(suite).toMatchObject({
      schema: "psbt-lab.suite/0.2",
      fixtures: [],
      parserFixtures: [
        {
          id: "fuzz-42-3-base",
          psbt: fixture.psbt,
          sha256: `sha256:${createHash("sha256")
            .update(Buffer.from(fixture.psbt, "base64"))
            .digest("hex")}`,
        },
      ],
      scenarios: [
        {
          id: "fuzz-42-3",
          fixture: "fuzz-42-3-base",
          steps: [
            { id: "mutated", operation: "mutate" },
            { id: "compare", operation: "compare-parsers" },
          ],
        },
      ],
    });
    expect(parseCustomSuiteManifest(suite)).toEqual(suite);
    expect(JSON.stringify(suite)).not.toMatch(/command|private|secret/i);
  });
});
