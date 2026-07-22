import { describe, expect, test } from "vitest";
import { getConformanceRule } from "../../src/conformance/rules.js";
import { publicConformanceRules } from "../../website/src/generated/conformance-rules.js";

describe("generated website conformance data", () => {
  test("matches the authored public fields for the empty final scriptSig rule", () => {
    const ruleId = "bip174.final-scriptsig.empty-omitted";
    const rule = getConformanceRule(ruleId);

    expect(publicConformanceRules[ruleId]).toEqual({
      id: rule.id,
      title: rule.title,
      normativeLevel: rule.normativeLevel,
      source: rule.source,
      expected: rule.expected,
    });
  });
});
