import { describe, expect, test } from "vitest";
import { CONFORMANCE_RULES, getConformanceRule } from "../../src/conformance/rules.js";

describe("conformance rule catalog", () => {
  test("publishes complete immutable rules with unique stable IDs", () => {
    const entries = Object.entries(CONFORMANCE_RULES);

    expect(entries.length).toBeGreaterThan(10);
    expect(new Set(entries.map(([id]) => id)).size).toBe(entries.length);
    for (const [id, rule] of entries) {
      expect(id).toMatch(/^[a-z0-9]+(?:[.-][a-z0-9]+)+$/);
      expect(rule.id).toBe(id);
      expect(rule.source.url).toMatch(/^https:\/\//);
      expect(rule.source.section.length).toBeGreaterThan(0);
      expect(rule.expected.length).toBeGreaterThan(0);
      expect(Object.isFrozen(rule)).toBe(true);
      expect(Object.isFrozen(rule.source)).toBe(true);
    }
  });

  test("fails closed for an unknown runtime rule ID", () => {
    expect(() => getConformanceRule("bip999.unknown" as never)).toThrow(
      "Unknown conformance rule: bip999.unknown",
    );
  });
});
