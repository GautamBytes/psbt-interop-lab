import { describe, expect, test, vi } from "vitest";
import type { AdapterResponse, JsonValue } from "../../src/protocol/types.js";
import { BIP370_VALID_VECTORS } from "../../src/psbt/bip370-vectors.js";
import {
  createPsbtv2ConstructorScenario,
  createPsbtv2LocktimeScenario,
} from "../../src/scenarios/psbtv2-constructor.js";

const implementation = {
  name: "rust-psbt-v2",
  version: "0.1.0",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

function fakeContext() {
  const actions: string[] = [];
  return {
    actions,
    checkpoint: vi.fn(async () => undefined),
    outputString(response: AdapterResponse, key: string) {
      if (response.status !== "ok" || typeof response.output[key] !== "string") {
        throw new Error("missing string");
      }
      return response.output[key];
    },
    request: vi.fn(
      async (
        _adapter: string,
        _operation: string,
        payload: Record<string, JsonValue>,
      ): Promise<AdapterResponse> => {
        const action = String(payload["action"]);
        actions.push(action);
        if (
          (action === "add-input" && actions.includes("seal")) ||
          (action === "add-input" && payload["previousTxid"] === "99".repeat(32))
        ) {
          return {
            protocol: "psbt-lab.adapter/0.2",
            id: `request-${actions.length}`,
            status: "rejected",
            implementation,
            error: {
              class: actions.includes("seal") ? "psbt.not_modifiable" : "psbt.locktime_conflict",
              message: "Expected constructor rejection",
            },
          };
        }
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: `request-${actions.length}`,
          status: "ok",
          implementation,
          output: {
            psbt: BIP370_VALID_VECTORS[0].base64,
            psbtVersion: 2,
            inputs: 1,
            outputs: 2,
            transactionModifiableFlags: action === "seal" ? 0 : 3,
            locktime: 0,
            locktimeType: "none",
          },
        };
      },
    ),
  };
}

describe("PSBTv2 constructor scenarios", () => {
  test("declares the additive native constructor contract", () => {
    for (const scenario of [createPsbtv2ConstructorScenario(), createPsbtv2LocktimeScenario()]) {
      expect(scenario.requirements).toEqual([
        {
          adapter: "rust-psbt-v2",
          operations: ["construct"],
          roles: ["constructor", "updater"],
          psbtVersions: [2],
          features: ["bip370-constructor", "bip370-locktime"],
        },
      ]);
    }
  });

  test("runs the complete add, update, remove, and seal action sequence", async () => {
    const context = fakeContext();

    const result = await createPsbtv2ConstructorScenario().run(context as never);

    expect(context.actions).toEqual([
      "create",
      "add-input",
      "add-output",
      "add-input",
      "add-output",
      "set-sequence",
      "remove-input",
      "remove-output",
      "seal",
      "add-input",
    ]);
    expect(result.assertions.map(({ name }) => name)).toEqual(
      expect.arrayContaining([
        "constructor-required-map-fields",
        "constructor-sequence-updated",
        "constructor-counts-after-removal",
        "constructor-sealed-mutation-rejected",
      ]),
    );
  });

  test("runs fallback, height, time, tie-break, and conflict locktime cases", async () => {
    const context = fakeContext();

    const result = await createPsbtv2LocktimeScenario().run(context as never);

    expect(context.actions.filter((action) => action === "create")).toHaveLength(4);
    expect(context.actions.filter((action) => action === "add-input").length).toBeGreaterThan(6);
    expect(result.assertions.map(({ name }) => name)).toEqual([
      "locktime-fallback-selected",
      "locktime-maximum-height-selected",
      "locktime-maximum-time-selected",
      "locktime-height-tie-break-selected",
      "locktime-conflict-rejected",
    ]);
  });
});
