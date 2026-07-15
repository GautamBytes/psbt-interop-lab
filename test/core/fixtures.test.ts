import { describe, expect, test } from "vitest";
import {
  btcToSats,
  prepareFixtures,
  type RpcCaller,
  satsToBtcString,
} from "../../src/core/fixtures.js";

describe("Bitcoin amount conversion", () => {
  test.each([
    ["0.00000001", 1],
    ["1.00000000", 100_000_000],
    [50, 5_000_000_000],
  ])("converts BTC to integer sats", (value, sats) => {
    expect(btcToSats(value)).toBe(sats);
  });

  test("formats integer sats without floating-point output", () => {
    expect(satsToBtcString(4_999_999_000)).toBe("49.99999000");
  });

  test.each(["0.000000001", -1, Number.NaN])("rejects invalid Bitcoin amounts", (value) => {
    expect(() => btcToSats(value)).toThrow(/amount/i);
  });
});

describe("prepareFixtures", () => {
  test("refuses to operate on a non-regtest chain", async () => {
    const rpc: RpcCaller = {
      async call<T>(method: string): Promise<T> {
        expect(method).toBe("getblockchaininfo");
        return { chain: "main", blocks: 800_000 } as T;
      },
    };

    await expect(prepareFixtures(rpc)).rejects.toThrow(/regtest/i);
  });
});
