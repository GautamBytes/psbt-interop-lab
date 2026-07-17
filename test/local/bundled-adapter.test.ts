import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "vitest";
import { LOCAL_PARSE_FIXTURES } from "../../src/local/fixtures.js";
import { AdapterProcess } from "../../src/protocol/adapter-process.js";
import { ADAPTER_PROTOCOL } from "../../src/protocol/types.js";

const running: AdapterProcess[] = [];

afterEach(async () => {
  await Promise.all(running.splice(0).map((adapter) => adapter.close()));
});

function bundledAdapter(): AdapterProcess {
  const adapter = new AdapterProcess({
    command: process.execPath,
    args: [fileURLToPath(new URL("../../src/local/bundled-js-adapter.mjs", import.meta.url))],
    cwd: fileURLToPath(new URL("../..", import.meta.url)),
  });
  running.push(adapter);
  return adapter;
}

describe("bundled local JavaScript adapter", () => {
  test("natively parses and byte-roundtrips the frozen PSBTv0 and PSBTv2 fixtures", async () => {
    const adapter = bundledAdapter();
    const hello = await adapter.request(
      { protocol: ADAPTER_PROTOCOL, id: "hello", operation: "hello", payload: {} },
      5_000,
    );

    expect(hello).toMatchObject({
      status: "ok",
      implementation: { name: "psbt-lab-js", version: "0.1.0" },
      output: {
        operations: ["hello", "native-parse", "roundtrip"],
        roles: ["parser"],
        psbtVersions: [0, 2],
      },
    });

    for (const [index, fixture] of LOCAL_PARSE_FIXTURES.entries()) {
      const parsed = await adapter.request(
        {
          protocol: ADAPTER_PROTOCOL,
          id: `parse-${index}`,
          operation: "native-parse",
          payload: { psbt: fixture.psbt },
        },
        5_000,
      );
      expect(parsed).toMatchObject({
        status: "ok",
        output: { nativeParser: "psbt-lab-js", psbtVersion: fixture.psbtVersion },
      });

      const roundtrip = await adapter.request(
        {
          protocol: ADAPTER_PROTOCOL,
          id: `roundtrip-${index}`,
          operation: "roundtrip",
          payload: { psbt: fixture.psbt },
        },
        5_000,
      );
      expect(roundtrip).toMatchObject({
        status: "ok",
        output: { psbt: fixture.psbt, byteIdentical: true, psbtVersion: fixture.psbtVersion },
      });
    }
  });

  test("rejects malformed PSBT bytes without crashing", async () => {
    const adapter = bundledAdapter();
    const response = await adapter.request(
      {
        protocol: ADAPTER_PROTOCOL,
        id: "malformed",
        operation: "native-parse",
        payload: { psbt: Buffer.from("not a psbt").toString("base64") },
      },
      5_000,
    );

    expect(response).toMatchObject({
      status: "rejected",
      error: { class: "psbt.native_parse_failed" },
    });
  });

  test("rejects PSBTv2 documents missing required transaction fields", async () => {
    const adapter = bundledAdapter();
    const incompleteV2 = Buffer.from(
      "70736274ff01fb04020000000104010101050101000000",
      "hex",
    ).toString("base64");
    const response = await adapter.request(
      {
        protocol: ADAPTER_PROTOCOL,
        id: "incomplete-v2",
        operation: "native-parse",
        payload: { psbt: incompleteV2 },
      },
      5_000,
    );

    expect(response).toMatchObject({
      status: "rejected",
      error: { class: "psbt.native_parse_failed" },
    });
  });
});
