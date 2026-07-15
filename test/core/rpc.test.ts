import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, test } from "vitest";
import { CoreRpc, CoreRpcError, CoreRpcTransportError } from "../../src/core/rpc.js";

interface TestServer {
  url: string;
  close: () => Promise<void>;
}

const servers: TestServer[] = [];

async function serve(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<TestServer> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  const testServer = {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
  servers.push(testServer);
  return testServer;
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe("CoreRpc", () => {
  test("sends authenticated named-parameter calls to a wallet", async () => {
    let observedPath = "";
    let observedAuthorization = "";
    let observedBody: unknown;
    const server = await serve(async (request, response) => {
      observedPath = request.url ?? "";
      observedAuthorization = request.headers.authorization ?? "";
      observedBody = JSON.parse(await readBody(request));
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ result: 42, error: null, id: "psbt-lab-1" }));
    });
    const rpc = new CoreRpc({
      url: server.url,
      username: "lab",
      password: "local-secret",
    });

    await expect(
      rpc.call<number>("getblockcount", { verbose: true }, "proof wallet"),
    ).resolves.toBe(42);
    expect(observedPath).toBe("/wallet/proof%20wallet");
    expect(observedAuthorization).toBe(
      `Basic ${Buffer.from("lab:local-secret").toString("base64")}`,
    );
    expect(observedBody).toMatchObject({
      jsonrpc: "1.0",
      id: "psbt-lab-1",
      method: "getblockcount",
      params: { verbose: true },
    });
  });

  test("surfaces a typed Bitcoin Core RPC error", async () => {
    const server = await serve((_request, response) => {
      response.statusCode = 500;
      response.end(
        JSON.stringify({
          result: null,
          error: { code: -8, message: "Invalid parameter" },
          id: "psbt-lab-1",
        }),
      );
    });
    const rpc = new CoreRpc({ url: server.url, username: "u", password: "p" });

    const error = await rpc.call("badmethod", {}).catch((reason: unknown) => reason);

    expect(error).toBeInstanceOf(CoreRpcError);
    expect(error).toMatchObject({ code: -8, method: "badmethod" });
  });

  test("rejects invalid JSON transport responses", async () => {
    const server = await serve((_request, response) => response.end("not-json"));
    const rpc = new CoreRpc({ url: server.url, username: "u", password: "p" });

    await expect(rpc.call("getblockcount", {})).rejects.toBeInstanceOf(CoreRpcTransportError);
  });

  test("enforces its response size limit", async () => {
    const server = await serve((_request, response) =>
      response.end(JSON.stringify({ result: "x".repeat(512), error: null })),
    );
    const rpc = new CoreRpc({
      url: server.url,
      username: "u",
      password: "p",
      maxResponseBytes: 64,
    });

    await expect(rpc.call("large", {})).rejects.toThrow(/size limit/i);
  });

  test("rejects non-loopback endpoints by default", () => {
    expect(
      () =>
        new CoreRpc({
          url: "http://example.com:8332",
          username: "u",
          password: "p",
        }),
    ).toThrow(/loopback/i);
  });
});
