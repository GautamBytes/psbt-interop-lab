import { request as httpRequest } from "node:http";

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_REQUEST_BYTES = 1024 * 1024;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

export class CoreRpcError extends Error {
  override readonly name = "CoreRpcError";

  constructor(
    readonly method: string,
    readonly code: number,
    message: string,
  ) {
    super(`Bitcoin Core RPC ${method} failed (${code}): ${message}`);
  }
}

export class CoreRpcTransportError extends Error {
  override readonly name = "CoreRpcTransportError";
}

export interface CoreRpcOptions {
  url: string;
  username: string;
  password: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowRemote?: boolean;
}

interface RpcErrorValue {
  code: number;
  message: string;
}

interface RpcEnvelope {
  id: unknown;
  result: unknown;
  error: RpcErrorValue | null;
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function isRpcEnvelope(value: unknown): value is RpcEnvelope {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const envelope = value as Record<string, unknown>;
  if (!("id" in envelope) || !("result" in envelope) || !("error" in envelope)) {
    return false;
  }
  if (envelope["error"] === null) {
    return true;
  }
  if (typeof envelope["error"] !== "object") {
    return false;
  }
  const error = envelope["error"] as Record<string, unknown>;
  return typeof error["code"] === "number" && typeof error["message"] === "string";
}

export class CoreRpc {
  readonly #baseUrl: URL;
  readonly #authorization: string;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  #requestId = 0;

  constructor(options: CoreRpcOptions) {
    const url = new URL(options.url);
    if (url.protocol !== "http:") {
      throw new TypeError("Bitcoin Core RPC URL must use http");
    }
    if (!options.allowRemote && !LOOPBACK_HOSTS.has(url.hostname)) {
      throw new TypeError("Bitcoin Core RPC URL must use a loopback host");
    }
    if (
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (url.pathname !== "/" && url.pathname !== "")
    ) {
      throw new TypeError("Bitcoin Core RPC URL must contain only scheme, host, and port");
    }
    if (!options.username || !options.password) {
      throw new TypeError("Bitcoin Core RPC username and password are required");
    }

    this.#baseUrl = url;
    this.#authorization = `Basic ${Buffer.from(
      `${options.username}:${options.password}`,
      "utf8",
    ).toString("base64")}`;
    this.#timeoutMs = positiveInteger(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, "timeoutMs");
    this.#maxResponseBytes = positiveInteger(
      options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      "maxResponseBytes",
    );
  }

  async call<T>(
    method: string,
    params: Record<string, unknown> | unknown[] = {},
    wallet?: string,
  ): Promise<T> {
    if (!/^[a-z][a-z0-9_]*$/.test(method)) {
      throw new TypeError("Bitcoin Core RPC method name is invalid");
    }
    if (wallet !== undefined && (wallet.length === 0 || wallet.length > 128)) {
      throw new TypeError("Bitcoin Core wallet name is invalid");
    }

    this.#requestId += 1;
    const id = `psbt-lab-${this.#requestId}`;
    const body = Buffer.from(JSON.stringify({ jsonrpc: "1.0", id, method, params }), "utf8");
    if (body.byteLength > MAX_REQUEST_BYTES) {
      throw new CoreRpcTransportError("Bitcoin Core RPC request exceeds the size limit");
    }

    const endpoint = new URL(this.#baseUrl);
    endpoint.pathname = wallet === undefined ? "/" : `/wallet/${encodeURIComponent(wallet)}`;
    const { statusCode, responseBody } = await this.#post(endpoint, body);

    let decoded: unknown;
    try {
      decoded = JSON.parse(responseBody.toString("utf8"));
    } catch {
      throw new CoreRpcTransportError(`Bitcoin Core RPC ${method} returned invalid JSON`);
    }
    if (!isRpcEnvelope(decoded)) {
      throw new CoreRpcTransportError(`Bitcoin Core RPC ${method} returned an invalid envelope`);
    }
    if (decoded.id !== id) {
      throw new CoreRpcTransportError(
        `Bitcoin Core RPC ${method} returned a mismatched response id`,
      );
    }
    if (decoded.error) {
      throw new CoreRpcError(method, decoded.error.code, decoded.error.message);
    }
    if (statusCode < 200 || statusCode >= 300) {
      throw new CoreRpcTransportError(`Bitcoin Core RPC ${method} returned HTTP ${statusCode}`);
    }
    return decoded.result as T;
  }

  #post(endpoint: URL, body: Buffer): Promise<{ statusCode: number; responseBody: Buffer }> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (error: Error) => {
        if (!settled) {
          settled = true;
          reject(error);
        }
      };

      const request = httpRequest(
        endpoint,
        {
          method: "POST",
          headers: {
            authorization: this.#authorization,
            "content-type": "application/json",
            "content-length": String(body.byteLength),
          },
        },
        (response) => {
          const chunks: Buffer[] = [];
          let bytes = 0;
          response.on("data", (chunk: Buffer) => {
            bytes += chunk.byteLength;
            if (bytes > this.#maxResponseBytes) {
              response.destroy();
              fail(new CoreRpcTransportError("Bitcoin Core RPC response exceeds the size limit"));
              return;
            }
            chunks.push(chunk);
          });
          response.on("end", () => {
            if (settled) {
              return;
            }
            settled = true;
            resolve({
              statusCode: response.statusCode ?? 0,
              responseBody: Buffer.concat(chunks),
            });
          });
          response.on("error", (error) =>
            fail(new CoreRpcTransportError(`Bitcoin Core RPC response failed: ${error.message}`)),
          );
        },
      );
      request.setTimeout(this.#timeoutMs, () => {
        request.destroy();
        fail(new CoreRpcTransportError("Bitcoin Core RPC request timed out"));
      });
      request.on("error", (error) =>
        fail(new CoreRpcTransportError(`Bitcoin Core RPC connection failed: ${error.message}`)),
      );
      request.end(body);
    });
  }
}
