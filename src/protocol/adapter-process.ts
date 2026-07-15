import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { once } from "node:events";
import { validateAdapterRequest, validateAdapterResponse } from "./schema.js";
import type { AdapterRequest, AdapterResponse, ValidationResult } from "./types.js";

const DEFAULT_MAX_LINE_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_STDERR_BYTES = 64 * 1024;

export class AdapterProtocolError extends Error {
  override readonly name = "AdapterProtocolError";
}

export class AdapterTimeoutError extends Error {
  override readonly name = "AdapterTimeoutError";
}

export interface AdapterProcessOptions {
  command: string;
  args?: string[];
  cwd: string;
  env?: Record<string, string>;
  maxLineBytes?: number;
  maxStderrBytes?: number;
}

interface PendingRequest {
  id: string;
  resolve: (response: AdapterResponse) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

function validationMessage(kind: string, result: ValidationResult): string {
  return result.ok ? "" : `Invalid adapter ${kind}: ${result.errors.join("; ")}`;
}

function boundedPositiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
  return value;
}

export class AdapterProcess {
  readonly #options: Required<Pick<AdapterProcessOptions, "command" | "args" | "cwd">> &
    AdapterProcessOptions;
  readonly #maxLineBytes: number;
  readonly #maxStderrBytes: number;
  #child: ChildProcessWithoutNullStreams | undefined;
  #stdoutBuffer = Buffer.alloc(0);
  #stderr = Buffer.alloc(0);
  #pending: PendingRequest | undefined;
  #closed = false;

  constructor(options: AdapterProcessOptions) {
    if (!options.command || !options.cwd) {
      throw new TypeError("Adapter command and cwd are required");
    }
    this.#options = { ...options, args: [...(options.args ?? [])] };
    this.#maxLineBytes = boundedPositiveInteger(
      options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES,
      "maxLineBytes",
    );
    this.#maxStderrBytes = boundedPositiveInteger(
      options.maxStderrBytes ?? DEFAULT_MAX_STDERR_BYTES,
      "maxStderrBytes",
    );
  }

  get stderr(): string {
    return this.#stderr.toString("utf8");
  }

  async request(request: AdapterRequest, timeoutMs: number): Promise<AdapterResponse> {
    const validation = validateAdapterRequest(request);
    if (!validation.ok) {
      throw new AdapterProtocolError(validationMessage("request", validation));
    }
    boundedPositiveInteger(timeoutMs, "timeoutMs");
    if (this.#closed) {
      throw new AdapterProtocolError("Adapter process is closed");
    }
    if (this.#pending) {
      throw new AdapterProtocolError("Adapter process supports one in-flight request at a time");
    }

    const encoded = Buffer.from(`${JSON.stringify(request)}\n`, "utf8");
    if (encoded.byteLength - 1 > this.#maxLineBytes) {
      throw new AdapterProtocolError("Adapter request exceeds the line limit");
    }

    const child = this.#start();
    return new Promise<AdapterResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#failPending(
          new AdapterTimeoutError(`Adapter request ${request.id} timed out after ${timeoutMs}ms`),
        );
        this.#terminate();
      }, timeoutMs);
      timer.unref();
      this.#pending = { id: request.id, resolve, reject, timer };

      child.stdin.write(encoded, (error) => {
        if (error) {
          this.#failPending(
            new AdapterProtocolError(`Could not write adapter request: ${error.message}`),
          );
          this.#terminate();
        }
      });
    });
  }

  async close(): Promise<void> {
    this.#closed = true;
    this.#failPending(new AdapterProtocolError("Adapter process closed"));
    const child = this.#child;
    if (!child || child.exitCode !== null || child.signalCode !== null) {
      return;
    }

    child.stdin.end();
    child.kill("SIGTERM");
    const forceKill = setTimeout(() => child.kill("SIGKILL"), 250);
    forceKill.unref();
    await once(child, "exit").catch(() => undefined);
    clearTimeout(forceKill);
  }

  #start(): ChildProcessWithoutNullStreams {
    if (this.#child) {
      return this.#child;
    }

    const inheritedEnvironment: Record<string, string> = {};
    for (const key of ["PATH", "HOME", "TMPDIR", "SYSTEMROOT"]) {
      const value = process.env[key];
      if (value !== undefined) {
        inheritedEnvironment[key] = value;
      }
    }

    const child = spawn(this.#options.command, this.#options.args, {
      cwd: this.#options.cwd,
      env: { ...inheritedEnvironment, ...this.#options.env },
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.#child = child;

    child.stdout.on("data", (chunk: Buffer) => this.#consumeStdout(chunk));
    child.stderr.on("data", (chunk: Buffer) => {
      const remaining = this.#maxStderrBytes - this.#stderr.byteLength;
      if (remaining > 0) {
        this.#stderr = Buffer.concat([this.#stderr, chunk.subarray(0, remaining)]);
      }
    });
    child.on("error", (error) => {
      this.#failPending(new AdapterProtocolError(`Adapter process error: ${error.message}`));
    });
    child.on("exit", (code, signal) => {
      this.#failPending(
        new AdapterProtocolError(
          `Adapter exited before responding (code=${String(code)}, signal=${String(signal)})`,
        ),
      );
    });

    return child;
  }

  #consumeStdout(chunk: Buffer): void {
    this.#stdoutBuffer = Buffer.concat([this.#stdoutBuffer, chunk]);

    while (true) {
      const newline = this.#stdoutBuffer.indexOf(0x0a);
      if (newline === -1) {
        if (this.#stdoutBuffer.byteLength > this.#maxLineBytes) {
          this.#protocolViolation("Adapter response exceeds the line limit");
        }
        return;
      }
      if (newline > this.#maxLineBytes) {
        this.#protocolViolation("Adapter response exceeds the line limit");
        return;
      }

      const line = this.#stdoutBuffer.subarray(0, newline);
      this.#stdoutBuffer = this.#stdoutBuffer.subarray(newline + 1);
      if (line.byteLength === 0) {
        this.#protocolViolation("Adapter emitted an empty response line");
        return;
      }
      this.#consumeLine(line);
    }
  }

  #consumeLine(line: Buffer): void {
    let value: unknown;
    try {
      value = JSON.parse(line.toString("utf8"));
    } catch {
      this.#protocolViolation("Adapter response is not valid JSON");
      return;
    }

    const validation = validateAdapterResponse(value);
    if (!validation.ok) {
      this.#protocolViolation(validationMessage("response", validation));
      return;
    }

    const response = value as AdapterResponse;
    const pending = this.#pending;
    if (!pending) {
      this.#protocolViolation("Adapter emitted an unsolicited response");
      return;
    }
    if (response.id !== pending.id) {
      this.#protocolViolation(
        `Adapter response id ${response.id} does not match request id ${pending.id}`,
      );
      return;
    }

    clearTimeout(pending.timer);
    this.#pending = undefined;
    pending.resolve(response);
  }

  #protocolViolation(message: string): void {
    this.#failPending(new AdapterProtocolError(message));
    this.#terminate();
  }

  #failPending(error: Error): void {
    const pending = this.#pending;
    if (!pending) {
      return;
    }
    clearTimeout(pending.timer);
    this.#pending = undefined;
    pending.reject(error);
  }

  #terminate(): void {
    this.#closed = true;
    const child = this.#child;
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
  }
}
