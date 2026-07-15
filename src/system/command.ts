import { spawn } from "node:child_process";

const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;

export class CommandError extends Error {
  override readonly name = "CommandError";

  constructor(
    message: string,
    readonly exitCode?: number,
    readonly stderr = "",
  ) {
    super(message);
  }
}

export interface CommandOptions {
  cwd: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  env?: Record<string, string>;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
}

export function runCommand(
  command: string,
  args: string[],
  options: CommandOptions,
): Promise<CommandResult> {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("Command timeout must be a positive safe integer");
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new TypeError("Command output limit must be a positive safe integer");
  }

  const environment: Record<string, string> = {};
  for (const key of ["PATH", "HOME", "TMPDIR", "SYSTEMROOT", "DOCKER_CONFIG", "DOCKER_HOST"]) {
    const value = process.env[key];
    if (value !== undefined) {
      environment[key] = value;
    }
  }

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: { ...environment, ...options.env },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;

    const finishWithError = (error: Error) => {
      if (!settled) {
        settled = true;
        child.kill("SIGKILL");
        reject(error);
      }
    };
    const timer = setTimeout(() => {
      finishWithError(new CommandError(`Command ${command} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref();

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes > maxOutputBytes) {
        finishWithError(new CommandError(`Command ${command} exceeded stdout limit`));
      } else {
        stdout.push(chunk);
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.byteLength;
      if (stderrBytes > maxOutputBytes) {
        finishWithError(new CommandError(`Command ${command} exceeded stderr limit`));
      } else {
        stderr.push(chunk);
      }
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      finishWithError(new CommandError(`Could not launch ${command}: ${error.message}`));
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (settled) {
        return;
      }
      settled = true;
      const stdoutText = Buffer.concat(stdout).toString("utf8").trim();
      const stderrText = Buffer.concat(stderr).toString("utf8").trim();
      if (code !== 0) {
        reject(
          new CommandError(
            `${command} ${args.join(" ")} failed (code=${String(code)}, signal=${String(signal)})${stderrText ? `: ${stderrText}` : ""}`,
            code ?? undefined,
            stderrText,
          ),
        );
        return;
      }
      resolve({ stdout: stdoutText, stderr: stderrText });
    });
  });
}
