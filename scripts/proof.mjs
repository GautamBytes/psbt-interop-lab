import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const child = spawn(
  process.execPath,
  [resolve(project, "dist/cli.js"), "run", "--suite", "proof"],
  {
    cwd: project,
    shell: false,
    stdio: "inherit",
  },
);

child.on("error", (error) => {
  process.stderr.write(`Could not start proof: ${error.message}\n`);
  process.exitCode = 1;
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.stderr.write(`Proof stopped by ${signal}\n`);
    process.exitCode = 1;
    return;
  }
  process.exitCode = code ?? 1;
});
