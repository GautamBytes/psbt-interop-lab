import { describe, expect, test } from "vitest";
import { createProgram } from "../src/cli.js";

describe("CLI program", () => {
  test("exposes discovery, matrix, runtime, and replay commands", () => {
    const commands = createProgram().commands.map((command) => command.name());

    expect(commands).toEqual(["doctor", "list", "run", "matrix", "replay"]);
  });
});
