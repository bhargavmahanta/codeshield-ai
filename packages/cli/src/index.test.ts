import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";

import { pythonExecutable, runPythonCli, type SpawnProcess } from "./index.js";

function childThatExits(code: number | null, signal: NodeJS.Signals | null = null) {
  const child = new EventEmitter() as ChildProcess;
  queueMicrotask(() => child.emit("exit", code, signal));
  return child;
}

describe("npm CLI wrapper", () => {
  it("selects Python, forwards arguments unchanged, and propagates exit codes", async () => {
    const spawnProcess = vi.fn(() => childThatExits(2)) as unknown as SpawnProcess;
    const args = ["scan", "--staged", "--output", "json"];

    const code = await runPythonCli(args, { CODESHIELD_PYTHON: "python312" }, spawnProcess);

    expect(code).toBe(2);
    expect(spawnProcess).toHaveBeenCalledWith(
      "python312",
      ["-m", "codeshield.cli", ...args],
      expect.objectContaining({ shell: false, stdio: "inherit" }),
    );
  });

  it("defaults to python", () => {
    expect(pythonExecutable({})).toBe("python");
  });

  it("maps missing runtimes and signals to execution errors", async () => {
    const missing = (() => {
      throw new Error("missing");
    }) as SpawnProcess;
    const signaled = (() => childThatExits(null, "SIGTERM")) as SpawnProcess;

    await expect(runPythonCli([], {}, missing)).resolves.toBe(3);
    await expect(runPythonCli([], {}, signaled)).resolves.toBe(3);
  });
});
