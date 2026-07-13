#!/usr/bin/env node

import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import process from "node:process";
import { pathToFileURL } from "node:url";

export type SpawnProcess = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => ChildProcess;

export function pythonExecutable(environment: NodeJS.ProcessEnv = process.env): string {
  return environment.CODESHIELD_PYTHON?.trim() || "python";
}

export function runPythonCli(
  args: readonly string[],
  environment: NodeJS.ProcessEnv = process.env,
  spawnProcess: SpawnProcess = spawn,
): Promise<number> {
  const executable = pythonExecutable(environment);
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawnProcess(executable, ["-m", "codeshield.cli", ...args], {
        env: environment,
        shell: false,
        stdio: "inherit",
      });
    } catch {
      process.stderr.write(
        "CodeShield setup error: Python or the CodeShield engine is unavailable.\n",
      );
      resolve(3);
      return;
    }
    child.once("error", () => {
      process.stderr.write(
        "CodeShield setup error: Python or the CodeShield engine is unavailable.\n",
      );
      resolve(3);
    });
    child.once("exit", (code, signal) => {
      if (signal) {
        process.stderr.write(`CodeShield Python process stopped by ${signal}.\n`);
        resolve(3);
        return;
      }
      resolve(code ?? 3);
    });
  });
}

const isEntryPoint = process.argv[1]
  ? import.meta.url === pathToFileURL(process.argv[1]).href
  : false;

if (isEntryPoint) {
  process.exitCode = await runPythonCli(process.argv.slice(2));
}
