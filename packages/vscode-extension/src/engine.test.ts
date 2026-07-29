import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import type { ChildProcess, SpawnOptions } from "node:child_process";
import { describe, expect, it, vi } from "vitest";

import {
  EngineExecutionError,
  EngineProcessRunner,
  EditorSessionRunner,
  isCompatibleVersion,
  type SpawnEngine,
} from "./engine.js";

function fakeChild(
  output: string,
  code = 0,
  close = true,
): ChildProcess {
  const child = new EventEmitter() as ChildProcess;
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  Object.assign(child, {
    pid: 43210,
    stdin,
    stdout,
    stderr,
    kill: vi.fn(() => true),
  });
  if (close) {
    queueMicrotask(() => {
      stdout.end(output);
      stderr.end();
      child.emit("close", code, null);
    });
  }
  return child;
}

describe("shell-free engine runner", () => {
  it("uses fixed arguments, shell false, and stdin transport", async () => {
    let received = "";
    const spawnMock = vi.fn(
      (
        _command: string,
        _args: readonly string[],
        _options: SpawnOptions,
      ) => {
        const child = fakeChild('{"ok":true}');
        child.stdin!.on("data", (chunk) => {
          received += chunk.toString();
        });
        return child;
      },
    );
    const runner = new EngineProcessRunner(
      "codeshield",
      "workspace",
      spawnMock as unknown as SpawnEngine,
    );
    const input = "editor-content-only-on-stdin";
    const result = await runner.run(
      ["scan-text", "--stdin", "--format", "json"],
      input,
      1000,
    );

    expect(result.exitCode).toBe(0);
    expect(received).toBe(input);
    expect(spawnMock).toHaveBeenCalledWith(
      "codeshield",
      ["scan-text", "--stdin", "--format", "json"],
      expect.objectContaining({
        cwd: "workspace",
        shell: false,
        windowsHide: true,
      }),
    );
    expect(JSON.stringify(spawnMock.mock.calls)).not.toContain(input);
  });

  it("rejects concurrent operations and times out safely", async () => {
    const spawnEngine = (() => fakeChild("", 0, false)) as SpawnEngine;
    const runner = new EngineProcessRunner("codeshield", "workspace", spawnEngine);
    const first = runner.run(["scan-text"], "", 100);

    await expect(runner.run(["scan-text"], "", 100)).rejects.toMatchObject({
      code: "CS_ENGINE_BUSY",
    });
    await expect(first).rejects.toEqual(
      new EngineExecutionError("CS_ENGINE_TIMEOUT"),
    );
  });

  it("requires the Phase 7 engine version range", () => {
    expect(isCompatibleVersion("0.7.0")).toBe(true);
    expect(isCompatibleVersion("0.7.9+local")).toBe(true);
    expect(isCompatibleVersion("0.6.0")).toBe(false);
    expect(isCompatibleVersion("0.8.0")).toBe(false);
    expect(isCompatibleVersion("not-a-version")).toBe(false);
  });

  it("reuses one owned editor session without placing content in argv", async () => {
    const child = fakeChild("", 0, false);
    child.stdin!.on("data", () => {
      (child.stdout as PassThrough).write(
        `${JSON.stringify({
          exit_code: 0,
          result: {
            findings: [],
            files_scanned: 1,
            scanned_bytes: 4,
            duration_ms: 1,
          },
        })}\n`,
      );
    });
    const spawnMock = vi.fn(
      (
        _command: string,
        _args: readonly string[],
        _options: SpawnOptions,
      ) => child,
    );
    const runner = new EditorSessionRunner(
      "codeshield",
      "workspace",
      spawnMock as unknown as SpawnEngine,
    );
    const request = {
      command: "scan-text" as const,
      content: "safe",
      repository: "workspace",
      source_path: "src/file.ts",
      destination: "local_file",
      profile: "core",
      max_input_bytes: 1_000_000,
    };

    await expect(runner.run(request, 1000)).resolves.toMatchObject({
      exitCode: 0,
    });
    await expect(runner.run(request, 1000)).resolves.toMatchObject({
      exitCode: 0,
    });
    expect(spawnMock).toHaveBeenCalledTimes(1);
    expect(spawnMock).toHaveBeenCalledWith(
      "codeshield",
      ["editor-session"],
      expect.objectContaining({ shell: false }),
    );
    expect(
      JSON.stringify(spawnMock.mock.calls.map((call) => call[1])),
    ).not.toContain("safe");
    runner.dispose();
  });
});
