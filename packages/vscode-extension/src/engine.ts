import {
  spawn,
  type ChildProcess,
  type SpawnOptions,
} from "node:child_process";
import process from "node:process";

const MAX_STDOUT_BYTES = 5_000_000;

export interface Cancellation {
  readonly isCancellationRequested: boolean;
  onCancellationRequested(listener: () => void): { dispose(): void };
}

export interface EngineResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly durationMs: number;
}

export interface EditorSessionRequest {
  readonly command: "scan-text" | "protect-text";
  readonly content: string;
  readonly repository: string;
  readonly source_path: string;
  readonly destination: string;
  readonly profile: string;
  readonly policy?: string;
  readonly mode?: string;
  readonly vault?: string;
  readonly session?: string;
  readonly max_input_bytes: number;
}

export type SpawnEngine = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => ChildProcess;

export class EngineExecutionError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "EngineExecutionError";
  }
}

export class EngineProcessRunner {
  private active = false;
  private compatible = false;

  constructor(
    private readonly executable: string,
    private readonly workspaceRoot: string,
    private readonly spawnEngine: SpawnEngine = spawn,
  ) {}

  async verifyCompatibility(timeoutMs: number): Promise<void> {
    if (this.compatible) {
      return;
    }
    const result = await this.run(["version"], "", timeoutMs);
    if (result.exitCode !== 0 || !isCompatibleVersion(result.stdout.trim())) {
      throw new EngineExecutionError("CS_ENGINE_VERSION_INCOMPATIBLE");
    }
    this.compatible = true;
  }

  run(
    args: readonly string[],
    stdin: string,
    timeoutMs: number,
    cancellation?: Cancellation,
  ): Promise<EngineResult> {
    if (this.active) {
      return Promise.reject(new EngineExecutionError("CS_ENGINE_BUSY"));
    }
    if (
      !Number.isFinite(timeoutMs) ||
      timeoutMs < 100 ||
      args.some((value) => value.includes("\0") || value.includes("\r") || value.includes("\n"))
    ) {
      return Promise.reject(new EngineExecutionError("CS_ENGINE_ARGUMENT_INVALID"));
    }
    this.active = true;
    const started = performance.now();

    return new Promise((resolve, reject) => {
      let child: ChildProcess;
      try {
        child = this.spawnEngine(this.executable, [...args], {
          cwd: this.workspaceRoot,
          env: process.env,
          shell: false,
          windowsHide: true,
          detached: process.platform !== "win32",
          stdio: ["pipe", "pipe", "pipe"],
        });
      } catch {
        this.active = false;
        reject(new EngineExecutionError("CS_ENGINE_MISSING"));
        return;
      }

      const chunks: Buffer[] = [];
      let stdoutBytes = 0;
      let finished = false;

      const finish = (error?: EngineExecutionError, result?: EngineResult) => {
        if (finished) {
          return;
        }
        finished = true;
        clearTimeout(timer);
        subscription?.dispose();
        this.active = false;
        if (error) {
          reject(error);
        } else if (result) {
          resolve(result);
        }
      };

      const terminate = () => terminateOwnedProcess(child, this.spawnEngine);
      const timer = setTimeout(() => {
        terminate();
        finish(new EngineExecutionError("CS_ENGINE_TIMEOUT"));
      }, timeoutMs);
      const subscription = cancellation?.onCancellationRequested(() => {
        terminate();
        finish(new EngineExecutionError("CS_ENGINE_CANCELLED"));
      });

      child.stdout?.on("data", (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        stdoutBytes += buffer.length;
        if (stdoutBytes > MAX_STDOUT_BYTES) {
          terminate();
          finish(new EngineExecutionError("CS_ENGINE_OUTPUT_LIMIT"));
          return;
        }
        chunks.push(buffer);
      });
      child.stderr?.on("data", () => {
        // Engine stderr is intentionally discarded and never surfaced in the editor.
      });
      child.once("error", () => finish(new EngineExecutionError("CS_ENGINE_MISSING")));
      child.once("close", (code, signal) => {
        if (signal) {
          finish(new EngineExecutionError("CS_ENGINE_TERMINATED"));
          return;
        }
        finish(undefined, {
          exitCode: code ?? 3,
          stdout: Buffer.concat(chunks).toString("utf8"),
          durationMs: Math.round((performance.now() - started) * 100) / 100,
        });
      });

      if (cancellation?.isCancellationRequested) {
        terminate();
        finish(new EngineExecutionError("CS_ENGINE_CANCELLED"));
        return;
      }
      child.stdin?.once("error", () => {
        // A closed stdin is reported by the process exit code, without echoing content.
      });
      child.stdin?.end(stdin, "utf8");
    });
  }
}

export class EditorSessionRunner {
  private active = false;
  private child: ChildProcess | undefined;

  constructor(
    private readonly executable: string,
    private readonly workspaceRoot: string,
    private readonly spawnEngine: SpawnEngine = spawn,
  ) {}

  run(
    request: EditorSessionRequest,
    timeoutMs: number,
    cancellation?: Cancellation,
  ): Promise<EngineResult> {
    if (this.active) {
      return Promise.reject(new EngineExecutionError("CS_ENGINE_BUSY"));
    }
    const serialized = `${JSON.stringify(request)}\n`;
    if (
      !Number.isFinite(timeoutMs) ||
      timeoutMs < 100 ||
      Buffer.byteLength(serialized, "utf8") > 4_000_000
    ) {
      return Promise.reject(new EngineExecutionError("CS_ENGINE_ARGUMENT_INVALID"));
    }
    this.active = true;
    const started = performance.now();

    return new Promise((resolve, reject) => {
      let child: ChildProcess;
      try {
        child = this.ensureChild();
      } catch {
        this.active = false;
        reject(new EngineExecutionError("CS_ENGINE_MISSING"));
        return;
      }
      let buffer = Buffer.alloc(0);
      let finished = false;

      const cleanup = () => {
        child.stdout?.off("data", onData);
        child.off("error", onError);
        child.off("close", onClose);
        child.stdin?.off("error", onStdinError);
        clearTimeout(timer);
        subscription?.dispose();
        this.active = false;
      };
      const finish = (error?: EngineExecutionError, result?: EngineResult) => {
        if (finished) {
          return;
        }
        finished = true;
        cleanup();
        if (error) {
          reject(error);
        } else if (result) {
          resolve(result);
        }
      };
      const terminate = () => {
        terminateOwnedProcess(child, this.spawnEngine);
        if (this.child === child) {
          this.child = undefined;
        }
      };
      const onData = (chunk: Buffer | string) => {
        const next = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        buffer = Buffer.concat([buffer, next]);
        if (buffer.length > MAX_STDOUT_BYTES) {
          terminate();
          finish(new EngineExecutionError("CS_ENGINE_OUTPUT_LIMIT"));
          return;
        }
        const newline = buffer.indexOf(0x0a);
        if (newline === -1) {
          return;
        }
        try {
          const envelope = JSON.parse(
            buffer.subarray(0, newline).toString("utf8"),
          ) as unknown;
          if (
            typeof envelope !== "object" ||
            envelope === null ||
            Array.isArray(envelope)
          ) {
            throw new Error("invalid envelope");
          }
          const value = envelope as Record<string, unknown>;
          if (
            typeof value.exit_code !== "number" ||
            !Number.isInteger(value.exit_code)
          ) {
            throw new Error("invalid exit code");
          }
          if (value.exit_code === 3 || value.result === undefined) {
            finish(undefined, {
              exitCode: 3,
              stdout: "",
              durationMs: Math.round((performance.now() - started) * 100) / 100,
            });
            return;
          }
          finish(undefined, {
            exitCode: value.exit_code,
            stdout: JSON.stringify(value.result),
            durationMs: Math.round((performance.now() - started) * 100) / 100,
          });
        } catch {
          terminate();
          finish(new EngineExecutionError("CS_ENGINE_RESULT_INVALID"));
        }
      };
      const onError = () => {
        this.child = undefined;
        finish(new EngineExecutionError("CS_ENGINE_MISSING"));
      };
      const onClose = () => {
        this.child = undefined;
        finish(new EngineExecutionError("CS_ENGINE_TERMINATED"));
      };
      const onStdinError = () => {
        terminate();
        finish(new EngineExecutionError("CS_ENGINE_TERMINATED"));
      };
      const timer = setTimeout(() => {
        terminate();
        finish(new EngineExecutionError("CS_ENGINE_TIMEOUT"));
      }, timeoutMs);
      const subscription = cancellation?.onCancellationRequested(() => {
        terminate();
        finish(new EngineExecutionError("CS_ENGINE_CANCELLED"));
      });

      child.stdout?.on("data", onData);
      child.once("error", onError);
      child.once("close", onClose);
      child.stderr?.on("data", () => {
        // Session stderr is intentionally discarded.
      });
      if (cancellation?.isCancellationRequested) {
        terminate();
        finish(new EngineExecutionError("CS_ENGINE_CANCELLED"));
        return;
      }
      child.stdin?.once("error", onStdinError);
      child.stdin?.write(serialized, "utf8");
    });
  }

  dispose(): void {
    if (this.child) {
      terminateOwnedProcess(this.child, this.spawnEngine);
      this.child = undefined;
    }
  }

  private ensureChild(): ChildProcess {
    if (this.child && !this.child.killed) {
      return this.child;
    }
    const child = this.spawnEngine(this.executable, ["editor-session"], {
      cwd: this.workspaceRoot,
      env: process.env,
      shell: false,
      windowsHide: true,
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    return child;
  }
}

export function isCompatibleVersion(value: string): boolean {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$/u.exec(value);
  if (!match) {
    return false;
  }
  return Number(match[1]) === 0 && Number(match[2]) === 9;
}

function terminateOwnedProcess(child: ChildProcess, spawnEngine: SpawnEngine): void {
  if (!child.pid) {
    return;
  }
  if (process.platform === "win32") {
    try {
      spawnEngine(
        "taskkill.exe",
        ["/PID", String(child.pid), "/T", "/F"],
        {
          shell: false,
          windowsHide: true,
          stdio: "ignore",
        },
      );
    } catch {
      child.kill();
    }
    return;
  }
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    child.kill("SIGTERM");
  }
}
