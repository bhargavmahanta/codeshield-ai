import { spawn, spawnSync } from "node:child_process";
import process from "node:process";
import { performance } from "node:perf_hooks";
import { createInterface } from "node:readline";

const executable = process.env.CODESHIELD_EXECUTABLE?.trim() || "codeshield";
const trials = 20;
const budgetMs = 750;
const line = "const localValue = 'ordinary deterministic benchmark text';\n";
const input = line.repeat(Math.ceil(100_000 / Buffer.byteLength(line))).slice(0, 100_000);
const request = {
  command: "scan-text",
  content: input,
  repository: process.cwd(),
  source_path: "benchmarks/editor-100kb.ts",
  destination: "local_file",
  profile: "core",
  max_input_bytes: 1_000_000,
};

const version = spawnSync(executable, ["version"], {
  cwd: process.cwd(),
  shell: false,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "ignore"],
});
if (version.status !== 0 || !/^0\.8\.\d+/u.test(version.stdout.trim())) {
  process.stderr.write("CodeShield benchmark requires the local 0.8.x engine.\n");
  process.exit(1);
}

const child = spawn(executable, ["editor-session"], {
  cwd: process.cwd(),
  shell: false,
  windowsHide: true,
  stdio: ["pipe", "pipe", "ignore"],
});
const lines = createInterface({ input: child.stdout });
const durations = [];
for (let index = 0; index < trials + 1; index += 1) {
  const response = new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("benchmark response timed out")),
      15_000,
    );
    lines.once("line", (lineValue) => {
      clearTimeout(timer);
      resolve(lineValue);
    });
  });
  const started = performance.now();
  child.stdin.write(`${JSON.stringify(request)}\n`, "utf8");
  const lineValue = await response;
  const duration = performance.now() - started;
  try {
    const envelope = JSON.parse(lineValue);
    const payload = envelope.result;
    if (envelope.exit_code !== 0) {
      throw new Error("benchmark scan failed");
    }
    if (payload.scanned_bytes !== 100_000 || payload.files_scanned !== 1) {
      throw new Error("invalid benchmark result");
    }
  } catch {
    process.stderr.write("CodeShield editor benchmark returned invalid metadata.\n");
    process.exit(1);
  }
  if (index > 0) {
    durations.push(duration);
  }
}
child.stdin.end();
lines.close();

durations.sort((left, right) => left - right);
const percentileIndex = Math.ceil(0.95 * durations.length) - 1;
const p95 = Math.round(durations[percentileIndex] * 100) / 100;
const result = {
  workload_bytes: 100_000,
  profile: "core",
  warm_trials: trials,
  p95_ms: p95,
  budget_ms: budgetMs,
  passed: p95 <= budgetMs,
};
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.passed) {
  process.exit(2);
}
