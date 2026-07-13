import { spawnSync } from "node:child_process";
import process from "node:process";

function run(command, args) {
  const result = spawnSync(command, args, { shell: false, stdio: "inherit" });
  if (result.error || result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

const python = process.env.CODESHIELD_PYTHON?.trim() || "python";
run(python, [
  "engine/scripts/export_openapi.py",
  "packages/shared/openapi.json",
]);
run(process.execPath, [
  "node_modules/openapi-typescript/bin/cli.js",
  "packages/shared/openapi.json",
  "-o",
  "packages/shared/src/generated.ts",
]);
