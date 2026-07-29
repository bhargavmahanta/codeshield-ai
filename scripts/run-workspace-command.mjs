import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const command = process.argv[2];
const npmCli = process.env.npm_execpath;
if (!npmCli || path.basename(npmCli).toLowerCase() !== "npm-cli.js") {
  process.stderr.write("The npm workspace runner is unavailable.\n");
  process.exit(1);
}
const npm = (args) => [process.execPath, [npmCli, ...args]];
const tasks = {
  typecheck: [
    [process.execPath, ["scripts/build-workspaces.mjs"]],
    npm(["run", "typecheck", "--workspace", "@codeshield-ai/shared"]),
    npm(["run", "typecheck", "--workspace", "@codeshield-ai/cli"]),
    npm(["run", "typecheck", "--workspace", "@codeshield-ai/sdk"]),
    npm(["run", "typecheck", "--workspace", "packages/vscode-extension"]),
  ],
  test: [
    [process.execPath, ["--test", "scripts/build-tools.test.mjs"]],
    npm(["run", "test", "--workspace", "@codeshield-ai/cli"]),
    npm(["run", "test", "--workspace", "@codeshield-ai/sdk"]),
    npm(["run", "test", "--workspace", "packages/vscode-extension"]),
  ],
  "pack-check": [
    npm([
        "pack",
        "--dry-run",
        "--cache",
        ".npm-cache",
        "--workspace",
        "@codeshield-ai/cli",
      ]),
    npm([
        "pack",
        "--dry-run",
        "--cache",
        ".npm-cache",
        "--workspace",
        "@codeshield-ai/sdk",
      ]),
    npm([
        "pack",
        "--dry-run",
        "--cache",
        ".npm-cache",
        "--workspace",
        "@codeshield-ai/shared",
      ]),
  ],
};

if (!Object.hasOwn(tasks, command)) {
  process.stderr.write("Unknown CodeShield workspace command.\n");
  process.exit(1);
}

for (const [executable, args] of tasks[command]) {
  const result = spawnSync(executable, args, {
    cwd: process.cwd(),
    shell: false,
    stdio: "inherit",
  });
  if (result.status !== 0 || result.error) {
    process.stderr.write("CodeShield workspace command failed safely.\n");
    process.exit(result.status ?? 1);
  }
}
