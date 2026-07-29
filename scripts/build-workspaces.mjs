import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import process from "node:process";

import { cleanBuildOutputs, SafeFileError } from "./lib/safe-files.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workspaces = [
  {
    name: "@codeshield-ai/shared",
    config: "packages/shared/tsconfig.json",
    expected: [
      "packages/shared/dist/index.js",
      "packages/shared/dist/index.d.ts",
      "packages/shared/dist/generated.js",
      "packages/shared/dist/generated.d.ts",
    ],
  },
  {
    name: "@codeshield-ai/cli",
    config: "packages/cli/tsconfig.json",
    expected: ["packages/cli/dist/index.js"],
  },
  {
    name: "@codeshield-ai/sdk",
    config: "packages/sdk/tsconfig.json",
    expected: ["packages/sdk/dist/index.js", "packages/sdk/dist/index.d.ts"],
  },
  {
    name: "CodeShield VS Code extension",
    workspace: "packages/vscode-extension",
    expected: ["packages/vscode-extension/dist/extension.js"],
  },
];

try {
  cleanBuildOutputs(root);
  for (const workspace of workspaces) {
    runTypeScript(workspace);
    for (const relative of workspace.expected) {
      if (!existsSync(path.join(root, relative))) {
        throw new SafeFileError(
          `Build for ${workspace.name} did not create expected output ${relative}.`,
        );
      }
    }
  }
} catch (error) {
  const message =
    error instanceof SafeFileError
      ? error.message
      : "CodeShield workspace build failed safely.";
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function runTypeScript(workspace) {
  const npmCli = process.env.npm_execpath;
  if (
    workspace.workspace &&
    (!npmCli || path.basename(npmCli).toLowerCase() !== "npm-cli.js")
  ) {
    throw new SafeFileError("The npm workspace runner is unavailable.");
  }
  const command = process.execPath;
  const args = workspace.workspace
    ? [npmCli, "run", "build", "--workspace", workspace.workspace]
    : ["node_modules/typescript/bin/tsc", "-p", workspace.config];
  const result = spawnSync(
    command,
    args,
    {
      cwd: root,
      shell: false,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.status === 0 && !result.error) {
    return;
  }
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (/TS5033|EPERM|EACCES|operation not permitted/i.test(output)) {
    throw new SafeFileError(
      `Build output for ${workspace.name} is locked; close tools using its dist directory and retry.`,
    );
  }
  throw new SafeFileError(`Compilation failed for ${workspace.name}.`);
}
