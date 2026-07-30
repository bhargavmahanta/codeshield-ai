import { existsSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import process from "node:process";
import { fileURLToPath } from "node:url";

import yauzl from "yauzl";

const extensionRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const repositoryRoot = path.resolve(extensionRoot, "..", "..");
const artifactDirectory = path.join(repositoryRoot, "artifacts");
const output = path.join(artifactDirectory, "codeshield-ai-0.8.0.vsix");
const vsce = path.join(repositoryRoot, "node_modules", "@vscode", "vsce", "vsce");

mkdirSync(artifactDirectory, { recursive: true });
rmSync(output, { force: true });

const result = spawnSync(
  process.execPath,
  [vsce, "package", "--out", output, "--no-dependencies"],
  {
    cwd: extensionRoot,
    shell: false,
    stdio: "inherit",
  },
);
if (result.status !== 0 || result.error || !existsSync(output)) {
  process.stderr.write("CodeShield VSIX packaging failed safely.\n");
  process.exit(1);
}

const allowed = new Set([
  "[Content_Types].xml",
  "extension.vsixmanifest",
  "extension/package.json",
  "extension/dist/extension.js",
  "extension/readme.md",
  "extension/changelog.md",
  "extension/LICENSE.txt",
]);
const entries = await listEntries(output);
const unexpected = entries.filter((entry) => !allowed.has(entry));
const required = ["extension/package.json", "extension/dist/extension.js"];
if (
  unexpected.length > 0 ||
  required.some((entry) => !entries.includes(entry)) ||
  entries.some((entry) => entry.endsWith(".map"))
) {
  rmSync(output, { force: true });
  process.stderr.write("CodeShield VSIX content validation failed safely.\n");
  process.exit(1);
}
process.stdout.write(`Validated local VSIX: artifacts/${path.basename(output)}\n`);

function listEntries(file) {
  return new Promise((resolve, reject) => {
    yauzl.open(file, { lazyEntries: true }, (error, archive) => {
      if (error || !archive) {
        reject(error ?? new Error("unable to open VSIX"));
        return;
      }
      const names = [];
      archive.readEntry();
      archive.on("entry", (entry) => {
        names.push(entry.fileName);
        archive.readEntry();
      });
      archive.on("end", () => resolve(names));
      archive.on("error", reject);
    });
  });
}
