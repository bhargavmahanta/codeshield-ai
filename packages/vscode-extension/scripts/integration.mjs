import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { runTests } from "@vscode/test-electron";

const extensionRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const repositoryRoot = path.resolve(extensionRoot, "..", "..");

try {
  await runTests({
    version: process.env.VSCODE_VERSION ?? "1.130.0",
    extensionDevelopmentPath: extensionRoot,
    extensionTestsPath: path.join(extensionRoot, "test", "integration", "run.cjs"),
    launchArgs: [repositoryRoot, "--disable-extensions"],
  });
} catch {
  process.stderr.write("CodeShield extension-host tests failed safely.\n");
  process.exit(1);
}
