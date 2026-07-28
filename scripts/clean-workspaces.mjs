import path from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

import { cleanBuildOutputs, SafeFileError } from "./lib/safe-files.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
try {
  cleanBuildOutputs(root);
} catch (error) {
  const message =
    error instanceof SafeFileError
      ? error.message
      : "CodeShield workspace cleanup failed safely.";
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
