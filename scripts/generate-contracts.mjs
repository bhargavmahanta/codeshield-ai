import {
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import process from "node:process";

import {
  canonicalizeJsonFile,
  canonicalizeTextFile,
  contractDriftDiagnostic,
  filesEqual,
  safeReplace,
  SafeFileError,
} from "./lib/safe-files.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mode = process.argv[2] ?? "--write";
if (!["--write", "--check"].includes(mode)) {
  process.stderr.write("usage: node scripts/generate-contracts.mjs [--write|--check]\n");
  process.exit(2);
}

const temporary = mkdtempSync(path.join(os.tmpdir(), "codeshield-contracts-"));
const openapi = path.join(temporary, "openapi.json");
const generated = path.join(temporary, "generated.ts");
const managementOpenapi = path.join(temporary, "management-openapi.json");
const managementGenerated = path.join(temporary, "management-generated.ts");

try {
  const python = process.env.CODESHIELD_PYTHON?.trim() || "python";
  run(python, ["engine/scripts/export_openapi.py", openapi]);
  canonicalizeJsonFile(openapi);
  validateOpenApi(openapi);
  run(process.execPath, [
    "node_modules/openapi-typescript/bin/cli.js",
    openapi,
    "--alphabetize",
    "-o",
    generated,
  ]);
  canonicalizeTextFile(generated);
  validateGeneratedTypes(generated);
  run(python, [
    "apps/management-api/scripts/export_openapi.py",
    managementOpenapi,
  ]);
  canonicalizeJsonFile(managementOpenapi);
  validateManagementOpenApi(managementOpenapi);
  run(process.execPath, [
    "node_modules/openapi-typescript/bin/cli.js",
    managementOpenapi,
    "--alphabetize",
    "-o",
    managementGenerated,
  ]);
  canonicalizeTextFile(managementGenerated);
  validateGeneratedTypes(managementGenerated);

  if (mode === "--check") {
    const drift = [];
    if (!filesEqual(openapi, path.join(root, "packages/shared/openapi.json"))) {
      drift.push(
        contractDriftDiagnostic(
          openapi,
          path.join(root, "packages/shared/openapi.json"),
          "packages/shared/openapi.json",
        ),
      );
    }
    if (!filesEqual(generated, path.join(root, "packages/shared/src/generated.ts"))) {
      drift.push(
        contractDriftDiagnostic(
          generated,
          path.join(root, "packages/shared/src/generated.ts"),
          "packages/shared/src/generated.ts",
        ),
      );
    }
    if (
      !filesEqual(
        managementOpenapi,
        path.join(root, "packages/shared/management-openapi.json"),
      )
    ) {
      drift.push(
        contractDriftDiagnostic(
          managementOpenapi,
          path.join(root, "packages/shared/management-openapi.json"),
          "packages/shared/management-openapi.json",
        ),
      );
    }
    if (
      !filesEqual(
        managementGenerated,
        path.join(root, "packages/shared/src/management-generated.ts"),
      )
    ) {
      drift.push(
        contractDriftDiagnostic(
          managementGenerated,
          path.join(root, "packages/shared/src/management-generated.ts"),
          "packages/shared/src/management-generated.ts",
        ),
      );
    }
    if (drift.length) {
      throw new SafeFileError(drift.join("\n"));
    }
  } else {
    safeReplace(openapi, "packages/shared/openapi.json", root);
    safeReplace(generated, "packages/shared/src/generated.ts", root);
    safeReplace(
      managementOpenapi,
      "packages/shared/management-openapi.json",
      root,
    );
    safeReplace(
      managementGenerated,
      "packages/shared/src/management-generated.ts",
      root,
    );
  }
} catch (error) {
  const message =
    error instanceof SafeFileError
      ? error.message
      : "CodeShield contract generation failed safely.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    shell: false,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) {
    throw new SafeFileError("A contract generator process failed.");
  }
}

function validateOpenApi(file) {
  let value;
  try {
    value = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    throw new SafeFileError("Generated OpenAPI document is not valid JSON.");
  }
  const required = ["/health", "/version", "/scan/text"];
  if (
    typeof value.openapi !== "string" ||
    !value.openapi.startsWith("3.") ||
    value.info?.title !== "CodeShield AI Local Engine" ||
    !required.every((entry) => value.paths?.[entry])
  ) {
    throw new SafeFileError("Generated OpenAPI document failed structural validation.");
  }
}

function validateGeneratedTypes(file) {
  const value = readFileSync(file, "utf8");
  if (value.length < 100 || !value.includes("export interface paths")) {
    throw new SafeFileError("Generated TypeScript contracts failed validation.");
  }
}

function validateManagementOpenApi(file) {
  let value;
  try {
    value = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    throw new SafeFileError("Generated management OpenAPI document is not valid JSON.");
  }
  const required = [
    "/health",
    "/version",
    "/v1/device-tokens",
    "/v1/policy-bundles/releases",
    "/v1/policy-bundles/latest",
    "/v1/audit-events/batch",
  ];
  if (
    typeof value.openapi !== "string" ||
    !value.openapi.startsWith("3.") ||
    value.info?.title !== "CodeShield Metadata Management API" ||
    !required.every((entry) => value.paths?.[entry])
  ) {
    throw new SafeFileError(
      "Generated management OpenAPI document failed structural validation.",
    );
  }
}
