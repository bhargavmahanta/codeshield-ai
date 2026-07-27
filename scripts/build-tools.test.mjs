import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  cleanBuildOutputs,
  safeReplace,
  SafeFileError,
} from "./lib/safe-files.mjs";


function temporaryRepository() {
  const root = mkdtempSync(path.join(os.tmpdir(), "codeshield-build-tools-"));
  for (const workspace of ["shared", "cli", "sdk"]) {
    mkdirSync(path.join(root, "packages", workspace, "dist"), { recursive: true });
    mkdirSync(path.join(root, "packages", workspace, "src"), { recursive: true });
    writeFileSync(
      path.join(root, "packages", workspace, "dist", "generated.js"),
      "generated",
    );
    writeFileSync(
      path.join(root, "packages", workspace, "src", "index.ts"),
      "source",
    );
  }
  return root;
}


test("cleanBuildOutputs deletes only fixed dist directories", () => {
  const root = temporaryRepository();
  try {
    cleanBuildOutputs(root);
    for (const workspace of ["shared", "cli", "sdk"]) {
      assert.equal(existsSync(path.join(root, "packages", workspace, "dist")), false);
      assert.equal(
        readFileSync(path.join(root, "packages", workspace, "src", "index.ts"), "utf8"),
        "source",
      );
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});


test("safeReplace validates, replaces, and removes temporary files", () => {
  const root = temporaryRepository();
  const generated = path.join(root, "generated-openapi.json");
  const destination = path.join(root, "packages", "shared", "openapi.json");
  writeFileSync(generated, "new-contract");
  writeFileSync(destination, "old-contract");
  try {
    safeReplace(generated, "packages/shared/openapi.json", root);
    assert.equal(readFileSync(destination, "utf8"), "new-contract");
    assert.equal(
      existsSync(path.join(root, "packages", "shared", ".openapi.json.tmp")),
      false,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});


test("safeReplace rejects unknown output targets", () => {
  const root = temporaryRepository();
  try {
    assert.throws(
      () => safeReplace("source", "engine/codeshield/version.py", root),
      SafeFileError,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
