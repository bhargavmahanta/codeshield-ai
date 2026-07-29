import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  contentFingerprint,
  isBinaryText,
  normalizeRelativePath,
  pathInside,
  resolveTrustedPolicy,
  safeSourcePath,
} from "./security.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("extension path and content safety", () => {
  it("normalizes repository paths and rejects escape forms", () => {
    expect(normalizeRelativePath("src\\settings.ts")).toBe("src/settings.ts");
    for (const unsafe of [
      "../outside.ts",
      "/absolute.ts",
      "C:\\absolute.ts",
      "file:///outside.ts",
      "src//file.ts",
      "src/./file.ts",
      "src\0file.ts",
    ]) {
      expect(normalizeRelativePath(unsafe)).toBeUndefined();
    }
  });

  it("resolves policy files only inside the workspace", () => {
    const root = mkdtempSync(path.join(tmpdir(), "codeshield-vscode-"));
    temporaryDirectories.push(root);
    mkdirSync(path.join(root, "policies"));
    writeFileSync(path.join(root, "policies", "local.yaml"), "rules: []\n");

    expect(resolveTrustedPolicy(root, "policies/local.yaml")).toBe(
      "policies/local.yaml",
    );
    expect(() => resolveTrustedPolicy(root, "../outside.yaml")).toThrow(
      "CS_POLICY_PATH_INVALID",
    );
  });

  it("uses stable fingerprints and identifies binary editor content", () => {
    expect(contentFingerprint("same")).toBe(contentFingerprint("same"));
    expect(contentFingerprint("same")).not.toBe(contentFingerprint("different"));
    expect(isBinaryText("text\0binary")).toBe(true);
    expect(isBinaryText("normal text")).toBe(false);
  });

  it("keeps document locations within their root", () => {
    const root = path.resolve("workspace");
    expect(pathInside(root, path.join(root, "src", "file.ts"))).toBe(true);
    expect(pathInside(root, path.resolve("outside", "file.ts"))).toBe(false);
    expect(safeSourcePath(path.join(root, "src", "file.ts"), root)).toBe(
      "src/file.ts",
    );
  });
});
