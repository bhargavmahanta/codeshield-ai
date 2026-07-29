import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  contentFingerprint,
  formatOperationEvent,
  isBinaryText,
  normalizeRelativePath,
  pathInside,
  resolveTrustedPolicy,
  resolveWorkspaceFile,
  safeSourcePath,
  validateOneBasedRange,
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

  it("rejects workspace finding paths that escape through links", () => {
    const parent = mkdtempSync(path.join(tmpdir(), "codeshield-vscode-link-"));
    temporaryDirectories.push(parent);
    const root = path.join(parent, "workspace");
    const outside = path.join(parent, "outside");
    mkdirSync(root);
    mkdirSync(outside);
    writeFileSync(path.join(root, "inside.ts"), "safe\n");
    writeFileSync(path.join(outside, "outside.ts"), "outside\n");
    symlinkSync(
      outside,
      path.join(root, "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );

    expect(resolveWorkspaceFile(root, "inside.ts")).toBe(
      path.join(root, "inside.ts"),
    );
    expect(() => resolveWorkspaceFile(root, "linked/outside.ts")).toThrow(
      "CS_ENGINE_RESULT_INVALID",
    );
  });

  it("validates document ranges before diagnostics are committed", () => {
    expect(
      validateOneBasedRange(
        { line: 1, column: 2, endLine: 2, endColumn: 3 },
        [4, 5],
      ),
    ).toEqual({
      startLine: 0,
      startColumn: 1,
      endLine: 1,
      endColumn: 2,
    });
    expect(() =>
      validateOneBasedRange(
        { line: 2, column: 7, endLine: 2, endColumn: 8 },
        [4, 5],
      ),
    ).toThrow("CS_ENGINE_RESULT_INVALID");
    expect(() =>
      validateOneBasedRange(
        { line: 2, column: 3, endLine: 1, endColumn: 4 },
        [4, 5],
      ),
    ).toThrow("CS_ENGINE_RESULT_INVALID");
  });

  it("formats output events without paths, names, or durations", () => {
    const event = formatOperationEvent("CS_SCAN_COMPLETED", 2, "high");
    expect(event).toBe("CS_SCAN_COMPLETED count=2 highest=high");
    expect(event).not.toContain("target=");
    expect(event).not.toContain("duration");
  });
});
