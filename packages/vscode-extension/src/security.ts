import { createHash } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import path from "node:path";

const URI_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/u;

export function normalizeRelativePath(value: string): string | undefined {
  if (!value || value.length > 1024 || value.includes("\0")) {
    return undefined;
  }
  const normalized = value.replaceAll("\\", "/");
  if (
    normalized.startsWith("/") ||
    normalized.startsWith("//") ||
    URI_SCHEME.test(normalized)
  ) {
    return undefined;
  }
  const parts = normalized.split("/");
  if (parts.some((part) => !part || part === "." || part === "..")) {
    return undefined;
  }
  return parts.join("/");
}

export function pathInside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  );
}

export function resolveTrustedPolicy(
  workspaceRoot: string,
  configuredPath: string,
): string | undefined {
  if (!configuredPath) {
    return undefined;
  }
  const relative = normalizeRelativePath(configuredPath);
  if (!relative) {
    throw new Error("CS_POLICY_PATH_INVALID");
  }
  const root = realpathSync(workspaceRoot);
  const candidate = path.resolve(root, ...relative.split("/"));
  const resolved = realpathSync(candidate);
  if (!pathInside(root, resolved) || !lstatSync(resolved).isFile()) {
    throw new Error("CS_POLICY_PATH_INVALID");
  }
  return relative;
}

export function resolveWorkspaceFile(
  workspaceRoot: string,
  relativePath: string,
): string {
  const relative = normalizeRelativePath(relativePath);
  if (!relative) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  const root = realpathSync(workspaceRoot);
  const candidate = path.resolve(root, ...relative.split("/"));
  if (!pathInside(root, candidate)) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  const resolved = realpathSync(candidate);
  if (!pathInside(root, resolved) || !lstatSync(resolved).isFile()) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return resolved;
}

export interface OneBasedRange {
  readonly line: number;
  readonly column: number;
  readonly endLine?: number;
  readonly endColumn?: number;
}

export interface ValidatedRange {
  readonly startLine: number;
  readonly startColumn: number;
  readonly endLine: number;
  readonly endColumn: number;
}

export function validateOneBasedRange(
  location: OneBasedRange,
  lineLengths: readonly number[],
): ValidatedRange {
  const startLine = location.line - 1;
  const startColumn = location.column - 1;
  const endLine = (location.endLine ?? location.line) - 1;
  const defaultEndColumn =
    endLine === startLine ? location.column + 1 : 1;
  const endColumn = (location.endColumn ?? defaultEndColumn) - 1;
  if (
    !Number.isInteger(startLine) ||
    !Number.isInteger(startColumn) ||
    !Number.isInteger(endLine) ||
    !Number.isInteger(endColumn) ||
    startLine < 0 ||
    startColumn < 0 ||
    endLine < startLine ||
    startLine >= lineLengths.length ||
    endLine >= lineLengths.length ||
    startColumn > lineLengths[startLine]! ||
    endColumn > lineLengths[endLine]! ||
    (endLine === startLine && endColumn <= startColumn)
  ) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return { startLine, startColumn, endLine, endColumn };
}

export function formatOperationEvent(
  code: string,
  count?: number,
  highestSeverity?: string,
): string {
  if (
    !/^CS_[A-Z_]+$/u.test(code) ||
    (count !== undefined && (!Number.isInteger(count) || count < 0)) ||
    (highestSeverity !== undefined &&
      !["none", "low", "medium", "high", "critical"].includes(highestSeverity))
  ) {
    throw new Error("CS_EXTENSION_EVENT_INVALID");
  }
  const fields = [code];
  if (count !== undefined) {
    fields.push(`count=${count}`);
  }
  if (highestSeverity !== undefined) {
    fields.push(`highest=${highestSeverity}`);
  }
  return fields.join(" ");
}

export function contentFingerprint(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function isBinaryText(value: string): boolean {
  return value.includes("\0");
}

export function safeSourcePath(fileName: string, workspaceRoot: string): string | undefined {
  const relative = path.relative(workspaceRoot, fileName);
  return normalizeRelativePath(relative);
}
