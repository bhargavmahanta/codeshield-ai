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
