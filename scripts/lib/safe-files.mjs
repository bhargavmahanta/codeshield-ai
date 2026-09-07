import {
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

export const DIST_TARGETS = [
  "packages/shared/dist",
  "packages/cli/dist",
  "packages/sdk/dist",
  "packages/vscode-extension/dist",
  "apps/dashboard/.next",
];

export const CONTRACT_TARGETS = [
  "packages/shared/openapi.json",
  "packages/shared/src/generated.ts",
  "packages/shared/management-openapi.json",
  "packages/shared/src/management-generated.ts",
];

export class SafeFileError extends Error {
  constructor(message) {
    super(message);
    this.name = "SafeFileError";
  }
}

export function cleanBuildOutputs(root) {
  for (const relative of DIST_TARGETS) {
    const target = resolveKnownPath(root, relative, DIST_TARGETS);
    if (!existsSync(target)) {
      continue;
    }
    const stat = lstatSync(target);
    if (stat.isSymbolicLink()) {
      throw new SafeFileError(`Refusing to clean symbolic output path: ${relative}`);
    }
    const expectedParent = path.resolve(root, path.dirname(relative));
    if (path.dirname(target) !== expectedParent) {
      throw new SafeFileError(`Refusing unexpected output parent: ${relative}`);
    }
    try {
      rmSync(target, {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 150,
      });
    } catch {
      throw new SafeFileError(
        `Unable to clean generated output ${relative}; close tools using that directory and retry.`,
      );
    }
  }
}

export function safeReplace(source, destinationRelative, root) {
  const destination = resolveKnownPath(root, destinationRelative, CONTRACT_TARGETS);
  const directory = path.dirname(destination);
  const nonce = `${process.pid}-${Date.now()}`;
  const sibling = path.join(directory, `.${path.basename(destination)}.${nonce}.tmp`);
  const backup = path.join(directory, `.${path.basename(destination)}.${nonce}.bak`);
  let movedOriginal = false;
  let copiedBackup = false;
  let replaced = false;

  try {
    copyFileSync(source, sibling);
    const descriptor = openSync(sibling, "r+");
    try {
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }

    if (!existsSync(destination)) {
      renameSync(sibling, destination);
      replaced = true;
      return;
    }

    try {
      renameSync(destination, backup);
      movedOriginal = true;
      renameSync(sibling, destination);
      replaced = true;
    } catch {
      if (movedOriginal) {
        throw new Error("atomic replacement failed after backup");
      }
      copyFileSync(destination, backup);
      copiedBackup = true;
      copyFileSync(source, destination);
      const destinationDescriptor = openSync(destination, "r+");
      try {
        fsyncSync(destinationDescriptor);
      } finally {
        closeSync(destinationDescriptor);
      }
      if (!readFileSync(destination).equals(readFileSync(source))) {
        throw new Error("replacement validation failed");
      }
      replaced = true;
    }
  } catch {
    try {
      rmSync(sibling, { force: true });
      if (movedOriginal && !existsSync(destination) && existsSync(backup)) {
        renameSync(backup, destination);
      } else if (copiedBackup && existsSync(backup)) {
        copyFileSync(backup, destination);
      }
    } catch {
      // Preserve the original sanitized failure below.
    }
    throw new SafeFileError(
      `Unable to replace generated file ${destinationRelative}; close tools locking it and retry.`,
    );
  } finally {
    try {
      if (!replaced && movedOriginal && !existsSync(destination) && existsSync(backup)) {
        renameSync(backup, destination);
      }
      rmSync(sibling, { force: true });
      rmSync(backup, { force: true });
    } catch {
      // A successful replacement must not be hidden by backup cleanup.
    }
  }
}

export function filesEqual(left, right) {
  if (!existsSync(left) || !existsSync(right)) {
    return false;
  }
  return readFileSync(left).equals(readFileSync(right));
}

export function canonicalizeText(value) {
  const withoutBom = value.startsWith("\uFEFF") ? value.slice(1) : value;
  const lines = withoutBom
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/u, ""));
  while (lines.length && lines.at(-1) === "") {
    lines.pop();
  }
  return `${lines.join("\n")}\n`;
}

export function canonicalizeTextFile(file) {
  const canonical = canonicalizeText(readFileSync(file, "utf8"));
  writeFileSync(file, canonical, { encoding: "utf8" });
}

export function canonicalizeJson(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalizeJson);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareOrdinal)
        .map((key) => [key, canonicalizeJson(value[key])]),
    );
  }
  return value;
}

export function canonicalizeJsonFile(file) {
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8").replace(/^\uFEFF/u, ""));
    const canonical = `${JSON.stringify(canonicalizeJson(parsed), null, 2)}\n`;
    writeFileSync(file, canonical, { encoding: "utf8" });
  } catch {
    throw new SafeFileError("Generated OpenAPI document is not valid JSON.");
  }
}

export function contractDriftDiagnostic(generated, tracked, relative) {
  if (!CONTRACT_TARGETS.includes(relative)) {
    throw new SafeFileError(`Refusing unknown generated path: ${relative}`);
  }
  const generatedBytes = readFileOrEmpty(generated);
  const trackedBytes = readFileOrEmpty(tracked);
  return (
    `Generated contract drift: ${relative} ` +
    `(tracked bytes=${trackedBytes.length}, sha256=${digest(trackedBytes)}, ` +
    `eol=${lineEndingKind(trackedBytes)}; generated bytes=${generatedBytes.length}, ` +
    `sha256=${digest(generatedBytes)}, eol=${lineEndingKind(generatedBytes)}; ` +
    `first differing line=${firstDifferingLine(trackedBytes, generatedBytes)})`
  );
}

function resolveKnownPath(root, relative, allowed) {
  if (!allowed.includes(relative)) {
    throw new SafeFileError(`Refusing unknown generated path: ${relative}`);
  }
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, relative);
  const prefix = resolvedRoot.endsWith(path.sep) ? resolvedRoot : `${resolvedRoot}${path.sep}`;
  if (!resolved.startsWith(prefix)) {
    throw new SafeFileError(`Generated path escapes the repository: ${relative}`);
  }
  return resolved;
}

function compareOrdinal(left, right) {
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
}

function readFileOrEmpty(file) {
  return existsSync(file) ? readFileSync(file) : Buffer.alloc(0);
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function lineEndingKind(value) {
  const text = value.toString("utf8");
  const crlf = (text.match(/\r\n/gu) ?? []).length;
  const withoutCrlf = text.replace(/\r\n/gu, "");
  const lf = (withoutCrlf.match(/\n/gu) ?? []).length;
  const cr = (withoutCrlf.match(/\r/gu) ?? []).length;
  const kinds = Number(crlf > 0) + Number(lf > 0) + Number(cr > 0);
  if (kinds > 1) {
    return "mixed";
  }
  if (crlf) {
    return "crlf";
  }
  if (lf) {
    return "lf";
  }
  if (cr) {
    return "cr";
  }
  return "none";
}

function firstDifferingLine(left, right) {
  const length = Math.min(left.length, right.length);
  let index = 0;
  while (index < length && left[index] === right[index]) {
    index += 1;
  }
  if (index === left.length && index === right.length) {
    return 0;
  }
  const prefix = left.subarray(0, index).toString("utf8");
  return 1 + (prefix.match(/\r\n|\r|\n/gu) ?? []).length;
}
