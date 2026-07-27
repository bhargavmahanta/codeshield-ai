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
} from "node:fs";
import path from "node:path";

export const DIST_TARGETS = [
  "packages/shared/dist",
  "packages/cli/dist",
  "packages/sdk/dist",
];

export const CONTRACT_TARGETS = [
  "packages/shared/openapi.json",
  "packages/shared/src/generated.ts",
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
