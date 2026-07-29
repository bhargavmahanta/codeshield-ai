import { normalizeRelativePath } from "./security.js";

const SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const ACTIONS = new Set(["allow", "warn", "mask", "pseudonymize", "block"]);
const SOURCES = new Set(["regex", "fragment", "entropy", "presidio", "gitleaks"]);
const CATEGORIES = new Set([
  "EMAIL",
  "PHONE_NUMBER",
  "IP_ADDRESS",
  "PERSON",
  "LOCATION",
  "PASSWORD",
  "API_KEY",
  "AUTH_TOKEN",
  "JWT",
  "PRIVATE_KEY",
  "DATABASE_CONNECTION_STRING",
  "CLOUD_CREDENTIAL",
  "SESSION_ID",
  "FINANCIAL_IDENTIFIER",
  "GOVERNMENT_IDENTIFIER",
  "BIOMETRIC_IDENTIFIER",
  "HEALTH_INFORMATION",
  "PAYMENT_CARD_DATA",
  "PAYMENT_AUTHENTICATION_DATA",
  "CUSTOMER_RECORD",
  "PRODUCTION_DATA",
  "PROPRIETARY_SOURCE_CODE",
  "THIRD_PARTY_SOURCE_CODE",
  "SYSTEM_PROMPT",
  "INTERNAL_ARCHITECTURE",
  "VULNERABILITY_DETAILS",
  "LEGAL_PRIVILEGED_MATERIAL",
  "MODEL_CONFIGURATION",
  "EXPORT_CONTROLLED_CONTENT",
  "UNKNOWN_SECRET",
]);

export interface SafeFinding {
  readonly id: string;
  readonly category: string;
  readonly severity: string;
  readonly action: string;
  readonly source: string;
  readonly start: number;
  readonly end: number;
  readonly filePath?: string;
  readonly line?: number;
  readonly column?: number;
  readonly endLine?: number;
  readonly endColumn?: number;
}

export interface SafeScanResult {
  readonly findings: readonly SafeFinding[];
  readonly filesScanned: number;
  readonly scannedBytes: number;
  readonly durationMs: number;
}

export interface SafeProtectionResult {
  readonly protectedText: string;
  readonly blocked: boolean;
  readonly replacementCount: number;
}

export interface SafeProviderProfile {
  readonly profileId: string;
  readonly provider: string;
  readonly product: string;
  readonly reviewDue: string;
  readonly referenceOnly: boolean;
}

export function parseScanResult(raw: string, inputLength?: number): SafeScanResult {
  const value = parseObject(raw);
  const findingsValue = value.findings;
  if (!Array.isArray(findingsValue) || findingsValue.length > 10_000) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  const findings = findingsValue.map((entry) => parseFinding(entry, inputLength));
  return {
    findings,
    filesScanned: boundedInteger(value.files_scanned, 0, 10_000_000),
    scannedBytes: boundedInteger(value.scanned_bytes, 0, 1_000_000_000),
    durationMs: boundedNumber(value.duration_ms, 0, 3_600_000),
  };
}

export function parseProtectionResult(
  raw: string,
  maximumOutputBytes: number,
): SafeProtectionResult {
  const value = parseObject(raw);
  if (
    typeof value.protected_text !== "string" ||
    Buffer.byteLength(value.protected_text, "utf8") > maximumOutputBytes ||
    typeof value.blocked !== "boolean" ||
    !Array.isArray(value.replacements)
  ) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return {
    protectedText: value.protected_text,
    blocked: value.blocked,
    replacementCount: value.replacements.length,
  };
}

export function parseProviderProfiles(raw: string): readonly SafeProviderProfile[] {
  const value: unknown = parseJson(raw);
  if (!Array.isArray(value) || value.length > 1000) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return value.map((entry) => {
    const profile = objectValue(entry);
    return {
      profileId: safeLabel(profile.profile_id),
      provider: safeLabel(profile.provider),
      product: safeLabel(profile.product),
      reviewDue: safeDate(profile.review_due),
      referenceOnly: Boolean(profile.reference_only),
    };
  });
}

export function parseAttestationStatus(raw: string): {
  profileId: string;
  profileVersion: string;
  status: string;
} {
  const value = parseObject(raw);
  const status = safeLabel(value.status);
  if (!new Set(["valid", "missing", "stale", "invalid"]).has(status)) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return {
    profileId: safeLabel(value.profile_id),
    profileVersion: safeLabel(value.profile_version),
    status,
  };
}

export function safeFindingMessage(finding: SafeFinding): string {
  const label = finding.category.replaceAll("_", " ").toLowerCase();
  return `Potential ${label}; action ${finding.action}.`;
}

export function safeRemediation(finding: SafeFinding): string {
  if (finding.action === "block") {
    return "Remove or locally protect this value before it leaves the workspace.";
  }
  if (finding.action === "mask" || finding.action === "pseudonymize") {
    return "Use CodeShield protection and review the confirmed edit.";
  }
  return "Review whether this value is appropriate for the intended destination.";
}

function parseFinding(entry: unknown, inputLength?: number): SafeFinding {
  const value = objectValue(entry);
  const start = boundedInteger(value.start, 0, inputLength ?? 1_000_000_000);
  const end = boundedInteger(value.end, 1, inputLength ?? 1_000_000_000);
  const category = safeLabel(value.data_category);
  const severity = safeLabel(value.severity);
  const action = safeLabel(value.recommended_action);
  const source = safeLabel(value.detection_source);
  if (
    end <= start ||
    !CATEGORIES.has(category) ||
    !SEVERITIES.has(severity) ||
    !ACTIONS.has(action) ||
    !SOURCES.has(source)
  ) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  const finding: SafeFinding = {
    id: safeIdentifier(value.finding_id),
    category,
    severity,
    action,
    source,
    start,
    end,
  };
  if (value.file_path !== undefined && value.file_path !== null) {
    const filePath = normalizeRelativePath(safeLabel(value.file_path));
    if (!filePath) {
      throw new Error("CS_ENGINE_RESULT_INVALID");
    }
    Object.assign(finding, { filePath });
  }
  assignOptionalLocation(finding, value);
  return finding;
}

function assignOptionalLocation(
  finding: SafeFinding,
  value: Record<string, unknown>,
): void {
  const mappings = [
    ["line", "line"],
    ["column", "column"],
    ["end_line", "endLine"],
    ["end_column", "endColumn"],
  ] as const;
  for (const [source, destination] of mappings) {
    if (value[source] !== undefined && value[source] !== null) {
      Object.assign(finding, {
        [destination]: boundedInteger(value[source], 1, 100_000_000),
      });
    }
  }
}

function parseObject(raw: string): Record<string, unknown> {
  return objectValue(parseJson(raw));
}

function parseJson(raw: string): unknown {
  if (Buffer.byteLength(raw, "utf8") > 5_000_000) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
}

function objectValue(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return value as Record<string, unknown>;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return value;
}

function boundedNumber(value: unknown, minimum: number, maximum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return value;
}

function safeLabel(value: unknown): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 128 ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return value;
}

function safeIdentifier(value: unknown): string {
  const label = safeLabel(value);
  if (!/^[A-Za-z0-9._-]+$/u.test(label)) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return label;
}

function safeDate(value: unknown): string {
  const label = safeLabel(value);
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(label)) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  return label;
}
