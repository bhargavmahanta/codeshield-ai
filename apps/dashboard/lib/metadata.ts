import { requireDashboardContext } from "@/lib/auth";
import { createServerSupabaseClient } from "@/lib/supabase/server";

const PROHIBITED_FIELD =
  /(prompt|response|source_?code|preview|path|credential|secret|password|pseudonym|vault|private_?key|raw_?(value|finding|content))/iu;
const PROHIBITED_VALUE =
  /(?:^[A-Za-z]:[\\/]|^[/\\]{1,2}|-----BEGIN [A-Z ]+-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})/u;

export const metadataViews = {
  findings: {
    table: "compliance_summaries",
    title: "Aggregate findings",
    description: "Period summaries contain counts and highest sensitivity only.",
    columns: [
      "period_start",
      "period_end",
      "category_counts",
      "action_counts",
      "highest_sensitivity",
      "generated_at"
    ]
  },
  audit: {
    table: "audit_events",
    title: "Audit metadata",
    description: "HMAC event IDs, aggregate counts, actions, and latency buckets.",
    columns: [
      "event_hmac",
      "endpoint_class",
      "category_counts",
      "action_counts",
      "highest_sensitivity",
      "status_bucket",
      "latency_bucket",
      "detector_version",
      "model_version",
      "occurred_at"
    ]
  },
  providers: {
    table: "provider_profile_versions",
    title: "Provider history",
    description: "Released and reviewable profile versions with evidence digests.",
    columns: [
      "version",
      "status",
      "evidence_digest",
      "created_at",
      "released_at"
    ]
  },
  destinations: {
    table: "destination_versions",
    title: "Destinations",
    description: "Versioned sensitivity ceilings and release states.",
    columns: ["version", "sensitivity_ceiling", "status", "created_at"]
  },
  policies: {
    table: "policy_versions",
    title: "Policy versions",
    description: "Version, state, revision, and release history without source content.",
    columns: ["version", "status", "revision", "created_at", "updated_at"]
  },
  devices: {
    table: "devices",
    title: "Devices",
    description: "Enrollment and revocation state; device tokens are never displayed here.",
    columns: [
      "id",
      "device_id",
      "display_name",
      "status",
      "last_policy_sequence",
      "created_at",
      "revoked_at"
    ]
  },
  attestations: {
    table: "attestations",
    title: "Attestations",
    description: "Profile evidence state and bounded validity metadata.",
    columns: [
      "attestation_id",
      "status",
      "evidence_digest",
      "issued_at",
      "expires_at",
      "updated_at"
    ]
  },
  feedback: {
    table: "safe_feedback",
    title: "Safe feedback",
    description: "Category, action, sensitivity, and review status only.",
    columns: [
      "category",
      "action",
      "sensitivity",
      "status_bucket",
      "detector_version",
      "state",
      "created_at"
    ]
  },
  exceptions: {
    table: "exceptions",
    title: "Exceptions",
    description: "Structured category and destination exceptions with expiry.",
    columns: [
      "exception_id",
      "category",
      "destination_id",
      "action",
      "reason_code",
      "status",
      "expires_at"
    ]
  },
  members: {
    table: "memberships",
    title: "Members",
    description: "Tenant-scoped membership role and active state.",
    columns: ["user_id", "role", "active", "created_at", "updated_at"]
  }
} as const;

export type MetadataViewName = keyof typeof metadataViews;
export type MetadataRow = Record<string, unknown>;

export async function loadMetadataView(name: MetadataViewName) {
  const context = await requireDashboardContext();
  const config = metadataViews[name];
  const supabase = await createServerSupabaseClient();
  const { data, error } = await supabase
    .from(config.table)
    .select(config.columns.join(","))
    .eq("organization_id", context.organizationId)
    .limit(100);
  if (error) {
    throw new Error("CS_DASHBOARD_METADATA_QUERY");
  }
  const rows = (data ?? []) as unknown as MetadataRow[];
  validateRows(rows, config.columns);
  return { context, config, rows };
}

export function validateRows(
  rows: MetadataRow[],
  columns: readonly string[]
) {
  if (columns.some((column) => PROHIBITED_FIELD.test(column))) {
    throw new Error("CS_DASHBOARD_PROHIBITED_FIELD");
  }
  for (const row of rows) {
    if (Object.keys(row).some((key) => !columns.includes(key))) {
      throw new Error("CS_DASHBOARD_UNEXPECTED_FIELD");
    }
    for (const [key, value] of Object.entries(row)) {
      if (
        PROHIBITED_FIELD.test(key) ||
        (typeof value === "string" && PROHIBITED_VALUE.test(value))
      ) {
        throw new Error("CS_DASHBOARD_PROHIBITED_VALUE");
      }
      if (value !== null && typeof value === "object") {
        validateCounts(value);
      }
    }
  }
}

export function displayValue(value: unknown) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  if (typeof value === "number" || typeof value === "string") {
    return String(value);
  }
  validateCounts(value);
  return JSON.stringify(value);
}

function validateCounts(value: unknown) {
  if (
    !value ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    Object.entries(value).some(
      ([key, count]) =>
        !/^[A-Z][A-Z0-9_]{0,63}$/u.test(key) ||
        typeof count !== "number" ||
        !Number.isInteger(count) ||
        count < 0
    )
  ) {
    throw new Error("CS_DASHBOARD_INVALID_AGGREGATE");
  }
}
