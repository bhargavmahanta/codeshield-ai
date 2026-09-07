import { MetadataTable } from "@/components/metadata-table";
import { PageHeading } from "@/components/page-heading";
import { requireDashboardContext } from "@/lib/auth";
import {
  validateRows,
  type MetadataRow
} from "@/lib/metadata";
import { createServerSupabaseClient } from "@/lib/supabase/server";

const columns = ["kind", "identifier", "version", "status", "recorded_at"] as const;

export default async function VersionsPage() {
  const context = await requireDashboardContext();
  const supabase = await createServerSupabaseClient();
  const [detectors, models] = await Promise.all([
    supabase
      .from("detector_versions")
      .select("detector_id,version,status,recorded_at")
      .eq("organization_id", context.organizationId),
    supabase
      .from("model_versions")
      .select("model_id,version,status,recorded_at")
      .eq("organization_id", context.organizationId)
  ]);
  if (detectors.error || models.error) {
    throw new Error("CS_DASHBOARD_METADATA_QUERY");
  }
  const rows: MetadataRow[] = [
    ...(detectors.data ?? []).map((row) => ({
      kind: "detector",
      identifier: row.detector_id,
      version: row.version,
      status: row.status,
      recorded_at: row.recorded_at
    })),
    ...(models.data ?? []).map((row) => ({
      kind: "model",
      identifier: row.model_id,
      version: row.version,
      status: row.status,
      recorded_at: row.recorded_at
    }))
  ];
  validateRows(rows, columns);
  return (
    <>
      <PageHeading
        title="Models and detectors"
        description="Supported, deprecated, and blocked local component versions."
      />
      <MetadataTable rows={rows} columns={columns} />
    </>
  );
}
