import { OverviewChart } from "@/components/overview-chart";
import { PageHeading } from "@/components/page-heading";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { requireDashboardContext } from "@/lib/auth";
import { createServerSupabaseClient } from "@/lib/supabase/server";

type AuditSummary = {
  category_counts: Record<string, number>;
  highest_sensitivity: string;
  status_bucket: string;
  latency_bucket: string;
};

export default async function OverviewPage() {
  const context = await requireDashboardContext();
  const supabase = await createServerSupabaseClient();
  const { data, error } = await supabase
    .from("audit_events")
    .select(
      "category_counts,highest_sensitivity,status_bucket,latency_bucket"
    )
    .eq("organization_id", context.organizationId)
    .limit(100);
  const rows = error ? [] : ((data ?? []) as AuditSummary[]);
  const categories = new Map<string, number>();
  for (const row of rows) {
    for (const [category, count] of Object.entries(row.category_counts ?? {})) {
      if (
        /^[A-Z][A-Z0-9_]{0,63}$/u.test(category) &&
        Number.isSafeInteger(count) &&
        count >= 0
      ) {
        categories.set(category, (categories.get(category) ?? 0) + count);
      }
    }
  }
  const chartValues = [...categories]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([category, count]) => ({ category, count }));
  const highest =
    rows.find((row) => row.highest_sensitivity === "restricted")
      ?.highest_sensitivity ??
    rows.find((row) => row.highest_sensitivity === "confidential")
      ?.highest_sensitivity ??
    rows[0]?.highest_sensitivity ??
    "none";
  return (
    <>
      <PageHeading
        title="Security overview"
        description="A tenant-scoped view of aggregate actions, sensitivity, and operational health."
      />
      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <Metric title="Audit events" value={String(rows.length)} />
        <Metric title="Highest sensitivity" value={highest} badge />
        <Metric
          title="Blocked operations"
          value={String(
            rows.filter((row) => row.status_bucket === "blocked").length
          )}
        />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Finding categories</CardTitle>
          <CardDescription>
            Aggregated category counts only. Source content never reaches this
            dashboard.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {chartValues.length ? (
            <OverviewChart values={chartValues} />
          ) : (
            <p className="py-16 text-center text-sm text-slate-500">
              No aggregate audit metadata yet.
            </p>
          )}
        </CardContent>
      </Card>
    </>
  );
}

function Metric({
  title,
  value,
  badge = false
}: {
  title: string;
  value: string;
  badge?: boolean;
}) {
  return (
    <Card>
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardTitle className="text-2xl">
          {badge ? <Badge>{value}</Badge> : value}
        </CardTitle>
      </CardHeader>
    </Card>
  );
}
