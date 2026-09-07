import {
  releasePolicy,
  updatePolicyDraft
} from "@/actions/management";
import { StatefulAction } from "@/components/action-feedback";
import { MetadataTable } from "@/components/metadata-table";
import { PageHeading } from "@/components/page-heading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { requireDashboardContext } from "@/lib/auth";
import { validateRows, type MetadataRow } from "@/lib/metadata";
import { createServerSupabaseClient } from "@/lib/supabase/server";

const displayColumns = [
  "policy_id",
  "display_name",
  "mandatory",
  "version",
  "status",
  "revision",
  "updated_at"
] as const;

type PolicyVersionRow = {
  id: string;
  version: number;
  status: string;
  revision: number;
  policy_document: unknown;
  updated_at: string;
  policies:
    | { policy_id: string; display_name: string; mandatory: boolean }
    | Array<{ policy_id: string; display_name: string; mandatory: boolean }>
    | null;
};

export default async function PoliciesPage() {
  const context = await requireDashboardContext();
  const supabase = await createServerSupabaseClient();
  const { data, error } = await supabase
    .from("policy_versions")
    .select(
      "id,version,status,revision,policy_document,updated_at,policies(policy_id,display_name,mandatory)"
    )
    .eq("organization_id", context.organizationId)
    .order("created_at", { ascending: false })
    .limit(100);
  if (error) {
    throw new Error("CS_DASHBOARD_METADATA_QUERY");
  }
  const versions = (data ?? []) as unknown as PolicyVersionRow[];
  const rows: MetadataRow[] = versions.map((version) => {
    const relation = Array.isArray(version.policies)
      ? version.policies[0]
      : version.policies;
    return {
      policy_id: relation?.policy_id ?? "unknown",
      display_name: relation?.display_name ?? "Unknown",
      mandatory: relation?.mandatory ?? false,
      version: version.version,
      status: version.status,
      revision: version.revision,
      updated_at: version.updated_at
    };
  });
  validateRows(rows, displayColumns);
  const draft = versions.find((item) => item.status === "draft");
  const releasable = versions.find((item) =>
    ["approved", "released"].includes(item.status)
  );
  const draftDocument =
    draft?.policy_document &&
    typeof draft.policy_document === "object" &&
    !Array.isArray(draft.policy_document)
      ? (draft.policy_document as Record<string, unknown>)
      : undefined;
  return (
    <div className="space-y-8">
      <div>
        <PageHeading
          title="Policy versions and releases"
          description="Structured policy metadata with optimistic revision checks and immutable signed releases."
        />
        <MetadataTable rows={rows} columns={displayColumns} />
      </div>
      {draft &&
      draftDocument &&
      ["administrator", "security_analyst"].includes(context.role) ? (
        <Card>
          <CardHeader>
            <CardTitle>Edit draft metadata</CardTitle>
          </CardHeader>
          <CardContent>
            <StatefulAction action={updatePolicyDraft} label="Save draft">
              <input type="hidden" name="id" value={draft.id} />
              <input type="hidden" name="revision" value={draft.revision} />
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="policy-name">Name</Label>
                  <Input
                    id="policy-name"
                    name="name"
                    defaultValue={String(draftDocument.name ?? "")}
                    required
                    maxLength={120}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="description-code">Description code</Label>
                  <Input
                    id="description-code"
                    name="description_code"
                    defaultValue={String(
                      draftDocument.description_code ?? "POLICY_DEFAULT"
                    )}
                    required
                    maxLength={128}
                  />
                </div>
              </div>
            </StatefulAction>
          </CardContent>
        </Card>
      ) : null}
      {releasable && context.role === "administrator" ? (
        <Card>
          <CardHeader>
            <CardTitle>Create signed release</CardTitle>
          </CardHeader>
          <CardContent>
            <StatefulAction action={releasePolicy} label="Release for seven days">
              <input
                type="hidden"
                name="policy_version_id"
                value={releasable.id}
              />
              <p className="text-sm text-slate-400">
                Releases are immutable, monotonic, and valid offline for at most
                seven days.
              </p>
            </StatefulAction>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
