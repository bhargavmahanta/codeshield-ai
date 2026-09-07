import { PageHeading } from "@/components/page-heading";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "@/components/ui/card";
import { requireDashboardContext } from "@/lib/auth";

export default async function SettingsPage() {
  const context = await requireDashboardContext();
  if (context.role !== "administrator") {
    throw new Error("CS_DASHBOARD_AUTHORIZATION");
  }
  return (
    <>
      <PageHeading
        title="Settings"
        description="The dashboard stores organizational metadata only."
      />
      <Card>
        <CardHeader>
          <CardTitle>Local management boundary</CardTitle>
          <CardDescription>
            Authentication, signing, and persistence are served by the local
            Supabase and management API processes.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm text-slate-300">
          <p>Organization: {context.organizationName}</p>
          <p>Policy delivery: explicit signed pull</p>
          <p>Audit upload: explicit opt-in</p>
          <p>Prompts, source, findings, paths, and vault material: local only</p>
        </CardContent>
      </Card>
    </>
  );
}
