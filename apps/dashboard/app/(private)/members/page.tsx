import { MetadataPage } from "@/components/metadata-page";
import { requireDashboardContext } from "@/lib/auth";

export default async function MembersPage() {
  const context = await requireDashboardContext();
  if (context.role !== "administrator") {
    throw new Error("CS_DASHBOARD_AUTHORIZATION");
  }
  return <MetadataPage view="members" />;
}
