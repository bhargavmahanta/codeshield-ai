import { cache } from "react";
import { redirect } from "next/navigation";

import { createServerSupabaseClient } from "@/lib/supabase/server";

export type OrganizationRole =
  | "administrator"
  | "security_analyst"
  | "developer";

export type DashboardContext = {
  userId: string;
  organizationId: string;
  organizationName: string;
  role: OrganizationRole;
};

export const requireDashboardContext = cache(
  async (): Promise<DashboardContext> => {
    const supabase = await createServerSupabaseClient();
    const {
      data: { user },
      error: userError
    } = await supabase.auth.getUser();
    if (!user || userError) {
      redirect("/sign-in");
    }
    const { data: memberships, error } = await supabase
      .from("memberships")
      .select("organization_id,role")
      .eq("user_id", user.id)
      .eq("active", true)
      .order("created_at", { ascending: true })
      .limit(1);
    if (error || !memberships?.length) {
      throw new Error("CS_DASHBOARD_MEMBERSHIP");
    }
    const membership = memberships[0] as {
      organization_id: string;
      role: OrganizationRole;
    };
    const { data: organization, error: organizationError } = await supabase
      .from("organizations")
      .select("display_name")
      .eq("id", membership.organization_id)
      .single();
    if (organizationError || !organization) {
      throw new Error("CS_DASHBOARD_ORGANIZATION");
    }
    return {
      userId: user.id,
      organizationId: membership.organization_id,
      organizationName: String(organization.display_name),
      role: membership.role
    };
  }
);
