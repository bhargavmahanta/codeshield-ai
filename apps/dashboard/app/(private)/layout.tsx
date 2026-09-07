import type { ReactNode } from "react";

import { DashboardShell } from "@/components/dashboard-shell";
import { requireDashboardContext } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function PrivateLayout({
  children
}: {
  children: ReactNode;
}) {
  const context = await requireDashboardContext();
  return <DashboardShell context={context}>{children}</DashboardShell>;
}
