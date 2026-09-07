import { managementApiOrigin } from "@/lib/environment";
import { createServerSupabaseClient } from "@/lib/supabase/server";

export async function callManagementApi<T>(
  path: string,
  init: RequestInit
): Promise<T> {
  if (!path.startsWith("/") || path.includes("..")) {
    throw new Error("CS_DASHBOARD_MANAGEMENT_PATH");
  }
  const supabase = await createServerSupabaseClient();
  const {
    data: { session },
    error
  } = await supabase.auth.getSession();
  if (error || !session?.access_token) {
    throw new Error("CS_DASHBOARD_AUTHENTICATION");
  }
  const response = await fetch(`${managementApiOrigin()}${path}`, {
    ...init,
    cache: "no-store",
    redirect: "error",
    headers: {
      authorization: `Bearer ${session.access_token}`,
      "content-type": "application/json"
    }
  });
  if (!response.ok) {
    throw new Error("CS_DASHBOARD_MANAGEMENT_REQUEST");
  }
  const payload: unknown = await response.json();
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("CS_DASHBOARD_MANAGEMENT_RESPONSE");
  }
  return payload as T;
}
