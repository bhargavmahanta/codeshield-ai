"use server";

import { revalidatePath } from "next/cache";

import { requireDashboardContext } from "@/lib/auth";
import { callManagementApi } from "@/lib/management-api";
import { createServerSupabaseClient } from "@/lib/supabase/server";

export type ActionState = {
  status: "idle" | "success" | "error";
  code?: string;
  token?: string;
};

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export async function issueDeviceToken(
  _state: ActionState,
  formData: FormData
): Promise<ActionState> {
  const context = await requireDashboardContext();
  if (context.role !== "administrator") {
    return { status: "error", code: "CS_DASHBOARD_AUTHORIZATION" };
  }
  const deviceId = String(formData.get("device_id") ?? "");
  const displayName = String(formData.get("display_name") ?? "");
  if (
    !IDENTIFIER.test(deviceId) ||
    displayName.length < 1 ||
    displayName.length > 120
  ) {
    return { status: "error", code: "CS_DASHBOARD_INVALID_INPUT" };
  }
  try {
    const result = await callManagementApi<{
      token?: unknown;
      shown_once?: unknown;
    }>("/v1/device-tokens", {
      method: "POST",
      body: JSON.stringify({
        organization_id: context.organizationId,
        device_id: deviceId,
        display_name: displayName,
        owner_user_id: context.userId
      })
    });
    if (
      result.shown_once !== true ||
      typeof result.token !== "string" ||
      result.token.length > 256
    ) {
      throw new Error("CS_DASHBOARD_MANAGEMENT_RESPONSE");
    }
    revalidatePath("/devices");
    return { status: "success", token: result.token };
  } catch {
    return { status: "error", code: "CS_DASHBOARD_DEVICE_TOKEN" };
  }
}

export async function revokeDevice(formData: FormData) {
  const context = await requireDashboardContext();
  if (context.role !== "administrator") {
    throw new Error("CS_DASHBOARD_AUTHORIZATION");
  }
  const deviceUuid = String(formData.get("device_uuid") ?? "");
  if (!UUID.test(deviceUuid)) {
    throw new Error("CS_DASHBOARD_INVALID_INPUT");
  }
  await callManagementApi(
    `/v1/devices/${deviceUuid}/revoke?organization_id=${context.organizationId}`,
    { method: "POST", body: "{}" }
  );
  revalidatePath("/devices");
}

export async function updatePolicyDraft(
  _state: ActionState,
  formData: FormData
): Promise<ActionState> {
  const context = await requireDashboardContext();
  if (!["administrator", "security_analyst"].includes(context.role)) {
    return { status: "error", code: "CS_DASHBOARD_AUTHORIZATION" };
  }
  const id = String(formData.get("id") ?? "");
  const revision = Number(formData.get("revision"));
  const name = String(formData.get("name") ?? "");
  const descriptionCode = String(formData.get("description_code") ?? "");
  if (
    !UUID.test(id) ||
    !Number.isSafeInteger(revision) ||
    revision < 1 ||
    name.length < 1 ||
    name.length > 120 ||
    !IDENTIFIER.test(descriptionCode)
  ) {
    return { status: "error", code: "CS_DASHBOARD_INVALID_INPUT" };
  }
  const supabase = await createServerSupabaseClient();
  const { data: current, error: readError } = await supabase
    .from("policy_versions")
    .select("id,revision,version,policy_document,status")
    .eq("organization_id", context.organizationId)
    .eq("id", id)
    .eq("status", "draft")
    .single();
  if (
    readError ||
    !current ||
    current.revision !== revision ||
    !current.policy_document ||
    typeof current.policy_document !== "object"
  ) {
    return { status: "error", code: "CS_DASHBOARD_STALE_REVISION" };
  }
  const document = current.policy_document as Record<string, unknown>;
  const nextDocument = {
    name,
    description_code: descriptionCode,
    version: current.version,
    rules: Array.isArray(document.rules) ? document.rules : []
  };
  const { data, error } = await supabase
    .from("policy_versions")
    .update({
      policy_document: nextDocument,
      revision: revision + 1
    })
    .eq("organization_id", context.organizationId)
    .eq("id", id)
    .eq("revision", revision)
    .eq("status", "draft")
    .select("id")
    .maybeSingle();
  if (error || !data) {
    return { status: "error", code: "CS_DASHBOARD_STALE_REVISION" };
  }
  revalidatePath("/policies");
  return { status: "success", code: "CS_DASHBOARD_POLICY_UPDATED" };
}

export async function releasePolicy(
  _state: ActionState,
  formData: FormData
): Promise<ActionState> {
  const context = await requireDashboardContext();
  if (context.role !== "administrator") {
    return { status: "error", code: "CS_DASHBOARD_AUTHORIZATION" };
  }
  const policyVersionId = String(formData.get("policy_version_id") ?? "");
  if (!UUID.test(policyVersionId)) {
    return { status: "error", code: "CS_DASHBOARD_INVALID_INPUT" };
  }
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  try {
    await callManagementApi("/v1/policy-bundles/releases", {
      method: "POST",
      body: JSON.stringify({
        organization_id: context.organizationId,
        policy_version_id: policyVersionId,
        provider_profile_version_ids: [],
        destination_version_ids: [],
        minimum_compatible_engine: "0.9.0",
        expires_at: expiresAt.toISOString()
      })
    });
    revalidatePath("/policies");
    return { status: "success", code: "CS_DASHBOARD_POLICY_RELEASED" };
  } catch {
    return { status: "error", code: "CS_DASHBOARD_POLICY_RELEASE" };
  }
}

export async function submitFeedback(formData: FormData) {
  const context = await requireDashboardContext();
  const category = String(formData.get("category") ?? "");
  const action = String(formData.get("action") ?? "");
  const sensitivity = String(formData.get("sensitivity") ?? "");
  const statusBucket = String(formData.get("status_bucket") ?? "");
  const detectorVersion = String(formData.get("detector_version") ?? "");
  if (
    !/^[A-Z][A-Z0-9_]{0,63}$/u.test(category) ||
    !["allow", "warn", "block", "protect"].includes(action) ||
    !["public", "internal", "confidential", "restricted"].includes(
      sensitivity
    ) ||
    !["expected", "false_positive", "false_negative", "needs_review"].includes(
      statusBucket
    ) ||
    !IDENTIFIER.test(detectorVersion)
  ) {
    throw new Error("CS_DASHBOARD_INVALID_INPUT");
  }
  const supabase = await createServerSupabaseClient();
  const { error } = await supabase.from("safe_feedback").insert({
    organization_id: context.organizationId,
    submitted_by: context.userId,
    category,
    action,
    sensitivity,
    status_bucket: statusBucket,
    detector_version: detectorVersion
  });
  if (error) {
    throw new Error("CS_DASHBOARD_FEEDBACK");
  }
  revalidatePath("/feedback");
}
