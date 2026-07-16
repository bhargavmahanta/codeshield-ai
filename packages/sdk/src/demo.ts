import { CodeShieldClient } from "./index.js";

const client = new CodeShieldClient();
const syntheticKey = ["sk", "live", "51ReviewSdkToken93628471"].join("_");
const findings = await client.scanText(`api_key = '${syntheticKey}'`, "private_git");
console.log(
  "scan:",
  findings.map(({ data_category, masked_preview, recommended_action }) => ({
    data_category,
    masked_preview,
    recommended_action,
  })),
);

const preflight = await client.assessForLlm({
  segments: [
    {
      segment_id: "demo-source",
      kind: "source_code",
      provenance: "trusted",
      content: `api_key = '${syntheticKey}'`,
      path: "src/demo.ts",
      language: "typescript",
    },
  ],
  provider_profile_id: "openai-api-zdr",
  direction: "outbound",
  purpose: "phase-4 SDK demonstration",
  enabled_features: [],
  privileged_tools: false,
});
console.log("LLM preflight:", {
  action: preflight.action,
  sensitivity: preflight.highest_sensitivity,
  safe_to_send: preflight.safe_to_send,
  finding_count: preflight.segments.reduce(
    (count, segment) => count + (segment.findings?.length ?? 0),
    0,
  ),
});

const session_id = "phase-3-sdk-demo";
const protectedResult = await client.protect({
  text: "contact = reviewer@example.test",
  destination: "external_llm",
  mode: "pseudonymize",
  session_id,
});
console.log("protected:", protectedResult.protected_text);
const restored = await client.restore({
  text: protectedResult.protected_text,
  session_id,
});
console.log("restore successful:", restored.restored_text.includes("@example.test"));
