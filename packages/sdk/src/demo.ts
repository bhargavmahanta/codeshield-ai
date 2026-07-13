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
