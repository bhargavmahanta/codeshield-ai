import { afterEach, describe, expect, it } from "vitest";

import {
  managementApiOrigin,
  publicSupabaseConfiguration
} from "@/lib/environment";

const original = { ...process.env };

afterEach(() => {
  process.env = { ...original };
});

describe("local-only configuration", () => {
  it("accepts explicit loopback origins", () => {
    process.env.NEXT_PUBLIC_SUPABASE_URL = "http://127.0.0.1:54321";
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY = "local-publishable";
    process.env.CODESHIELD_MANAGEMENT_API_URL = "http://[::1]:8766";
    expect(publicSupabaseConfiguration().url).toBe(
      "http://127.0.0.1:54321"
    );
    expect(managementApiOrigin()).toBe("http://[::1]:8766");
  });

  it.each([
    "https://example.invalid",
    "http://10.0.0.1:54321",
    "http://127.0.0.1:54321/path",
    "http://localhost:54321?token=value"
  ])("rejects non-loopback or non-origin values", (value) => {
    process.env.CODESHIELD_MANAGEMENT_API_URL = value;
    expect(() => managementApiOrigin()).toThrow(
      "CS_DASHBOARD_MANAGEMENT_CONFIGURATION"
    );
  });
});
