import { describe, expect, it } from "vitest";

import { displayValue, validateRows } from "@/lib/metadata";

describe("metadata boundary", () => {
  it("accepts aggregate-only rows", () => {
    expect(() =>
      validateRows(
        [{ category_counts: { API_KEY: 2 }, status_bucket: "blocked" }],
        ["category_counts", "status_bucket"]
      )
    ).not.toThrow();
  });

  it.each([
    [{ source_path: "src/app.ts" }, ["source_path"]],
    [{ category: "C:\\Users\\person\\repo" }, ["category"]],
    [{ raw_value: "redacted" }, ["raw_value"]],
    [{ category: "sk-example-value-that-must-not-render" }, ["category"]]
  ])("rejects prohibited metadata", (row, columns) => {
    expect(() => validateRows([row], columns)).toThrow(
      /^CS_DASHBOARD_PROHIBITED_/u
    );
  });

  it("rejects unknown response fields", () => {
    expect(() =>
      validateRows([{ status: "valid", unexpected: "value" }], ["status"])
    ).toThrow("CS_DASHBOARD_UNEXPECTED_FIELD");
  });

  it("renders only bounded aggregate JSON", () => {
    expect(displayValue({ API_KEY: 3 })).toBe('{"API_KEY":3}');
    expect(() => displayValue({ API_KEY: "3" })).toThrow(
      "CS_DASHBOARD_INVALID_AGGREGATE"
    );
  });
});
