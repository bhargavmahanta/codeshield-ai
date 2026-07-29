import { describe, expect, it } from "vitest";

import {
  parseAttestationStatus,
  parseProtectionResult,
  parseProviderProfiles,
  parseScanResult,
  safeFindingMessage,
} from "./protocol.js";

function scanPayload(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    destination: "local_file",
    findings: [
      {
        finding_id: "safe-id",
        data_category: "API_KEY",
        start: 4,
        end: 12,
        masked_preview: "never-use-engine-previews",
        detection_source: "regex",
        confidence_score: 0.99,
        severity: "high",
        explanation: "untrusted engine text",
        recommended_action: "block",
        file_path: "src/settings.ts",
        line: 1,
        column: 5,
        end_line: 1,
        end_column: 13,
      },
    ],
    files_scanned: 1,
    files_skipped: [],
    scanned_bytes: 20,
    duration_ms: 4.5,
    ...overrides,
  });
}

describe("engine protocol parsing", () => {
  it("retains only allowlisted finding metadata", () => {
    const result = parseScanResult(scanPayload(), 20);

    expect(result.findings[0]).toEqual({
      id: "safe-id",
      category: "API_KEY",
      start: 4,
      end: 12,
      source: "regex",
      severity: "high",
      action: "block",
      filePath: "src/settings.ts",
      line: 1,
      column: 5,
      endLine: 1,
      endColumn: 13,
    });
    expect(JSON.stringify(result)).not.toContain("never-use-engine-previews");
    expect(safeFindingMessage(result.findings[0]!)).toBe(
      "Potential api key; action block.",
    );
  });

  it("rejects traversal, invalid enums, and out-of-range spans", () => {
    const payload = JSON.parse(scanPayload()) as Record<string, unknown>;
    const findings = payload.findings as Array<Record<string, unknown>>;
    findings[0]!.file_path = "../outside.ts";
    expect(() => parseScanResult(JSON.stringify(payload), 20)).toThrow(
      "CS_ENGINE_RESULT_INVALID",
    );

    findings[0]!.file_path = "src/file.ts";
    findings[0]!.severity = "urgent";
    expect(() => parseScanResult(JSON.stringify(payload), 20)).toThrow(
      "CS_ENGINE_RESULT_INVALID",
    );

    findings[0]!.severity = "high";
    findings[0]!.end = 21;
    expect(() => parseScanResult(JSON.stringify(payload), 20)).toThrow(
      "CS_ENGINE_RESULT_INVALID",
    );
  });

  it("parses bounded protection and read-only provider responses", () => {
    expect(
      parseProtectionResult(
        JSON.stringify({
          protected_text: "value=<API_KEY>",
          blocked: false,
          replacements: [{ mode: "type_placeholder" }],
          findings: [],
        }),
        100,
      ),
    ).toEqual({
      protectedText: "value=<API_KEY>",
      blocked: false,
      replacementCount: 1,
    });

    expect(
      parseProviderProfiles(
        JSON.stringify([
          {
            profile_id: "provider-id",
            provider: "Provider",
            product: "Product",
            review_due: "2026-12-31",
            reference_only: false,
          },
        ]),
      ),
    ).toHaveLength(1);
    expect(
      parseAttestationStatus(
        JSON.stringify({
          profile_id: "provider-id",
          profile_version: "2026.07",
          status: "missing",
        }),
      ).status,
    ).toBe("missing");
  });
});
