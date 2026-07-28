import { describe, expect, it, vi } from "vitest";

import { CodeShieldApiError, CodeShieldClient } from "./index.js";

const jsonResponse = (payload: object, status = 200) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });

describe("CodeShieldClient", () => {
  it("calls health and version on the configured loopback service", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ status: "ok", service: "codeshield-engine", local_only: true }),
      )
      .mockResolvedValueOnce(jsonResponse({ version: "0.3.0" }));
    const client = new CodeShieldClient({ fetch: fetchMock });

    await expect(client.health()).resolves.toMatchObject({ status: "ok" });
    await expect(client.version()).resolves.toEqual({ version: "0.3.0" });
    expect(fetchMock.mock.calls[0]?.[0].toString()).toBe("http://127.0.0.1:8765/health");
  });

  it("sends typed scan, protect, and restore request shapes", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(
        jsonResponse({ blocked: false, protected_text: "<EMAIL>", replacements: [] }),
      )
      .mockResolvedValueOnce(jsonResponse({ restored_text: "restored" }));
    const client = new CodeShieldClient({ fetch: fetchMock });

    await client.scanText("contact value", "external_llm");
    await client.protect({
      text: "contact value",
      destination: "external_llm",
      mode: "pseudonymize",
      session_id: "sdk-test",
    });
    await client.restore({ text: "<EMAIL>", session_id: "sdk-test" });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(
      JSON.stringify({ text: "contact value", destination: "external_llm" }),
    );
    expect(fetchMock.mock.calls[1]?.[1]?.method).toBe("POST");
  });

  it("aborts timed out requests", async () => {
    const fetchMock = vi.fn<typeof fetch>((_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      }),
    );
    const client = new CodeShieldClient({ fetch: fetchMock, timeoutMs: 5 });

    await expect(client.health()).rejects.toThrow("timed out");
  });

  it("does not leak request values through API or validation errors", async () => {
    const privateValue = "private-value-for-sdk-test";
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({}, 422));
    const client = new CodeShieldClient({ fetch: fetchMock });

    const error = await client.scanText(privateValue).catch((value: unknown) => value);

    expect(error).toBeInstanceOf(CodeShieldApiError);
    expect(String(error)).not.toContain(privateValue);
    expect(() => new CodeShieldClient({ baseUrl: "https://example.test" })).toThrow(
      "loopback",
    );
  });

  it("sends typed LLM assessment and protection requests", async () => {
    const assessment = {
      highest_sensitivity: "public",
      categories: [],
      segments: [],
      action: "allow",
      safe_to_send: true,
      reasons: ["approved"],
      required_transformations: [],
      provider_profile_id: "openai-api-zdr",
      attestation_status: "valid",
      audit_id: "audit-1",
    };
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(assessment))
      .mockResolvedValueOnce(
        jsonResponse({ assessment, protected_segments: [] }),
      );
    const client = new CodeShieldClient({ fetch: fetchMock });
    const payload = {
      segments: [
        {
          segment_id: "one",
          kind: "user" as const,
          content: "public question",
          provenance: "trusted" as const,
        },
      ],
      provider_profile_id: "openai-api-zdr",
      direction: "outbound" as const,
      purpose: "SDK preflight test",
      enabled_features: [],
      privileged_tools: false,
    };

    await client.assessForLlm(payload);
    await client.protectForLlm(payload);

    expect(fetchMock.mock.calls[0]?.[0].toString()).toBe(
      "http://127.0.0.1:8765/llm/assess",
    );
    expect(fetchMock.mock.calls[1]?.[0].toString()).toBe(
      "http://127.0.0.1:8765/llm/protect",
    );
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify(payload));
  });

  it("does not leak LLM segment content in API errors", async () => {
    const privateValue = "confidential-source-fragment";
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({}, 403));
    const client = new CodeShieldClient({ fetch: fetchMock });

    const error = await client
      .assessForLlm({
        segments: [
          {
            segment_id: "one",
            kind: "source_code",
            content: privateValue,
            provenance: "trusted",
          },
        ],
        provider_profile_id: "unknown",
        direction: "outbound",
        purpose: "safe error test",
        enabled_features: [],
        privileged_tools: false,
      })
      .catch((value: unknown) => value);

    expect(String(error)).not.toContain(privateValue);
  });

  it("uses read-only detector and provider interoperability endpoints", async () => {
    const detectorPayload = { profile: "core", detectors: [] };
    const profile = {
      profile_id: "openai-api-zdr",
      version: "2026.07",
    };
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(detectorPayload))
      .mockResolvedValueOnce(jsonResponse([profile]))
      .mockResolvedValueOnce(jsonResponse(profile))
      .mockResolvedValueOnce(jsonResponse({ valid: true, issues: [] }))
      .mockResolvedValueOnce(
        jsonResponse({
          profile_id: "openai-api-zdr",
          profile_version: "2026.07",
          status: "missing",
        }),
      );
    const client = new CodeShieldClient({ fetch: fetchMock });

    await client.detectorStatus();
    await client.listProviders();
    await client.getProvider("openai-api-zdr");
    await client.verifyProviders();
    await client.attestationStatus({
      profile_id: "openai-api-zdr",
      attestation_id: null,
    });

    expect(fetchMock.mock.calls.map((call) => call[0].toString())).toEqual([
      "http://127.0.0.1:8765/detectors/status",
      "http://127.0.0.1:8765/providers",
      "http://127.0.0.1:8765/providers/openai-api-zdr",
      "http://127.0.0.1:8765/providers/verify",
      "http://127.0.0.1:8765/providers/attestations/status",
    ]);
    expect(fetchMock.mock.calls[4]?.[1]?.method).toBe("POST");
  });
});
