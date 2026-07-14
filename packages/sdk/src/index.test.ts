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
});
