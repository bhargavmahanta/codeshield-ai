import type { components } from "@codeshield-ai/shared";

export type Destination = components["schemas"]["Destination"];
export type Finding = components["schemas"]["Finding"];
export type ProtectionMode = components["schemas"]["ProtectionMode"];
export type ProtectionResult = components["schemas"]["ProtectionResult"];
export type ProtectTextRequest = components["schemas"]["ProtectTextRequest"];
export type RestoreTextRequest = components["schemas"]["RestoreTextRequest"];
export type ScanTextRequest = components["schemas"]["ScanTextRequest"];
export type LlmPreflightRequest = components["schemas"]["LlmPreflightRequest"];
export type LlmAssessmentResult = components["schemas"]["LlmAssessmentResult"];
export type LlmProtectionResult = components["schemas"]["LlmProtectionResult"];
export type ContentSegment = components["schemas"]["ContentSegment"];
export type DetectorStatusResponse = components["schemas"]["DetectorStatusResponse"];
export type ProviderProfile = components["schemas"]["ProviderProfile"];
export type ProviderVerificationResponse =
  components["schemas"]["ProviderVerificationResponse"];
export type AttestationStatusRequest =
  components["schemas"]["AttestationStatusRequest"];
export type AttestationStatusResponse =
  components["schemas"]["AttestationStatusResponse"];

export interface HealthResponse {
  status: string;
  service: string;
  local_only: boolean;
}

export interface VersionResponse {
  version: string;
}

export interface RestoreResponse {
  restored_text: string;
}

export interface CodeShieldClientOptions {
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
}

export class CodeShieldApiError extends Error {
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "CodeShieldApiError";
    this.status = status;
  }
}

export class CodeShieldClient {
  readonly baseUrl: URL;
  readonly timeoutMs: number;
  private readonly fetchImplementation: typeof globalThis.fetch;

  constructor(options: CodeShieldClientOptions = {}) {
    this.baseUrl = validateLoopbackUrl(options.baseUrl ?? "http://127.0.0.1:8765");
    this.fetchImplementation = options.fetch ?? globalThis.fetch;
    if (!this.fetchImplementation) {
      throw new CodeShieldApiError("A Fetch API implementation is required.");
    }
    this.timeoutMs = options.timeoutMs ?? 10_000;
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0) {
      throw new CodeShieldApiError("timeoutMs must be a positive number.");
    }
  }

  health(): Promise<HealthResponse> {
    return this.request("/health", { method: "GET" });
  }

  version(): Promise<VersionResponse> {
    return this.request("/version", { method: "GET" });
  }

  detectorStatus(): Promise<DetectorStatusResponse> {
    return this.request("/detectors/status", { method: "GET" });
  }

  listProviders(): Promise<ProviderProfile[]> {
    return this.request("/providers", { method: "GET" });
  }

  getProvider(profileId: string): Promise<ProviderProfile> {
    if (!profileId || profileId.length > 128) {
      throw new CodeShieldApiError("profileId must be between 1 and 128 characters.");
    }
    return this.request(`/providers/${encodeURIComponent(profileId)}`, {
      method: "GET",
    });
  }

  verifyProviders(): Promise<ProviderVerificationResponse> {
    return this.request("/providers/verify", { method: "GET" });
  }

  attestationStatus(
    payload: AttestationStatusRequest,
  ): Promise<AttestationStatusResponse> {
    return this.request(
      "/providers/attestations/status",
      jsonRequest(payload),
    );
  }

  scanText(
    text: string,
    destination: Destination = "local_file",
  ): Promise<Finding[]> {
    const payload: ScanTextRequest = { text, destination };
    return this.request("/scan/text", jsonRequest(payload));
  }

  protect(payload: ProtectTextRequest): Promise<ProtectionResult> {
    return this.request("/protect", jsonRequest(payload));
  }

  restore(payload: RestoreTextRequest): Promise<RestoreResponse> {
    return this.request("/restore", jsonRequest(payload));
  }

  assessForLlm(payload: LlmPreflightRequest): Promise<LlmAssessmentResult> {
    return this.request("/llm/assess", jsonRequest(payload));
  }

  protectForLlm(payload: LlmPreflightRequest): Promise<LlmProtectionResult> {
    return this.request("/llm/protect", jsonRequest(payload));
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImplementation(new URL(path, this.baseUrl), {
        ...init,
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new CodeShieldApiError(
          `CodeShield API request failed with status ${response.status}.`,
          response.status,
        );
      }
      try {
        return (await response.json()) as T;
      } catch {
        throw new CodeShieldApiError("CodeShield API returned an invalid response.");
      }
    } catch (error) {
      if (error instanceof CodeShieldApiError) {
        throw error;
      }
      if (controller.signal.aborted) {
        throw new CodeShieldApiError("CodeShield API request timed out.");
      }
      throw new CodeShieldApiError("CodeShield API request failed.");
    } finally {
      clearTimeout(timeout);
    }
  }
}

function jsonRequest(payload: object): RequestInit {
  return {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  };
}

function validateLoopbackUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new CodeShieldApiError("baseUrl must be a valid loopback URL.");
  }
  const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
  if (!loopbackHosts.has(url.hostname) || !["http:", "https:"].includes(url.protocol)) {
    throw new CodeShieldApiError("baseUrl must use a loopback host.");
  }
  return url;
}
