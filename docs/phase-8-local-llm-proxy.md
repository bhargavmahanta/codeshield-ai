# Phase 8 — Authenticated Local LLM Proxy

## Outcome

CodeShield 0.8.0 adds a dedicated Python proxy process with a deliberately
narrow OpenAI-compatible surface. One process serves one exact HTTPS
upstream/provider-profile pair. It binds only to `127.0.0.1` or `::1`, requires
a separate local bearer token, replaces that token with the configured
upstream credential, and releases content only after complete outbound and
inbound inspection.

Phase 7 remains intact. The extension now requires engine
`>=0.8.0,<0.9.0`; its trust, subprocess, diagnostics, protection, VSIX, and
VS Code 1.127/1.130 behavior is unchanged.

## Installation and configuration

Install the Python 3.12 engine, create a current provider attestation, and copy
the non-secret example to an absolute machine-local location:

```powershell
python -m pip install -e ".\engine[dev,evaluation]"
codeshield provider attest openai-api-zdr `
  --id local-zdr-review `
  --account-hash <sha256-account-identifier> `
  --evidence-digest <sha256-evidence-digest> `
  --reviewer local-security-review `
  --expires 2026-10-14
Copy-Item .\integrations\llm-proxy\example.config.yaml C:\secure\codeshield-proxy.yaml
codeshield proxy validate-config C:\secure\codeshield-proxy.yaml
```

On Linux, use owner-only permissions such as `chmod 600`. Configuration must
be an absolute regular YAML file, must not be a symbolic link, junction, or
link traversal, and contains no credential values. It fixes:

- schema version, loopback address, and port;
- one exact credential-free HTTPS upstream base URL;
- one provider profile and attestation ID;
- the upstream credential environment-variable name;
- exact model IDs;
- request/response byte caps, concurrency, and timeouts.

Set independent local and upstream credentials, then serve:

```powershell
$env:CODESHIELD_PROXY_TOKEN = "<generate-at-least-32-random-characters>"
$env:OPENAI_API_KEY = "<upstream-credential>"
codeshield proxy serve C:\secure\codeshield-proxy.yaml
```

`CODESHIELD_PROXY_TOKEN` authenticates local clients. It is never forwarded.
The proxy obtains the upstream credential from the named environment variable
and sends it only as the replacement upstream bearer credential. Values never
enter arguments, configuration, temporary files, logs, errors, or audits.

## HTTP interface

- `GET /health`
- `GET /version`
- `GET /v1/models` — returns only the local exact allowlist and never contacts
  the upstream
- `POST /v1/chat/completions`
- `POST /v1/responses`

The POST endpoints and `/v1/models` require
`Authorization: Bearer <CODESHIELD_PROXY_TOKEN>`. Authentication comparison is
constant-time. Errors use fixed OpenAI-style envelopes and codes:

- `CS_PROXY_AUTHENTICATION`
- `CS_PROXY_INVALID_INPUT`
- `CS_PROXY_UNSUPPORTED_FEATURE`
- `CS_PROXY_POLICY_BLOCKED`
- `CS_PROXY_SATURATED`
- `CS_PROXY_TIMEOUT`
- `CS_PROXY_UPSTREAM_FAILURE`
- `CS_PROXY_MALFORMED_RESPONSE`
- `CS_PROXY_INBOUND_BLOCKED`

The compatible subset includes text messages, instructions, common
sampling/token controls, text or JSON-object response formats, reasoning
effort, and function tools. Previous assistant text, tool results, and
function-call outputs are untrusted; tool names, descriptions, schemas, and
arguments are scanned. Any request involving tools is treated as privileged.

Streaming, images, audio, files, batches, realtime, background mode, stored or
previous responses, prompt references/caching, built-in tools, MCP tools,
remote connectors, and unknown fields are rejected. `store` is fixed to
`false`. The upstream Responses API supports a broader multimodal, stateful,
tool, and streaming surface; Phase 8 intentionally narrows it so inspection is
complete before release. See the current official
[Responses API reference](https://developers.openai.com/api/reference/resources/responses/methods/create)
and [OpenAI API quickstart](https://developers.openai.com/api/docs/quickstart).

## Security flow

1. Enforce loopback configuration, body limit, local authentication, exact
   model allowlist, strict schema, and unsupported-feature rejection.
2. Recheck the configured attestation.
3. Map all outbound text to structured CodeShield segments.
4. Run the fixed core detector profile (including fragments), built-in policy,
   provider evidence, attestation, and protection logic. Repository files
   cannot replace this proxy boundary configuration.
5. Forward only `ALLOW`, `WARN`, or fully pseudonymized content.
6. Resolve the upstream immediately before use and reject loopback, private,
   link-local, multicast, reserved, or otherwise non-global addresses.
7. Send with TLS verification, `trust_env=false`, no redirects, and a fixed
   minimal header set.
8. Fully buffer the response under its byte limit, require UTF-8 JSON and the
   supported response shape, and inspect all assistant text, refusals, and
   function-call arguments as untrusted.
9. If any item blocks or is malformed, discard the complete response.
10. Restore only pseudonyms created in the request-scoped in-memory vault and
    return the complete validated response.

Hop-by-hop, client authorization, forwarding, cookie, and unapproved provider
headers are never forwarded. Upstream error bodies are never returned.
Redirects are rejected. Metadata-only HMAC audit rows contain a correlation
HMAC, endpoint class, provider profile/version, outbound/inbound actions,
category counts, upstream status class, and latency. They contain no content,
paths, headers, URLs, credentials, model output, or pseudonym mappings.

## Evaluation and measured performance

The versioned `phase8` suite retains all Phase 6 datasets and adds eleven
deterministic proxy cases. Gates require exact leak recall `1.0`, block recall
`1.0`, negative-case false-positive rate at most `0.02`, no overall exact-F2
regression greater than `0.02`, and the existing core/fragment/security gates.

The initial Windows Python 3.12 measurements on 2026-07-29 were:

- Phase 8 proxy exact leak recall: `1.0`
- Phase 8 proxy block recall: `1.0`
- Phase 8 proxy negative-case false-positive rate: `0.0`
- Core 100 KB warm p95: `150.79 ms` in the committed baseline and
  `153.39 ms` in the final repeat (`250 ms` budget)
- Enhanced 100 KB warm p95: `1074.91 ms` in the committed baseline and
  `1014.82 ms` in the final repeat (`3000 ms` budget)
- Phase 7 editor 100 KB warm p95: `147.47 ms` (`750 ms` budget)
- Fully inspected 100 KB local mock-proxy p95: `222.55 ms`
  (`750 ms` budget)

All measurements are synthetic local engineering results, not production
provider latency or real-world accuracy claims. No test contacts a real LLM
provider.

## Tests and limitations

Proxy tests cover authentication, configuration/link rules, exact allowlists,
headers, redirects, byte limits, malformed input and responses, unsupported
features, both endpoints, roles, text parts, tools, function outputs,
pseudonymization/restoration, outbound zero-send blocking, inbound
all-or-nothing blocking, credential echoes, timeouts, sanitized errors, and
metadata-only audits. CI runs the mock-upstream integration suite on Ubuntu and
Windows with Python 3.12.

Limitations:

- no streaming or chunk release;
- function tools only;
- no public binding or multi-upstream routing;
- no hosted management, telemetry, automatic downloads, or real-provider CI;
- no releases, deployments, package publication, Marketplace publication,
  SARIF upload, or credential storage.

## Changed implementation areas

- `engine/codeshield/proxy/` — config, protocol models, mapping, network
  boundary, forwarding, error envelopes, audit, and FastAPI factory
- `engine/codeshield/cli.py` — `proxy validate-config` and `proxy serve`
- `engine/codeshield/llm/service.py` — request-scoped caller-owned vault support
- `engine/codeshield/evaluation/` and `reports/phase8/` — versioned proxy gates
- `engine/tests/test_proxy.py` — mock-upstream security and interoperability
- `.github/workflows/ci.yml` — Python 3.12 Ubuntu/Windows proxy jobs
