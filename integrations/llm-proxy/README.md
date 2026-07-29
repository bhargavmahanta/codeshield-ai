# Local LLM Proxy

CodeShield 0.8.0 includes an authenticated OpenAI-compatible proxy that binds
only to `127.0.0.1` or `::1`. It inspects the complete outbound request before
opening the upstream connection and buffers, validates, and inspects the
complete response before returning any content.

Copy `example.config.yaml` to a machine-local absolute path outside a
repository, replace the profile, attestation, upstream, credential variable,
and exact model allowlist, then restrict it to the current user. The file must
be regular and cannot be a symlink or junction.

```powershell
codeshield proxy validate-config C:\secure\codeshield-proxy.yaml
$env:CODESHIELD_PROXY_TOKEN = "<generate-at-least-32-random-characters>"
$env:OPENAI_API_KEY = "<upstream-credential>"
codeshield proxy serve C:\secure\codeshield-proxy.yaml
```

Point a compatible local client at `http://127.0.0.1:8770/v1` and authenticate
with `CODESHIELD_PROXY_TOKEN`, not the upstream credential. See
[`docs/phase-8-local-llm-proxy.md`](../../docs/phase-8-local-llm-proxy.md) for
the supported protocol subset, security model, tests, and limitations.
