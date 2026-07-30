# CodeShield AI

CodeShield AI is a local-first sensitive-data protection framework for developer workflows. Version 0.8.0 adds an authenticated loopback-only OpenAI-compatible proxy with complete outbound and inbound inspection while preserving all Phase 7 editor, CLI, API, SDK, policy, and security behavior.

The scanner is intentionally local. It never returns complete raw secrets in CLI output or API responses; findings include masked previews only.

## Phase 1 Features

- Monorepo scaffold for the planned engine, packages, extension, dashboard, integrations, docs, and policies.
- Typed Pydantic models for findings, destinations, severities, scan results, and risk scores.
- Regex detector for common sensitive values including emails, IP addresses, passwords, API keys, JWTs, private keys, database URLs, cloud credentials, session IDs, phone numbers, and financial identifiers.
- Entropy detector for unknown high-entropy tokens.
- Finding deduplication and overlap resolution.
- Explainable 0-100 risk scoring.
- Typer CLI with human and JSON output.
- Minimal FastAPI service with `/health` and `/version`.
- Docker-ready Python 3.12 runtime.

## Phase 2 Features

- Hybrid deterministic/scikit-learn context classification using synthetic data.
- Validated YAML policies with deterministic conflict handling.
- Configurable risk factors for context, destination, policy, and visibility.
- Redaction, partial masking, type placeholders, and consistent pseudonyms.
- AES-GCM encrypted local SQLite pseudonym vault and explicit restoration.
- Local `/scan/text`, `/protect`, and `/restore` API endpoints.
- Synthetic classifier evaluation command and expanded security tests.

## Phase 3 Features

- Zero-context staged Git scanning that considers only added lines.
- Repository-relative finding locations, multiline grouping, exclusions, and binary skips.
- Managed native pre-commit hook plus pre-commit framework metadata.
- Expiring, path-scoped test-data exceptions with visible IDs and preserved risk.
- Private npm workspaces for the Python CLI wrapper, generated API types, and SDK.
- Python 3.12 and Node 22 CI with contract drift and changed-addition enforcement.

## Phase 4 Features

- Independent semantic categories and Public/Internal/Confidential/Restricted sensitivity.
- Reviewed, expiring provider profiles for major enterprise APIs and coding assistants.
- Local account attestations and fail-closed external LLM transfer policy.
- Structured outbound and inbound prompt assessment with injection/tool safeguards.
- Local personal-data pseudonymization and mandatory Restricted-content blocking.
- Metadata-only HMAC audit records with no prompt, source, preview, or raw path columns.

## Phase 5 Features

- Dependency-light `core` and explicitly enabled `enhanced` detector profiles.
- Lazy, offline Presidio `2.2.363` analysis with the pinned spaCy English model.
- Gitleaks `8.30.1` stdin scanning with argument arrays, timeouts, private reports, and safe cleanup.
- Deterministic synthetic, PII-template, adversarial, and workflow evaluation suites.
- Exact-span, overlap, category, source, policy, transformation, and latency metrics.
- Metadata-only JSON/Markdown baselines and CI regression gates.

## Phase 6 Features

- Safe repeatable TypeScript builds and temporary contract generation on Windows and Linux.
- Deterministic SARIF 2.1.0 for path and staged scans with repository-relative locations.
- Conservative static reconstruction for Python, JavaScript, TypeScript, and explicit JSON part arrays.
- Read-only detector, provider, verification, and attestation-status API/SDK interfaces.
- Versioned Phase 6 fragment evaluation with false-positive and latency gates.

## Phase 7 Features

- Local-only VS Code diagnostics for files, selections, workspaces, and staged changes.
- One owned, shell-free engine subprocess per workspace with bounded stdio messages.
- Manual scanning by default with opt-in scan-on-save and no scan-on-type behavior.
- Confirmed, stale-span-safe protection edits with normal VS Code undo support.
- Workspace Trust enforcement, machine-scoped engine/vault settings, and local policies.
- Strict runtime result validation and extension-owned messages that exclude previews and raw values.
- Local allowlisted VSIX packaging with no publishing or Marketplace credentials.

## Phase 8 Features

- Authenticated `127.0.0.1`/`::1` proxy with separate local and upstream credentials.
- Strict text-only Chat Completions and Responses subsets with function tools.
- Provider/attestation/policy inspection before opening the upstream connection.
- Request-scoped in-memory pseudonymization and local restoration after inbound inspection.
- Full response buffering with all-or-nothing release and fixed sanitized errors.
- TLS verification, public-address enforcement, redirect rejection, minimal headers, and metadata-only audit.
- Versioned proxy evaluation and local mock-upstream tests with no real-provider calls.

## Quick Start

Install and test locally from the engine package:

```powershell
cd engine
python -m pip install -e ".[dev]"
python -m pytest tests
codeshield scan ../README.md
codeshield scan --staged
codeshield install-hook
codeshield provider verify
codeshield server
```

The current workspace default Python may be newer than the target runtime. Docker pins Python 3.12:

```powershell
docker compose build engine
docker compose run --rm engine pytest
docker compose up engine
```

The Docker service publishes the engine on host loopback only:

```text
http://127.0.0.1:8765/health
```

## CLI Examples

```powershell
codeshield scan .
codeshield scan . --destination public_git
codeshield scan path/to/file.txt --format json
codeshield scan . --format sarif --output codeshield.sarif
codeshield check-staged
codeshield hook-status
codeshield policy validate policies/default.yaml
codeshield protect input.txt --mode type_placeholder --output protected.txt
codeshield evaluate-context
codeshield prompt assess --provider openai-api-zdr --file prompt.txt
codeshield detector status
Get-Content .\input.py | codeshield scan-text --stdin --source-path input.py --format json
Get-Content .\input.py | codeshield protect-text --stdin --source-path input.py --format json
codeshield evaluate prepare --suite phase5
codeshield evaluate run --profile core --output ../reports/local-core.json
codeshield evaluate run --suite phase6 --profile core --output ../reports/local-phase6.json
codeshield evaluate run --suite phase8 --profile core --output ../reports/local-phase8.json
codeshield proxy validate-config C:\secure\codeshield-proxy.yaml
codeshield proxy serve C:\secure\codeshield-proxy.yaml
codeshield version
```

Exit codes:

- `0`: no blocking findings
- `1`: findings require warning or masking
- `2`: blocked by policy/risk threshold
- `3`: configuration or execution error

## Architecture

```text
developer files/prompts
        |
        v
CodeShield detectors -> dedupe -> context -> policy -> risk -> protection
        |
        v
masked findings only
```

## Current Limitations

- The enhanced profile is optional, larger, and slower than the default core profile.
- npm packages and the VS Code extension remain local/private; Supabase, dashboard, hosted management, and streaming proxy work remain later phases.
- Current accuracy results use deterministic synthetic and MIT-methodology-derived data; they do not establish real-world performance.
- Detection relies on regex and entropy heuristics, so false positives and false negatives are expected.

Detailed documentation:

- [Phase 1 implementation and testing guide](docs/phase-1-testing.md)
- [Phase 2 implementation plan](docs/phase-2-plan.md)
- [Phase 2 usage and security guide](docs/phase-2-guide.md)
- [Phase 3 review and five-minute demo](docs/phase-3-review.md)
- [Phase 4 prompt and source-code safety](docs/phase-4-prompt-safety.md)
- [LLM provider data-handling matrix](docs/provider-data-handling.md)
- [Phase 5 evaluation and detector hardening](docs/phase-5-evaluation.md)
- [Phase 6 cross-platform hardening and interoperability](docs/phase-6-hardening.md)
- [Phase 7 local VS Code extension](docs/phase-7-vscode-extension.md)
- [Phase 8 authenticated local LLM proxy](docs/phase-8-local-llm-proxy.md)

## Roadmap

1. Completed: context classification, YAML policies, explainable destination-aware controls, masking, and encrypted pseudonymization.
2. Completed: Git staged-diff scanning, hooks, controlled exceptions, npm CLI, and TypeScript SDK.
3. Completed: provider-aware prompt/source-code classification and preflight.
4. Completed: optional Presidio/spaCy and Gitleaks adapters with reproducible evaluation gates.
5. Completed: cross-platform builds, SARIF, fragment-aware detection, and interoperability APIs.
6. Completed: local VS Code scanning, diagnostics, protection, and VSIX packaging.
7. Completed: authenticated loopback LLM proxy with fail-closed outbound and inbound inspection.
8. Later: hosted management, Supabase, dashboard, and explicitly approved streaming work.

## License Recommendation

For a student project, MIT is a simple starting point. Revisit licensing before using third-party datasets or bundling external scanner binaries.
