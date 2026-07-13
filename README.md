# CodeShield AI

CodeShield AI is a local-first sensitive-data protection framework for developer workflows. Engine 0.3.0 adds staged Git protection, controlled policy exceptions, a local npm CLI, and a typed loopback SDK to the Phase 2 security engine.

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

## Quick Start

Install and test locally from the engine package:

```powershell
cd engine
python -m pip install -e ".[dev]"
python -m pytest tests
codeshield scan ../README.md
codeshield scan --staged
codeshield install-hook
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
codeshield scan path/to/file.txt --output json
codeshield check-staged
codeshield hook-status
codeshield policy validate policies/default.yaml
codeshield protect input.txt --mode type_placeholder --output protected.txt
codeshield evaluate-context
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

- Presidio, spaCy, and Gitleaks/detect-secrets adapters are not yet integrated.
- npm packages are local/private; VS Code, Supabase, dashboard, and LLM proxy work remain later phases.
- The context model uses a small synthetic baseline dataset and requires broader evaluation before production use.
- Detection relies on regex and entropy heuristics, so false positives and false negatives are expected.

Detailed documentation:

- [Phase 1 implementation and testing guide](docs/phase-1-testing.md)
- [Phase 2 implementation plan](docs/phase-2-plan.md)
- [Phase 2 usage and security guide](docs/phase-2-guide.md)
- [Phase 3 review and five-minute demo](docs/phase-3-review.md)

## Roadmap

1. Completed: context classification, YAML policies, explainable destination-aware controls, masking, and encrypted pseudonymization.
2. Completed: Git staged-diff scanning, hooks, controlled exceptions, npm CLI, and TypeScript SDK.
3. Add the VS Code extension.
4. Add hosted management API, Supabase schema, and dashboard.
5. Add the mock LLM proxy, logging sanitizer, CI/CD, deployment docs, and full evaluation pipeline.

## License Recommendation

For a student project, MIT is a simple starting point. Revisit licensing before using third-party datasets or bundling external scanner binaries.
