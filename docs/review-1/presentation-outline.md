# CodeShield AI Review 1 Presentation

Target duration: **10 minutes presentation + 2 minutes questions**

## Slide 1 — CodeShield AI (0:45)

**Subtitle:** A Context-Aware and Destination-Sensitive Framework for Preventing Sensitive Data Leakage in Developer and LLM Workflows

- Bhargav Mahanta | [REGISTRATION NUMBER]
- [DEPARTMENT] | [INSTITUTION]
- Guide: [GUIDE NAME]
- Review 1 | August 5, 2026

**Speaker cue:** Developers now move the same sensitive artifact through source code, Git, APIs, and LLM prompts. CodeShield adds one local decision boundary before that artifact leaves its intended trust zone.

## Slide 2 — Problem And Motivation (1:00)

- Credentials, PII, private code, architecture, and vulnerabilities can leak through Git and LLM prompts.
- Pattern-only scanners can be noisy and do not explain whether the destination changes the risk.
- Sending content to a remote classifier creates the very exposure the control should prevent.
- Leakage must be stopped before commit or provider transfer.

**Evidence callout:** Meli et al. found secret leakage across more than 100,000 public repositories [1].

## Slide 3 — Objectives And Boundaries (0:55)

- Detect and classify locally.
- Combine context, destination, sensitivity, provider evidence, and requested features.
- Explain allow, warn, mask, pseudonymize, or block decisions.
- Protect staged Git additions and structured LLM traffic.
- Store no raw prompt/source content in audit records.

**Boundary:** No provider calls, legal-compliance claim, transparent proxy, hosted dashboard, or production benchmark claim in Review 1.

## Slide 4 — Literature Review (1:05)

| Work | Main contribution | Remaining gap |
| --- | --- | --- |
| Meli et al. [1] | Scale of Git secret leakage | No contextual transfer policy |
| Saha et al. [2] | ML reduction of false positives | Secret/not-secret focus |
| SecretBench [3] | Diverse evaluation dataset | Benchmark, not prevention workflow |
| CodexLeaks/HCR [5], [6] | Leakage from code models | Not an outbound local gate |
| Casper [7] | Local prompt sanitization | Web/PII focus; no Git/provider policy |
| BIPIA [9] | Indirect injection benchmark | Prompt defenses are not authorization |

**Speaker cue:** Each line solves an important slice. The integration gap is the research opportunity.

## Slide 5 — Research Gap And Contribution (0:55)

**Gap:** Existing work separately addresses repository secrets, contextual DLP, prompt privacy, model leakage, or prompt injection.

**CodeShield contribution:** One local framework combining:

- context classification and destination-sensitive policy;
- Git and structured LLM preflight;
- provider profiles and expiring attestations;
- reversible local pseudonymization;
- inbound assessment and metadata-only auditing.

## Slide 6 — Level 1: Context And Trust Boundaries (1:05)

Use `architecture/system-context.svg` full width.

**Speaker cue:** Solid components are implemented. Dashed components are roadmap. CodeShield itself never contacts a provider in Phase 4; the application may transmit only after a local decision.

## Slide 7 — Level 2: Processing Architecture (1:15)

Use `architecture/processing-pipeline.svg` full width.

**Speaker cue:** The Git path and LLM path share policy and protection concepts. Restricted data is blocked; personal data can be transformed only when exact local spans are available.

## Slide 8 — Implemented Prototype (0:55)

- Python 3.12 engine, Typer CLI, loopback FastAPI
- Regex + entropy detection, context classifier, YAML policy, risk score
- Managed Git hook and CI changed-additions scan
- AES-GCM local pseudonym vault and metadata-only SQLite audit
- npm wrapper, generated OpenAPI types, TypeScript SDK
- 20 reviewed provider-surface profiles

**Status:** `0.4.0`, commit `cf48c5b`; Phase 4 implemented on draft PR #2 with green checks.

## Slide 9 — Evidence And Limitations (1:05)

**Evidence**

- 84 Python tests + 9 TypeScript tests
- CLI, API, SDK, Git-hook, contract-drift, provider-freshness, and live loopback checks
- Masked outputs and synthetic fixtures only

**Limitations**

- No benchmark precision/recall/F1 claim yet
- Regex/entropy and synthetic classifier baseline can miss or over-report
- Presidio, spaCy, and external secret-scanner adapters remain future work
- Native `--no-verify` requires CI enforcement

## Slide 10 — Roadmap And Conclusion (0:55)

1. Licensed/synthetic evaluation pipeline and detector adapters
2. Debounced VS Code extension
3. Mock-upstream LLM proxy and logging sanitizer
4. Metadata-only management API, Supabase, and dashboard

**Conclusion:** CodeShield demonstrates that sensitive-data controls can remain local while making transfer decisions sensitive to context, destination, provider handling, and requested capabilities.

**Closing line:** Review 1 establishes feasibility; the next milestone is reproducible accuracy, leakage-prevention, and latency evaluation.
