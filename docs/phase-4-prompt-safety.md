# Phase 4: Safe Prompts and Source Code

CodeShield 0.4.0 adds a local preflight trust boundary. It classifies structured prompt segments, applies reviewed provider controls, protects eligible personal data, blocks restricted data, and writes metadata-only decisions before any caller sends content to an LLM.

## Data Classification

Sensitivity and semantic category are independent:

- `PUBLIC`: explicitly configured public source paths.
- `INTERNAL`: ordinary prompts, system instructions, and operational information.
- `CONFIDENTIAL`: private source code, customer/financial records, architecture, legal material, and personal data.
- `RESTRICTED`: credentials, cryptographic material, government/biometric identifiers, PHI, payment authentication data, active vulnerability details, and export-controlled content.

Private source code defaults to Confidential. Only repository/path configuration can establish public code. Inline `codeshield:sensitivity=...` annotations can raise sensitivity but cannot lower it.

## Transfer Rules

- Unknown or unattested providers receive only Public content.
- Internal and Confidential content require a current exact-profile attestation, no training use, retention no longer than 30 days, and no incompatible feature.
- Restricted content never crosses an external LLM boundary and cannot be excepted.
- Personal data is pseudonymized locally. Credentials and unsafe source spans are blocked rather than rewritten.
- Stateful storage, files, grounding, extended caches, connectors, code execution, and workspace indexing must be declared. Missing feature information is treated conservatively.
- Inbound model responses are scanned before display, storage, or execution.

## Prompt Injection And Tool Safety

System prompts are not secrets or authorization mechanisms. Credentials, roles, permissions, database details, and enforcement logic stay outside model instructions. Retrieved content and tool output are untrusted. Injection indicators warn by default; untrusted injected content combined with privileged tools blocks for human approval.

These controls follow [OWASP prompt-injection guidance](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and [OWASP system-prompt leakage guidance](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/): input/output filtering, least privilege, content segregation, output validation, and human approval are enforced in code rather than entrusted to prompt wording.

## API And SDK

```text
POST /llm/assess
POST /llm/protect
```

Requests contain typed segments (`system`, `developer`, `user`, `retrieved`, `tool_output`, or `source_code`), provenance, provider profile, attestation reference, direction, purpose, and enabled feature flags. Assessment responses contain masked findings and metadata only. Protection responses contain transformed content only when the decision is not blocked.

The TypeScript SDK exposes `assessForLlm` and `protectForLlm`. Neither endpoint contacts a provider.

## CLI

```powershell
codeshield provider list
codeshield provider show openai-api-zdr
codeshield provider verify

codeshield prompt assess --provider openai-api-zdr --attestation approved-api --file prompt.json
Get-Content prompt.txt | codeshield prompt protect --provider openai-api-zdr --attestation approved-api --stdin
```

Prompt text is never accepted as a command-line argument. Structured manifests contain a `segments` array. Exit codes remain `0` allow, `1` warning/transformation, `2` block, and `3` configuration/execution error.

## Metadata-Only Audit

The local SQLite audit retains 30 days of keyed payload/path HMACs, profile and evidence versions, sensitivity, categories, action, feature flags, counts, and timestamps. Its schema has no prompt, output, source, preview, raw path, evidence document, account identifier, or reversible-value column.

## Governance Mapping

CodeShield uses [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework), [NIST SSDF](https://csrc.nist.gov/projects/ssdf), and OWASP as engineering baselines. Its classifications can inform reviews under [India's DPDP Rules](https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa), GDPR, [HIPAA de-identification guidance](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html), and [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/), but do not establish legal compliance.

## Generated Code

Provider approval does not make generated code trustworthy. Generated changes still require human review, tests, SAST, software-composition analysis, dependency and provenance checks, license review, and normal branch protection. CodeShield does not automatically execute generated code.
