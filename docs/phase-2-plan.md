# Phase 2 Plan: Context, Policies, and Protection

Status: complete; 37 tests verified in Python 3.12 Docker  
Prerequisite: Phase 1 tests pass  
Target release: engine `0.2.0`

## Objective

Phase 2 will turn the Phase 1 detector into a context-aware protection engine.
For each finding, the engine will estimate what the value represents, apply a
destination-specific YAML policy, calculate an explainable risk decision, and
produce safely masked or consistently pseudonymized content when required.

The engine must remain local-first. Raw values may exist transiently in process
memory while a scan or protection operation is running, but they must never be
added to public Pydantic models, logs, CLI JSON, API responses, or remote
services.

## Committed Scope

1. Context labels and deterministic feature extraction.
2. A small synthetic dataset generator and scikit-learn baseline classifier.
3. Pydantic-validated destination policies loaded from YAML.
4. Configurable, explainable risk scoring that incorporates context and policy.
5. Full redaction, partial masking, type placeholders, and consistent
   pseudonyms.
6. An encrypted local pseudonym vault with authorized local restoration.
7. CLI/API integration and focused unit, integration, security, and evaluation
   tests.
8. Documentation for policies, privacy behavior, and Phase 2 operation.

Presidio, spaCy, and a Gitleaks/detect-secrets adapter are a final optional
milestone. They will be included only after the committed pipeline is stable and
their runtime/model dependencies do not compromise the local quick start.

## Non-Goals

- Git staged-diff scanning or hook installation.
- npm, TypeScript SDK, or VS Code extension work.
- Hosted management API, Supabase, or dashboard work.
- External or paid LLM calls.
- Cloud synchronization of raw content or pseudonym mappings.
- A deep-learning classifier or production-scale training dataset.

## Architecture

```text
untrusted local text + file context
              |
              v
regex/entropy detectors -> safe findings with source spans
              |
              v
transient feature extraction from text[span]
              |
              v
context rules + scikit-learn classifier
              |
              v
YAML destination policy -> explainable risk decision
              |
              +---- allow / warn / block
              |
              v
redact / mask / placeholder / pseudonymize
              |
              v
protected text + safe findings only

pseudonym <-> original mapping
              |
              v
encrypted local SQLite vault (never synchronized)
```

The existing `Finding` model will remain raw-value-free. The classifier and
protector will use the original input text and a finding's start/end positions
only during the active operation. This avoids introducing a serializable model
that can accidentally leak a secret.

## Proposed Models and Interfaces

### Context models

- `ContextLabel`: `probable_real_secret`, `placeholder`, `test_data`,
  `public_information`, `personal_data`, `confidential_business_data`, and
  `uncertain`.
- `FileContext`: path, suffix, whether the path is under tests/fixtures, and
  optional repository visibility.
- `ContextAssessment`: label, confidence, rule signals, model signals, and a
  short safe explanation.
- Add an optional `context` field to `Finding`; it must contain metadata only.

### Policy models

- `PolicyDocument`: schema version, policy name, defaults, scoring weights, and
  destination rule sets.
- `PolicyRule`: destinations, data categories, optional context labels,
  minimum confidence, action, priority, and safe rationale.
- `PolicyDecision`: matched rule ID, action, rationale, and whether the rule is
  mandatory.
- Add `PSEUDONYMIZE` to `RecommendedAction`.

Ambiguous rules with the same priority and specificity but conflicting actions
will fail validation. Policy loading must fail closed for malformed files.

### Protection models

- `ProtectionMode`: `redact`, `partial_mask`, `type_placeholder`, and
  `pseudonymize`.
- `ProtectionResult`: protected text, safe findings, replacements applied, and
  blocked status. It must not contain original values.
- `TextProtector`: applies replacements from the end of the text toward the
  beginning so source spans remain stable.
- `PseudonymVault`: stores, resolves, and removes encrypted mappings.
- `KeyProvider`: supplies encryption keys without embedding them in source or
  configuration files.

## Context Classifier Design

### Deterministic features

- Data category and detector source.
- Detection confidence and entropy bucket.
- Value length and character-class composition.
- Known credential prefixes.
- Variable/assignment name near the finding.
- Nearby words such as `example`, `dummy`, `sample`, `fixture`, `test`,
  `production`, `live`, `secret`, and `token`.
- File suffix and whether the path is under `tests`, `fixtures`, `examples`, or
  generated output.
- Comment-like versus assignment-like surrounding text using conservative
  language-independent heuristics.

Features must not include raw values, reversible hashes, or complete surrounding
source text in telemetry or explanations.

### Model

- Use a deterministic scikit-learn pipeline with `DictVectorizer` and logistic
  regression.
- Generate only synthetic labelled records with a fixed random seed.
- Keep the dataset generator and evaluation split reproducible.
- Do not commit real secrets, real personal data, or opaque generated binaries.
- Use rule overrides for strong placeholder/test indicators and critical known
  credential formats; use the model for ambiguous cases.
- Return `uncertain` below a configurable confidence threshold.

## Policy Resolution

Policy evaluation order will be deterministic:

1. Validate the complete YAML document before use.
2. Filter rules by destination, category, context, and confidence.
3. Select the highest explicit priority.
4. Prefer the most specific rule within that priority.
5. Reject conflicting ties rather than relying on YAML order.
6. Apply mandatory policy actions as a minimum action severity; a risk result
   may make the action stricter but cannot weaken a mandatory rule.

The repository will include a documented `policies/default.yaml` containing
conservative local, Git, logging, API, cloud, and LLM defaults. Every weight will
have a rationale in the policy-writing guide.

## Risk Scoring Changes

Refactor the Phase 1 constants into a validated configuration with contributions
for:

- Data sensitivity.
- Detection confidence.
- Context classification.
- Destination exposure.
- Repository visibility when known.
- Policy importance.

The score remains bounded from 0 to 100 and keeps the Phase 1 thresholds. The
returned `RiskScore.factors` will show each value, maximum weight, contribution,
and safe explanation. Regression tests will preserve important Phase 1 behavior,
including blocking high-confidence credentials sent to public Git.

## Pseudonymization and Vault Security

- Pseudonyms are type-based counters such as `<EMAIL_1>` and `<API_KEY_1>`.
- The same value receives the same pseudonym within a session.
- Replacement order is deterministic and overlap-safe.
- Mapping rows are encrypted independently with AES-GCM from `cryptography`,
  using a unique random nonce and authenticated metadata.
- SQLite stores ciphertext, nonce, type, timestamps, and a keyed lookup token;
  it never stores plaintext mappings.
- A `KeyProvider` interface separates vault encryption from key storage. Tests
  use an in-memory provider. Local operation should use an OS credential store
  or an explicitly supplied key and fail closed when no secure key is available.
- Restoration is local-only, explicit, and restricted to known pseudonyms.
- No vault content is included in audit metadata, CLI JSON, or API responses.

## Milestones

### M1: Context contracts and feature extraction

- Add context enums/models and `FileContext`.
- Implement transient feature extraction from source spans.
- Add placeholder/test-data rule signals.
- Preserve all Phase 1 tests.

Acceptance:

- No raw value appears in context models or explanations.
- Feature tests cover assignments, comments, test paths, placeholders, Unicode,
  malformed text, and unknown file types.

### M2: Synthetic data and baseline classifier

- Add deterministic synthetic dataset generation.
- Build the scikit-learn pipeline and hybrid rule/model classifier.
- Add an evaluation command or script.
- Report accuracy, precision, recall, F1, and confusion matrix by label.

Acceptance:

- Repeated runs with the same seed produce the same dataset and metrics.
- Placeholder versus probable-real-secret evaluation meets a documented
  baseline target without using real data.

### M3: YAML policy engine

- Add YAML/Pydantic policy models and loader.
- Add conflict detection and deterministic rule matching.
- Add `codeshield policy validate POLICY_FILE`.
- Add conservative default policies and examples.

Acceptance:

- Invalid enums, weights, duplicates, conflicting ties, and malformed YAML
  produce clear errors and CLI exit code `3`.
- Public Git credentials cannot be downgraded by a weaker non-mandatory rule.

### M4: Explainable risk integration

- Move weights from Python constants into validated configuration.
- Include context, repository visibility, and policy importance.
- Attach the matched policy decision and complete safe factor breakdown.

Acceptance:

- Scores are deterministic and bounded.
- Every non-zero contribution has a safe explanation.
- Destination and context changes have focused regression tests.

### M5: Protection operations

- Implement redaction, partial masking, type placeholders, and span-safe text
  replacement.
- Add `codeshield protect FILE --destination ...` with human/JSON metadata and
  protected output written only to an explicit output path or standard output.
- Block before writing output when a mandatory block rule matches.

Acceptance:

- Adjacent and overlapping findings are replaced correctly.
- Protected output contains no original detected value.
- Input files are never modified unless an explicit in-place mode is designed
  and separately approved.

### M6: Encrypted pseudonym vault and restore

- Add SQLite storage, AES-GCM encryption, and key-provider abstraction.
- Add session consistency and authorized local restoration.
- Add lifecycle operations and safe error handling for wrong/tampered keys.

Acceptance:

- Database inspection reveals no plaintext original values.
- Tampered ciphertext fails authentication.
- Repeated values map consistently; different values do not collide.
- Restoration works only with the local vault and correct key.

### M7: API, CLI, and documentation

- Add local-only scanning/protection endpoints with request-size limits.
- Expand CLI output with safe context, policy, and risk explanations.
- Add policy, classifier, protection, privacy, and vault documentation.
- Update Docker and dependency extras.

Acceptance:

- API paths cannot access arbitrary files.
- CORS remains restrictive and the default host remains `127.0.0.1`.
- Structured logs and error responses contain no supplied secret values.

### M8: Optional detector adapters

- Add Presidio PII and spaCy NER adapters behind an optional dependency group.
- Evaluate Gitleaks versus detect-secrets and implement one adapter using safe
  subprocess argument arrays or a library API.
- Keep startup functional when optional models/tools are absent.

This milestone may move to a later phase if model downloads or platform-specific
scanner installation would make Phase 2 unreliable.

## Test Plan

### Context classification

- Probable real credential versus placeholder.
- Test fixture versus production-like assignment.
- Personal data and public-information examples.
- Unknown/low-confidence fallback.
- Unicode variable names and surrounding text.
- Prompt-injection text treated only as data.

### Policy engine

- Valid policy parsing and version checks.
- Unknown destination/category/action rejection.
- Rule priority and specificity.
- Conflicting tie rejection.
- Mandatory action cannot be weakened.
- Missing, unreadable, and malformed policy files.

### Risk scoring

- Context changes risk in the expected direction.
- Public destinations score above local destinations.
- Repository visibility affects Git decisions.
- Threshold boundaries: 29/30, 59/60, and 79/80.
- Factor contributions sum to the final bounded score.

### Protection and vault

- Redaction, partial masking, placeholders, and pseudonyms.
- Repeated-value consistency and different-value separation.
- Adjacent, nested, and overlapping spans.
- Encrypted-at-rest inspection.
- Wrong key, modified nonce, and modified ciphertext failures.
- Authorized restoration and unknown pseudonym behavior.
- No raw values in repr, exceptions, logs, JSON, or API responses.

### Integration and adversarial coverage

- CLI exit codes and policy validation.
- JSON, source code, configuration files, and mixed PII/credentials.
- Base64-looking benign values and fake secrets.
- Very long input, malformed UTF-8, and scan timeout.
- API request limits, path traversal, malicious filenames, and CORS.
- Docker tests on Python 3.12.

## Evaluation Outputs

The Phase 2 evaluation script will report:

- Precision, recall, F1, false-positive rate, and false-negative rate.
- Placeholder versus probable-real-secret accuracy.
- Results by context label, destination, and data category.
- Leakage-prevention rate after protection.
- Average and percentile scan latency.
- Pseudonym consistency.

Metrics must be calculated from synthetic or properly licensed data only.

## Dependencies Under Consideration

- `PyYAML` for policy files.
- `scikit-learn` for the baseline classifier.
- `cryptography` for AES-GCM vault encryption.
- `keyring` or an equivalent OS credential-store adapter for local key storage.
- Optional extras for Presidio, spaCy, and the selected secret scanner.

Exact versions will be pinned within compatibility ranges after validating
Python 3.12 wheels and Docker builds.

## Delivery Checklist

- [ ] All Phase 1 tests remain passing.
- [ ] New Phase 2 tests pass locally and in Docker on Python 3.12.
- [ ] No real secrets or personal data exist in fixtures or documentation.
- [ ] No public model, output, log, or exception contains a raw detected value.
- [ ] Default policies are documented and deterministic.
- [ ] Classifier metrics and known limitations are recorded.
- [ ] Vault ciphertext and tamper tests pass.
- [ ] CLI/API recovery instructions are documented.
- [ ] Engine version is updated to `0.2.0` only when acceptance criteria pass.

## Recommended Implementation Order

Implement M1 through M4 first and keep scanning behavior stable. Then implement
protection and the vault in M5 and M6. Finish with API/CLI hardening and docs in
M7. Evaluate optional detector adapters only after the committed Phase 2 suite
passes.
