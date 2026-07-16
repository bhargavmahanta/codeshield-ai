# Review 1 Reviewer Q&A

## What is novel about CodeShield?

The contribution is not a new regex. It is the integration of context,
destination, sensitivity, provider evidence, Git enforcement, structured LLM
preflight, local reversible protection, and metadata-only auditing in one local
decision path. The report positions this as an engineering framework
contribution, not as proof that every individual detector is novel.

## How is CodeShield different from Gitleaks or GitHub secret scanning?

Those tools are important credential detectors. CodeShield additionally models
whether a value appears real, where it is going, repository visibility, broader
personal/confidential categories, provider handling, and whether local masking
or pseudonymization is permissible. External secret-scanner adapters are future
detector inputs rather than competitors to replace.

## Why use a context classifier if regex already finds secrets?

Regex and entropy generate candidates quickly but can match examples,
placeholders, documentation, and benign high-entropy text. Context provides
evidence such as variable name, path, test-fixture location, and surrounding
words. Mandatory policy still blocks prohibited categories even if context is
uncertain.

## Does CodeShield prove that an LLM provider is safe?

No. Provider profiles summarise reviewed first-party evidence, and local
attestations record an administrative review of account controls. Unknown,
stale, mismatched, or unattested profiles fail closed for non-public content.
Contracts and legal compliance remain organisational responsibilities.

## Why is Restricted content always blocked?

Credentials, private keys, production data, payment authentication material,
health data, active vulnerability details, and similar categories have a high
impact if detection or transformation is wrong. Phase 4 chooses a conservative
boundary: these categories do not cross an external LLM boundary and cannot be
excepted.

## Can prompt injection be solved by filtering phrases?

No. Deterministic signals identify obvious cases, but prompt wording is not an
authorization boundary. CodeShield labels retrieved/tool content as untrusted
and blocks untrusted injection indicators when privileged tools are requested.
Least privilege, output validation, and human approval remain necessary.

## Where are precision, recall, and F1 results?

They are not claimed in Review 1. The current 84 Python and 9 TypeScript tests
validate implementation behavior, not population-level detector accuracy. A
licensed or carefully synthetic evaluation corpus and per-category metrics are
the next research milestone.

## What happens if a developer uses `git commit --no-verify`?

Native Git permits that bypass. CodeShield documents it instead of claiming it
can be prevented. Pull-request CI reconstructs changed additions in an isolated
index and reruns equivalent scanning as the enforcement backstop.

## Why keep processing local?

Remote classification would disclose raw content before deciding whether it is
safe to disclose. Local processing keeps the sensitive path under the
developer's control and allows only protected content or masked metadata to
cross a trust boundary.

## What is implemented versus future work?

Implemented: engine, CLI, loopback API, detectors, context and policy, risk,
protection, encrypted vault, Git staged scanning and hook, npm wrapper, SDK,
provider profiles/attestations, structured LLM preflight, and metadata-only
audit. Future: VS Code UI, hosted management, Supabase, dashboard, transparent
proxy, logging integration, advanced detector adapters, and benchmark
evaluation.

## Rehearsal Checklist

- Complete two timed runs at 9:30–10:00 minutes.
- Do not read the literature table row by row; explain the integration gap.
- Point to the local/external boundary before describing provider handling.
- State “implemented on draft PR #2” unless the PR is merged before freeze.
- Distinguish test count from accuracy metrics without prompting.
- Keep two minutes for reviewer questions.
