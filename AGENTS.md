# AGENTS.md

Local-first sensitive-data protection for developer workflows. Monorepo: Python
engine (`engine/`), TypeScript workspaces (`packages/`, `apps/dashboard`), a
local Supabase stack (`supabase/`), and phase documentation (`docs/`).

This file owns repository-specific constraints. General engineering policy is not
restated here.

## Before you change anything

1. Read the root `README.md` and the relevant `docs/phase-*.md` before editing.
   Phase documents record the security decisions behind the current code.
2. Locate the existing implementation first. A helper, policy table, detector, or
   contract already solving your problem should be reused, not reimplemented.
3. Treat `docs/README.md` as the documentation index. Add new documents there.
4. Preserve backward compatibility of every published contract: the Typer CLI
   (`codeshield`), the FastAPI services, the TypeScript SDK and CLI, the SARIF
   and OpenAPI outputs, the VS Code extension, and the policy YAML schema.
   Breaking one of these is a breaking change, not a cleanup.

## Security boundaries

These are the product. Never weaken them, and never route around them to make a
test, build, or demonstration pass.

- **Local-first.** Scanning, classification, pseudonymization, vault keys, and
  the pseudonym mapping table stay on the developer machine.
- **Fail closed.** When a provider profile is missing, unreviewed, expired, or
  cannot be verified, deny the transfer. Never fall back to a permissive
  default, a different model, or another authentication route.
- **The management plane accepts metadata only.** Category and action counts,
  sensitivity, identifiers, versions, status buckets, HMAC event identifiers,
  and reviewed policy documents. Prompts, responses, source, findings,
  previews, absolute paths, credentials, pseudonyms, keys, and arbitrary content
  fields are rejected before persistence.
- **Never** expose or log secrets, tokens, raw prompts, vault keys, or
  pseudonym mappings. Error paths must not echo content — CLI error output stays
  a fixed code string.
- **Never execute untrusted scanned content.** Subprocess adapters use a
  minimal environment, isolated working/config/cache directories, a fixed argv,
  content passed only over stdin, bounded stdout/stderr, a timeout, and
  process-group termination. Preserve all of it when editing an adapter.
- **Provider checks are not advisory.** Bypassing preflight, inbound
  inspection, or a compatibility check to obtain a passing result invalidates
  the result and the change.

## Repository facts worth knowing

- The engine targets **Python 3.12 only** (`requires-python = ">=3.12,<3.13"`).
  CI matrix: Ubuntu and Windows, Node 20 and 22, Python 3.12.
- Install the CLI with `python -m pip install -e ./engine`. There is no
  preinstalled global `codeshield`.
- **Line endings are repository-managed.** `.gitattributes` sets
  `* text=auto eol=lf`; all blobs are stored LF. If many files ever appear
  modified at once, suspect a stray `core.autocrlf` before editing content —
  do not reformat files to "fix" it.
- **The OpenCode runner pins an exact version** (`OPENCODE_VERSION` in
  `engine/codeshield/opencode/runner.py`) and enforces strict equality against
  the installed binary. To run against a different OpenCode build, install that
  version **side-by-side** and point `CODESHIELD_OPENCODE_EXECUTABLE` at it.
  Never relax the version comparison and never overwrite a user's existing
  OpenCode installation.
- CLI exit codes are meaningful: `0` ALLOW, `1` WARN, `2` policy or inbound
  block, `3` configuration or execution failure. **A permitted WARN request
  exits `1` and is a success.** Do not "fix" it.
- Evaluation suites need `CODESHIELD_DATA_HOME` pointing at a writable datasets
  directory.
- Optional detector suites require the `enhanced` and `evaluation` extras
  (Presidio, spaCy, Gitleaks). Their absence is an environment limitation, not a
  regression.

## Verifying a change

`.github/workflows/ci.yml` is the authoritative gate list — read it rather than
guessing. `package.json` holds the Node entry points.

Fast local subset for engine changes:

```bash
python -m pip install -e "./engine[dev]"
python -m pytest engine/tests
```

Node workspaces:

```bash
npm run typecheck
npm run build
npm test
npm run check:contracts
npm run pack:check
```

Rules for verification:

- Add a regression test with every behavior change, and read the existing tests
  for the area before implementing.
- Report the exact command and real counts. Distinguish failures from skips,
  environment problems, and pre-existing failures. A skipped or unexecuted
  check is never reported as passing.
- Keep security tests intact. Never weaken an assertion to make a suite pass.
- Avoid unrelated refactoring, dependency upgrades, version bumps, and
  unrequested architectural changes. Scoped work is easier to review and to
  revert.

## Git

- No destructive history operations: no `reset --hard`, no `clean -fd`, no
  force-push, no bypassing branch protection, no overwriting concurrent work.
- Keep commits focused; stage only intended files and inspect the staged diff
  before committing.
- Never commit generated output, local virtualenvs, datasets, cached binaries,
  or credential-shaped fixtures. `.gitignore` already covers these.
- Never commit credentials. Synthetic test values must be unmistakably fake.