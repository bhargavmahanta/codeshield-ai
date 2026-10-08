# Review 2: inspected OpenCode demo

## Status

Gate A and Gate B have been implemented and verified locally. No commit, push,
merge, branch change, provider publication, or authentication-file inspection
was performed.

## Boundary

The existing Typer CLI uses `LlmPreflightService`, the real scanner, context
classifier, risk scorer, policy engine, provider registry, protection service,
and metadata-only audit store. A final Public-only authorization gate returns
before any OpenCode executable lookup when transmission is denied.

For an approved request, one isolated OpenCode process receives the protected
prompt through stdin. Its entire text-only response must pass strict event
validation and inbound inspection before the CLI displays any response content.
Terminal controls are escaped. Errors never display raw subprocess streams.

The route is `openai-chatgpt-plus-pro-via-opencode`: OpenCode using existing
ChatGPT Plus/Pro sign-in. It is not the standard API, Enterprise, or ZDR route.
The conservative reference profile permits only Public content with WARN.
WARN is not relabeled ALLOW. Non-public pseudonymization is offline-only.

The safe preset supplies application-owned reviewed Public context, not a
hard-coded detector result. Arbitrary stdin/file input is not automatically
Public, and a source path or inline annotation cannot lower its sensitivity.

## Rehearsal commands

Run in Ubuntu WSL with Python 3.12 and the existing authenticated OpenCode
1.18.26 installation. CodeShield does not inspect or copy its authentication.

The rehearsed engine environment is on WSL's native filesystem. From the
repository root, setup/use it with:

```bash
python3 -m venv "$HOME/.cache/codeshield-review2-venv"
"$HOME/.cache/codeshield-review2-venv/bin/python" -m pip install -e ./engine pytest
source "$HOME/.cache/codeshield-review2-venv/bin/activate"
export CODESHIELD_OPENCODE_EXECUTABLE="$HOME/.opencode/bin/opencode"
export CODESHIELD_HOME="$HOME/.cache/codeshield-review2-state"
```

These settings contain only local executable/state paths, not credentials.
Do not set or copy an OpenAI API key. Installation on the Windows-mounted
artifact directory stalled on disk I/O; the native cache installation finished.

```bash
codeshield prompt doctor --via opencode
codeshield prompt run --via opencode --model openai/gpt-5.5 --demo safe --explain
codeshield prompt run --via opencode --model openai/gpt-5.5 --demo test-credential --explain
codeshield prompt run --via opencode --model openai/gpt-5.5 --demo production-secret --explain
```

The model was changed from `openai/gpt-5.4-mini` on 2026-10-08. OpenAI
retired the `gpt-5.3`/`gpt-5.4` families for ChatGPT subscription accounts, so
that route now rejects them with `400` and `"not supported when using Codex
with a ChatGPT account"`. CodeShield surfaces this as `CS_OPENCODE_FAILED`
(exit `3`) because it never echoes subprocess output. Confirm a model is
entitled before rehearsing; CodeShield will not substitute one automatically.
Confirming models never changes a security decision: a blocked preset blocks
identically regardless of which entitled model is named.

Inputs can instead use exactly one of `--stdin` or `--file FILE`, with an
optional sanitized repository-relative `--source-path PATH`. Input is capped
at 1 MB. No content is passed in process arguments or environment variables.

Verified safe outcome:

```text
Decision: WARN
Transmission permitted: YES
OpenCode: INVOKED ONCE
Inbound inspection: PASSED
```

Expected synthetic credential outcome:

```text
Decision: BLOCK
Transmission permitted: NO
OpenCode: NOT INVOKED
Sensitivity: Restricted
```

Exit status is 0 for ALLOW, 1 for WARN, 2 for policy/inbound blocking, and 3
for configuration or execution failure. A successful WARN demo intentionally
has exit status 1.

## Narration

- Safe: “This is reviewed Public content. CodeShield scans it locally, applies
  provider policy, and only then starts OpenCode.”
- Test credential: “Context recognizes synthetic test data, but context cannot
  weaken the mandatory LLM credential-protection rule.”
- Production-looking synthetic credential: “The real detector classifies this
  as Restricted. CodeShield stops before starting OpenCode.”

The explanation distinguishes finding-level policy from the mandatory LLM
transfer rule. Deterministic context rules are labeled separately from ML
fallback; the demo does not claim all classifications use ML.

## Actual verification so far

- Scoped clock correction: four formerly date-dependent tests passed, with
  production expiry logic and fixture expiry dates unchanged.
- Credential assignment regression: six regex tests passed.
- Combined relevant baseline and coordinator/protocol tests:
  **149 passed, 1 skipped, 1 deselected**, 18.14 seconds. The deselected test
  is runner isolation, pending that adapter. One existing Starlette/httpx
  deprecation warning remains.
- Automated receivers verify zero invocations for both blocked presets and
  one invocation for safe Public content. No real credentials are used.
- See `review2-baseline-results.md` for exact prerequisite commands/results.
- Subsequent targeted coordinator/protocol tests: **32 passed**, with runner
  isolation deselected. Four malformed structural-field regressions first
  failed, then passed after strict validation was added.
- Broader discovery exposed one additional dated commit-hook fixture. Its
  copied temporary policy now uses a one-day exception; all **4 hook tests
  passed**. No production policy document was changed.
- Existing TypeScript CLI/SDK tests: **3 + 7 passed**. Both package type-checks
  passed with `node node_modules/typescript/bin/tsc -p PACKAGE/tsconfig.json
  --noEmit`. The CLI tests deliberately exercise sanitized missing-engine and
  terminated-process messages.
- WSL native CLI production-secret and test-credential demos both returned
  `Decision: BLOCK`, `Transmission permitted: NO`, `OpenCode: NOT INVOKED`,
  `Sensitivity: Restricted`, and mandatory LLM rule BLOCK while the executable
  was deliberately set to `/missing/opencode`. Contexts were respectively
  `probable_real_secret` (0.94) and `test_data` (0.95). An independent child
  process check confirmed the production demo's native exit code was **2**.
- Current coordinator/protocol/CLI tests: **34 passed**, including refusing
  `--file auth.json` before opening it. After the final review fixes this rose
  to **37 passed**.
- Hardened metadata-only `prompt doctor --via opencode`: **passed**, exact
  installed version 1.18.26; authentication not inspected.
- Live Public smoke: **WARN**, transmission permitted, OpenCode invoked once,
  inbound inspection PASSED. Displayed answer: “Python raises an `IndexError`
  when you access a list index that is out of range.” No real secret was used.
- Final WSL OpenCode integration: **58 passed in 6.14 seconds**, including real
  offline process transport, stdout/stderr overflow, timeout cleanup, and the
  final pre-worker cancellation regression.
- Final Windows engine suite: **257 passed, 6 skipped in 64.08 seconds**, with
  one pre-existing Starlette/httpx deprecation warning.
- Final TypeScript CLI/SDK tests: **3 + 7 passed**; both type-checks passed.
- Post-fix blocked rehearsal again returned Restricted BLOCK and `OpenCode:
  NOT INVOKED` while the executable path was deliberately missing. The live
  Public rehearsal again returned WARN, invoked OpenCode once, passed inbound
  inspection, and displayed: “Python raises an `IndexError` when a list index
  is out of range.”

Exact WSL integration command (from the repository root):

```bash
python -m pytest engine/tests/test_opencode.py engine/tests/test_opencode_runner.py engine/tests/test_opencode_process.py -o addopts= -p no:cacheprovider -q --tb=short --basetemp=/tmp/review2-linux-final-2
```

## Troubleshooting

- If compatibility is missing or the binary changes, run `prompt doctor`
  explicitly. `prompt run` never probes automatically or changes models.
- `CS_OPENCODE_TIMEOUT`, `CS_OPENCODE_OUTPUT_LIMIT`, and protocol failures
  release no answer. Do not work around them by disabling inspection.
- Ensure the existing OpenCode sign-in is configured by the user. CodeShield
  will neither inspect it nor inject an API key.
- Input through `--file` or `--stdin` is conservatively non-Public unless a
  supported application-owned reviewed context exists. Use `--demo safe` for
  this approved Public rehearsal; changing a path cannot downgrade sensitivity.
- OpenCode content execution is Linux/WSL-only. Windows unit tests use offline
  doubles, while real process transport/cleanup is exercised in WSL.

## Limitations and privacy

This is an explicit CLI-mediated boundary, not interception of independently
started OpenCode sessions. OpenCode may maintain its own local session
metadata. CodeShield guarantees inspection before its own authorized external
execution and before it displays the buffered answer; it does not claim to
control the provider's retention or OpenCode's independent local storage.

No project files, project instructions, tools, plugins, or skills may be made
available to the demo agent. Native Windows live execution is not part of the
WSL rehearsal. Missing/incompatible engines must fail closed without fallback
models, authentication routes, or automatic retries.

References: [OpenCode CLI](https://opencode.ai/docs/cli/),
[OpenCode configuration](https://opencode.ai/docs/config/),
[ChatGPT plan use](https://help.openai.com/en/articles/11369540-codex-in-chatgpt).
