# Review 2 OpenCode runner results

## Implemented boundary

- Supports only OpenCode `1.18.26` on Linux and requires a prior local
  compatibility receipt keyed by SHA-256 of the binary and version.
- `doctor()` invokes only `--version` and `--pure run --help`, with bounded
  stdout/stderr and no prompt content. It does not inspect authentication.
- `run()` verifies the receipt without probing the executable, then starts one
  content subprocess with this fixed argv and sends content only over stdin:
  `--pure run --format json --model MODEL --agent codeshield-review2 --title CodeShield-Review2`.
- The subprocess receives a minimal environment, preserves only the `HOME` and
  `XDG_DATA_HOME` pointers needed by built-in OAuth, uses temporary working,
  config, cache, state, and temp directories, denies every tool globally and
  for the named agent, disables sharing and external configuration sources,
  and does not disable built-in plugins.
- Stdout is limited to 2,000,000 bytes and stderr to 65,536 bytes while both
  are consumed concurrently. The timeout is 120 seconds. Breaches terminate
  only the process group created by `start_new_session=True`.

## Verification

From `engine/`:

- RED: `..\.venv312\Scripts\python.exe -m pytest tests/test_opencode_runner.py --basetemp=C:\Users\bharg\AppData\Local\Temp\codeshield-review2-runner-red-019f753e -o addopts='' -p no:cacheprovider -q`
  - Result: 7 failed because `codeshield.opencode.runner` did not exist.
- Focused GREEN: `..\.venv312\Scripts\python.exe -m pytest tests/test_opencode_runner.py --basetemp=C:\Users\bharg\AppData\Local\Temp\codeshield-review2-runner-focused-final-019f753e -o addopts='' -p no:cacheprovider -q`
  - Result: 8 passed.
- Final combined suite: `..\.venv312\Scripts\python.exe -m pytest tests/test_opencode.py tests/test_opencode_runner.py --basetemp=C:\Users\bharg\AppData\Local\Temp\codeshield-review2-runner-final-019f753e -o addopts='' -p no:cacheprovider -q`
  - Result: 41 passed.

The installed WSL binary independently reported `1.18.26`, and
`--pure run --help` exposed all required flags. The real metadata-only
`doctor()` subsequently passed and created a receipt under the dedicated
`/tmp/codeshield-review2-doctor-019f753e` test location. No live content run
was attempted.

One compatibility detail was captured in the test double: under the isolated
non-interactive environment, OpenCode emits help on stderr. Both metadata
streams are bounded and validated without being returned or logged.

## Security hardening follow-up

The runner now selects literal `/tmp` as its native Linux temporary root rather
than trusting `TMPDIR` or `TEMP`. Before creating the mode-private randomized
runtime directory, it rejects a root inside the current working tree or its
repository and rejects link-like or instruction-bearing ancestors containing
`AGENTS.md` or `.opencode`. The non-Linux temporary-root fallback exists only
for offline unit testing; all runner and doctor entrypoints still reject
non-Linux execution.

The reviewed OpenCode 1.18.26 inline configuration now explicitly sets
`mcp: {}`, `plugin: []`, `instructions: []`, and
`enabled_providers: ["openai"]`, in addition to the global and named-agent
wildcard tool and permission denials. The fixed `--pure` argument and external
configuration disable flags remain in place. `HOME` and `XDG_DATA_HOME` remain
opaque data-location pointers; the runner does not open authentication files.
This supersedes the earlier statement above that plugins were not disabled.

Compatibility receipt writes reject link-like parent components and targets,
repeat validation around directory creation and atomic replacement, and keep
the temporary receipt mode at `0600`. Receipt reads reject link-like paths and
use `O_NOFOLLOW` where the host exposes it, then validate the opened object as
a small regular file before parsing it.

Every exception after `Popen` ownership is acquired now enters bounded cleanup.
Timeouts and `BaseException` cancellation (including interrupts during either
`wait()` or worker-thread joins) kill only the process group created by
`start_new_session=True`, perform a bounded reap and bounded joins, and close
only stopped workers' pipes so cleanup cannot block indefinitely on a live
pipe operation.

### Follow-up verification

From `engine/` on native Windows Python 3.12.10, with isolated OS temporary
directories and no credential-file reads or provider/content execution:

- Pre-hardening focused baseline:
  `..\.venv312\Scripts\python.exe -m pytest tests/test_opencode_runner.py ... -q`
  - Result: **8 passed** in 0.42 seconds.
- Hardening RED run of the focused file:
  - Result: **8 failed, 7 passed** in 0.82 seconds. Failures independently
    demonstrated the missing explicit configuration, poisoned temp selection,
    unsafe temp ancestors/repository placement, link-like receipt paths, and
    interrupt cleanup.
- Join-cancellation RED regression:
  `..\.venv312\Scripts\python.exe -m pytest tests/test_opencode_runner.py -k 'interrupt_while_joining' ... -q`
  - Result: **1 failed, 15 deselected** because the interrupt was swallowed
    before cleanup was tightened.
- Focused GREEN:
  `..\.venv312\Scripts\python.exe -m pytest tests/test_opencode_runner.py ... -q`
  - Result: **16 passed** in 0.61 seconds.
- Combined coordinator, runner, and real-process-stub suite:
  `..\.venv312\Scripts\python.exe -m pytest tests/test_opencode.py tests/test_opencode_runner.py tests/test_opencode_process.py ... -q`
  - Result: **50 passed, 1 skipped** in 2.70 seconds. The skip is the explicitly
    Linux-only real OS-pipe test on Windows.
- Phase 9 preservation check:
  `..\.venv312\Scripts\python.exe -m pytest tests/test_management.py ... -q`
  - Result: **10 passed, 1 skipped** in 1.20 seconds.

The optional Ruff module is not installed in this venv. A separate compileall
attempt could not write an existing protected `tests/__pycache__` entry;
pytest imported and executed the changed runner and test module in every green
run above.

### Remaining boundary limitations

- Linux remains the only supported execution platform; Windows coverage here
  is deliberately offline and uses process doubles.
- The adapter mediates only CodeShield-started OpenCode processes. It does not
  sandbox independently launched sessions or control provider/OpenCode
  retention.
- Existing link-like receipt components are rejected and targets are opened
  no-follow where supported. As with other per-user filesystem state, a hostile
  process already running as the same OS account can still race or replace
  surrounding writable directories; protecting against a fully compromised
  same-account environment is outside this adapter boundary.
- Worker joins and the post-kill reap are bounded. If an operating-system pipe
  operation remains uninterruptibly stuck even after group termination, its
  daemon worker is left for process shutdown rather than risking an unbounded
  close.

### Integrated verification

An intermediate aggregate run observed three intentionally failing new RED
tests for optional protocol field types. They were newly added cases, not a
regression in previously passing behavior. Snapshot/string and metadata/object
validation was then implemented; all **37 coordinator/protocol tests passed**.
The focused reviewer confirmed both reported issues were closed.

Native WSL integration subsequently passed **57 tests in 4.50 seconds**,
including real OS-pipe stdin transport, stdout/stderr overflow, and timeout.
The hardened doctor passed against OpenCode 1.18.26, and the reviewed Public
live demo completed with WARN, one content invocation, and inbound PASSED.

Final review identified a cancellation window after process creation but
before worker setup. The new regression first failed with zero cleanup calls,
then passed after worker initialization was moved inside the ownership cleanup
boundary. Final focused runner result: **17 passed in 0.59 seconds**. Final WSL
OpenCode integration: **58 passed in 6.14 seconds**. Final Windows engine suite:
**257 passed, 6 skipped in 64.08 seconds**; the sole warning is the pre-existing
Starlette/httpx deprecation. The post-fix live Public and blocked demonstrations
both repeated successfully.
