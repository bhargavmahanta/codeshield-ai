# Phase 7: Local VS Code Extension

## Release and Phase 6 closeout

Phase 7 advances the engine, OpenAPI document, root workspace, npm packages,
SDK, and extension to `0.7.0`. Development is on
`phase-7-vscode-extension`, created from merged Phase 6 commit
`5e09aa421a3dda4dbb8dc311d1dd577288fda51d`.

The Phase 6 closeout was run before creating the branch. It passed 138 Python
tests, 10 TypeScript package tests, 7 build-tool tests, two consecutive clean
builds, two contract drift checks, package dry-runs, fixture and provider
checks, staged scanning, and every core/enhanced evaluation gate. No tag,
release, package publication, deployment, or SARIF upload was created.

## Architecture and data flow

The extension is a workspace extension. It does not contain the Python engine
and never downloads one. `codeshield.enginePath` identifies a separately
installed `0.7.x` engine and is machine-scoped so repository settings cannot
replace the executable.

```text
trusted VS Code document
        |
        | bounded JSON line on stdin
        v
owned `codeshield editor-session` process
        |
        | validated JSON line on stdout
        v
allowlisted metadata -> Problems / hover / status
        |
        +-> confirmed WorkspaceEdit for protection
```

The process is created with a fixed argument array and `shell: false`. Each
trusted workspace has at most one active editor operation and one owned local
session. Keeping the process alive avoids repeated Python initialization while
remaining a non-networked CLI subprocess. Cancellation or timeout terminates
only that owned process tree; the next operation starts a clean session.

Raw editor content exists only in VS Code memory, the stdio request, and the
engine's transient scanner state. It is never placed in argv, environment
variables, temporary files, diagnostics, hover text, status text, or the
CodeShield output channel. Responses are capped and runtime-validated before
use.

## Commands and settings

The extension contributes:

- `CodeShield: Scan Current File`
- `CodeShield: Scan Selection`
- `CodeShield: Scan Workspace`
- `CodeShield: Check Staged Changes`
- `CodeShield: Protect Selection`
- `CodeShield: Clear Diagnostics`
- `CodeShield: Show Detector Status`
- `CodeShield: Show Provider Profiles`
- `CodeShield: Verify Provider Attestation`

The default profile is `core`, destination is `local_file`, protection mode is
`type_placeholder`, maximum editor input is 1 MB, and scanning is manual.
`codeshield.scanOnSave` is available but defaults to `false`; the extension
never scans while typing. Workspace and editor timeouts are bounded.

`codeshield.policyPath` must be a normalized relative path that resolves to a
file inside the trusted workspace. `codeshield.vaultPath` and
`codeshield.attestationId` are machine-only, excluded from Settings Sync, and
are never displayed. Pseudonymization additionally requires an absolute local
vault path and the existing environment-provided vault key.

## Diagnostics and protection safety

Critical/high findings map to Error, medium to Warning, and low to
Information. Diagnostics use `CodeShield` as their source and stable codes
such as `CS.API_KEY`.

The extension discards engine explanations and masked previews. Messages and
remediation text are constructed from fixed extension-owned templates using
only validated category, severity, action, and detection-source enums.
Absolute, traversal, URI, malformed, or unrelativizable paths fail closed.
Results with invalid spans or stale document versions are discarded atomically.

Protection always presents the transformation mode and replacement count
before asking for confirmation. Immediately before applying a `WorkspaceEdit`,
the extension rechecks the document version and a SHA-256 fingerprint of the
selected content. This prevents stale-offset edits and preserves normal VS Code
undo behavior. Fragmented findings continue to fail closed because replacing a
composite expression is not syntax-safe.

## Workspace Trust and multi-root behavior

Content scan and protection commands are disabled in untrusted workspaces.
Clear Diagnostics and non-content detector/provider metadata remain available,
and their execution ignores workspace-local engine and policy choices.

Unsaved and dirty text documents are scanned from their in-memory content.
Binary/NUL-containing and oversized documents are skipped. Workspace roots are
scanned sequentially; staged checks require selecting one root. There is no
filesystem scan API, scan-on-type behavior, automatic engine installation,
telemetry, or network request.

## Build, CI, and local VSIX

Root type-check, test, and package checks use Node orchestration with fixed
arguments and `shell: false`. The hardened output allowlist now includes only
`packages/vscode-extension/dist` in addition to the three Phase 6 package
outputs. The extension is bundled as one CommonJS file with `vscode`
externalized and no source map.

Build and inspect a local VSIX:

```powershell
npm ci
npm run build
npm run package:vsix
```

The ignored artifact is `artifacts/codeshield-ai-0.7.0.vsix`. Packaging checks
an exact archive allowlist and rejects source maps, test data, credentials,
vaults, local paths, reports, and unexpected dependencies. There is no publish
script or Marketplace credential.

CI runs pushes only on `main` and all pull requests. The extension matrix
covers Ubuntu and Windows against VS Code 1.127 and 1.130, including unit
checks, a real local-engine diagnostics flow, command registration, and local
VSIX inspection.

Local Phase 7 verification passed 145 Python tests, 7 build-tool tests, 10
existing TypeScript package tests, 11 extension unit tests, and real-engine
extension-host runs on VS Code 1.127 and 1.130. It also passed two full builds,
contract drift twice, package dry-runs, the VSIX allowlist, npm audit, provider
and fixture checks, staged scanning, and all core/enhanced evaluation gates.

## Evaluation and performance

The committed Phase 6 core and enhanced evaluation suites and thresholds are
unchanged. The editor benchmark uses a 100 KB deterministic text document,
one warm-up request, and 20 warm local stdio requests. On the Windows
development machine on 2026-07-29, final warm core p95 was **139.54 ms**, below the
Phase 7 **750 ms** budget. The Phase 6 underlying 100 KB warm p95 baseline
remains **121.2 ms**, below its **250 ms** gate.

## Security review and limitations

- Subprocesses use fixed arguments and never invoke a shell.
- Extension messages never include raw engine stderr/stdout, raw findings,
  masked previews, pseudonym data, vault data, or absolute paths.
- Runtime schemas, output caps, normalized paths, cancellation, timeouts,
  version checks, trust checks, and stale-edit checks fail closed.
- npm audit reports no known vulnerabilities after exact direct pins and
  reviewed transitive overrides.
- The enhanced detector profile remains optional, larger, and slower.
- The first operation pays local engine process-start cost; the measured budget
  applies to warm operations in the owned session.
- Findings remain heuristic and can contain false positives or false negatives.
- VS Code Marketplace publication, hosted management, Supabase, telemetry,
  automatic downloads, deployments, SARIF upload, and the Phase 8 LLM proxy are
  out of scope.
