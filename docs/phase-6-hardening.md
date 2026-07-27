# Phase 6: Cross-Platform Hardening and Interoperability

CodeShield `0.6.0` adds repeatable Windows/Linux builds, leakage-safe SARIF
2.1.0, conservative static reconstruction of fragmented secrets, and
read-only metadata interfaces for local clients. The Public, Internal,
Confidential, and Restricted sensitivity model is unchanged.

## Cross-Platform Build

The root build is controlled by Node scripts using fixed argument arrays. Only
`packages/shared/dist`, `packages/cli/dist`, and `packages/sdk/dist` may be
cleaned. Resolved paths are checked before deletion and symbolic outputs are
rejected.

Contracts are generated outside the repository, structurally validated, and
then replaced with backup/rollback handling. Contract drift checks compare
temporary output and do not rewrite tracked files.

```powershell
npm ci
$env:CODESHIELD_PYTHON="$PWD\.venv312\Scripts\python.exe"
npm run build
npm run build
npm run check:contracts
npm test
```

If Windows reports that generated output is locked, close the process using the
specific `dist` directory and retry. Disabling antivirus or weakening file
permissions is neither required nor recommended.

## SARIF 2.1.0

```powershell
codeshield scan . --destination private_git --format sarif
codeshield scan . --destination private_git --format sarif --output codeshield.sarif
codeshield check-staged --format sarif --output staged.sarif
```

`--format` accepts `human`, `json`, and `sarif`. For compatibility,
`--output json` and `--output human` still select a stdout format but emit a
deprecation notice on stderr. When `--format` is supplied, `--output` is a file
path.

SARIF includes stable CodeShield rule IDs, category, severity, confidence,
recommended action, remediation, safe fingerprints, and accurate start/end
regions. It excludes raw values, masked previews, pseudonym data, absolute
paths, source roots, skipped-file paths, and timestamps. Unsafe paths cause a
configuration error instead of partial output.

The inert example at
[`../.github/examples/codeshield-sarif.yml`](../.github/examples/codeshield-sarif.yml)
must be explicitly copied into `.github/workflows` before it can run. Uploading
SARIF sends repository-relative paths and finding metadata to GitHub and may
require GitHub Code Security for private repositories.

## Static Fragment Reconstruction

Fragment reconstruction is dependency-light and enabled in both detector
profiles:

```yaml
detectors:
  profile: core
  fragments:
    enabled: true
    max_fragments: 8
    max_reconstructed_length: 512
```

Supported inputs are Python literal adjacency, `+` expressions, prior simple
constants and constant-only f-strings; JavaScript/TypeScript literal
concatenation, prior top-level `const` values and static templates; and JSON
string arrays under explicit keys such as `api_key_parts`.

CodeShield does not resolve function calls, attribute access, indexing,
arithmetic, forward references, reassigned variables, computed templates, or
arbitrary JSON arrays. It never imports or executes scanned code. Reconstructed
values exist only transiently and are checked with the existing regex rules;
entropy is not applied. Automatic protection of a non-blocked composite finding
fails closed because rewriting a source expression as plain text is not
syntax-safe.

## Local API Additions

- `GET /detectors/status`
- `GET /providers`
- `GET /providers/verify`
- `GET /providers/{profile_id}`
- `POST /providers/attestations/status`

These endpoints expose reviewed configuration metadata and fixed status codes
only. Filesystem scanning, staged Git access, and standalone policy evaluation
were intentionally not added to the API.

## Reproducible Evaluation

Phase 5 remains available. Run Phase 6 independently:

```powershell
$env:CODESHIELD_DATA_HOME="$PWD\.phase6-data"
codeshield evaluate prepare --suite phase6
codeshield evaluate run --suite phase6 --profile core --output core.json
codeshield evaluate compare reports\phase6\core-baseline.json core.json
```

The committed Windows baseline records:

- 8/8 supported fragmented secrets detected.
- 0/12 fragment-negative cases flagged.
- Fragment exact recall `1.00` and negative-case FPR `0.00`.
- Core 100 KB warm p95 `121.20 ms`, within the `250 ms` budget.
- Enhanced 100 KB warm p95 `841.42 ms`, within the `3 s` budget.
- Enhanced overall exact F2 `0.9231`.

Compared with Phase 5, measured 100 KB warm p95 increased by `50.83 ms` for
core and `59.81 ms` for enhanced. Results are synthetic engineering
measurements, not real-world accuracy claims.

## Implementation Map

- `scripts/` contains the fixed-target build, cleanup, replacement, and
  contract-drift tooling.
- `engine/codeshield/sarif/` contains the validated SARIF model and renderer.
- `engine/codeshield/detectors/fragments.py` contains static fragment
  reconstruction.
- `engine/codeshield/api/main.py` and `packages/sdk/src/index.ts` contain the
  new read-only API and SDK interfaces.
- `engine/codeshield/evaluation/manifest_phase6.yaml` and `reports/phase6/`
  contain the versioned suite definition and reproducible aggregate baselines.
- `.github/workflows/ci.yml` covers Ubuntu and Windows; the non-executing SARIF
  upload example remains under `.github/examples/`.

## Verification and Review

The Phase 6 review ran the complete Python suite, Node build-tool tests,
TypeScript package tests and type checks, two consecutive clean builds,
contract drift, package dry-runs, core and enhanced evaluation comparisons,
fixture classification, provider evidence validation, and an isolated-index
staged scan. The final local results were:

- Python: `138 passed`.
- TypeScript packages: `10 passed`; Node build tooling: `3 passed`.
- Core and enhanced Phase 6 evaluation comparisons: passed all gates.
- Contract drift, package contents, fixture checks, and provider checks:
  passed.

Review found and corrected one Windows-specific issue before sign-off:
`fsync` must use a writable file descriptor on Windows. No release, push,
deployment, SARIF upload, or external write was performed.

## Security Review and Limitations

- SARIF tests use synthetic credentials and assert that raw values, previews,
  absolute paths, and temporary content do not escape.
- All CodeShield child processes use argument arrays with shell execution
  disabled.
- Static reconstruction is deliberately incomplete and may miss obfuscated,
  encoded, cross-file, dynamically computed, or language-specific expressions.
- JSON reconstruction requires an explicit fragment-signalling key.
- GitHub SARIF upload remains disabled and no package or service is published.
