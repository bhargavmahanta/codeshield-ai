# Phase 1 Implementation and Testing Guide

Status: complete  
Engine version: `0.1.0`  
Verified result: 14 automated tests passing

## Purpose

Phase 1 establishes a runnable, local-first security engine. It scans files and
directories for common sensitive values, masks every reported value, scores the
risk for an intended destination, and exposes the result through a CLI. It also
provides a minimal local FastAPI service and a Python 3.12 Docker runtime.

## Implemented Scope

- Pydantic models for findings, scan results, destinations, severity, actions,
  and explainable risk factors.
- A detector protocol shared by regex and entropy detectors.
- Regex detection for email addresses, phone numbers, IPv4 addresses, JWTs,
  private keys, database URLs, credentials, API-key-like values, passwords,
  session IDs, and financial identifiers.
- Entropy detection for long random-looking tokens, including basic
  false-positive controls.
- Deterministic finding IDs, masked previews, deduplication, and overlap
  resolution.
- Destination-aware baseline risk scoring from 0 to 100.
- Typer commands: `codeshield scan`, `codeshield version`, and
  `codeshield server`.
- Human and JSON CLI output with CI-oriented exit codes.
- `.codeshieldignore`, exclusion globs, binary-file skipping, file-size limits,
  and scan timeouts.
- FastAPI `GET /health` and `GET /version` endpoints.
- Dockerfile and Docker Compose configuration pinned to Python 3.12.

Raw detected values are not fields on the `Finding` model and must not appear in
CLI output, API responses, or logs.

## Risk Thresholds and Exit Codes

| Risk score | Severity | Default action |
| --- | --- | --- |
| 0-29 | Low | Allow |
| 30-59 | Medium | Warn |
| 60-79 | High | Mask |
| 80-100 | Critical | Block |

| Exit code | Meaning |
| --- | --- |
| `0` | No finding requires intervention |
| `1` | At least one finding requires warning or masking |
| `2` | At least one finding is blocked |
| `3` | Configuration or execution error |

## Automated Verification

Run from `E:\Projects\codeshield-ai\engine`:

```powershell
..\.venv\Scripts\python.exe -m pytest tests
```

Expected result:

```text
14 passed
```

The FastAPI/Starlette TestClient deprecation warning is informational. It does
not indicate a failed test.

Run the same suite with Python 3.12 in Docker from the repository root:

```powershell
docker compose build engine
docker compose run --rm engine pytest
```

## Automated Test Catalogue

### TC-A01: Health endpoint

- Test: `tests/test_api.py::test_health_endpoint`
- Input: `GET /health` through FastAPI TestClient.
- Expected: HTTP 200, `status` is `ok`, and `local_only` is `true`.
- Purpose: verifies that the local service is alive and identifies itself as
  local-only.

### TC-A02: Version endpoint

- Test: `tests/test_api.py::test_version_endpoint`
- Input: `GET /version`.
- Expected: HTTP 200 and the package version in the response.
- Purpose: verifies API/package version consistency.

### TC-A03: Public Git API key blocking

- Test: `tests/test_cli.py::test_cli_scan_json_blocks_public_git_secret_without_raw_output`
- Input: a synthetic API-key-shaped value, destination `public_git`, and JSON
  output.
- Expected: exit code `2`, valid JSON, action `block`, and no raw token in CLI
  output.
- Purpose: verifies critical destination risk and the no-secret-output rule.

### TC-A04: Clean CLI scan

- Test: `tests/test_cli.py::test_cli_scan_returns_zero_when_no_findings`
- Input: a normal text file with no sensitive value.
- Expected: exit code `0` and a zero-finding message.
- Purpose: protects the normal clean-file path from false failures.

### TC-A05: CLI version

- Test: `tests/test_cli.py::test_cli_version`
- Input: `codeshield version`.
- Expected: exit code `0` and a non-empty version string.
- Purpose: verifies package entry-point wiring.

### TC-A06: Specific finding wins an overlap

- Test: `tests/test_dedupe.py::test_dedupe_prefers_specific_regex_finding_over_entropy_overlap`
- Input: overlapping generic entropy and specific regex API-key findings.
- Expected: only the API-key finding remains.
- Purpose: prevents duplicate reporting and preserves the most useful category.

### TC-A07: Non-overlapping finding order

- Test: `tests/test_dedupe.py::test_dedupe_keeps_non_overlapping_findings_in_order`
- Input: non-overlapping email and IP findings supplied in reverse order.
- Expected: both remain and are sorted by source position.
- Purpose: keeps output deterministic and easy to consume.

### TC-A08: High-entropy token

- Test: `tests/test_entropy_detector.py::test_entropy_detector_finds_high_entropy_token`
- Input: a long synthetic value containing varied characters.
- Expected: one `UNKNOWN_SECRET` finding with a masked preview.
- Purpose: detects unknown token formats without exposing the token.

### TC-A09: Low-entropy benign value

- Test: `tests/test_entropy_detector.py::test_entropy_detector_skips_low_entropy_benign_value`
- Input: a long repeated-character fixture.
- Expected: no finding.
- Purpose: verifies a basic entropy false-positive control.

### TC-A10: Common regex categories

- Test: `tests/test_regex_detector.py::test_regex_detector_masks_common_sensitive_values`
- Input: synthetic email, password, API key, IP address, and financial identifier.
- Expected: all categories are detected; password and API-key content is absent
  from every masked preview.
- Purpose: verifies common-format coverage and masking.

### TC-A11: Private-key masking

- Test: `tests/test_regex_detector.py::test_regex_detector_detects_private_key_without_exposing_body`
- Input: a synthetic PEM private-key block.
- Expected: category `PRIVATE_KEY`; the preview uses a private-key mask and does
  not contain key-body content.
- Purpose: verifies multiline detection and safe output.

### TC-A12: Critical public Git risk

- Test: `tests/test_risk_scoring.py::test_public_git_secret_scores_critical_block`
- Input: a high-confidence API-key finding destined for public Git.
- Expected: score at least 80, critical severity, and action `block`.
- Purpose: verifies the highest-risk baseline decision.

### TC-A13: Local email warning

- Test: `tests/test_risk_scoring.py::test_local_email_scores_warning_not_block`
- Input: a high-confidence email finding in a local file.
- Expected: score from 30 through 59 and action `warn`.
- Purpose: verifies that destination exposure changes the result.

### TC-A14: File filtering

- Test: `tests/test_scanner_files.py::test_scanner_skips_binary_oversized_and_excluded_files`
- Input: one included text file, one binary file, one oversized file, and one
  `.codeshieldignore` exclusion.
- Expected: only the included file is scanned; skip reasons include `binary`,
  `file too large`, and `excluded`.
- Purpose: verifies safe filesystem traversal controls.

## Manual Test Cases

Run these from `E:\Projects\codeshield-ai`. Use only synthetic values.

### TC-M01: Clean file

```powershell
Set-Content clean.txt 'print("Hello CodeShield")'
.\.venv\Scripts\codeshield.exe scan clean.txt
$LASTEXITCODE
```

Expected: zero findings and exit code `0`.

### TC-M02: Email and IP address

```powershell
Set-Content personal-data.txt @'
Contact: test.user@example.test
Server: 192.168.10.25
'@
.\.venv\Scripts\codeshield.exe scan personal-data.txt
```

Expected: email and IP findings with masked previews. Complete detected values
must not appear in output.

### TC-M03: Public Git API key

```powershell
Set-Content api-key.txt 'api_key = "sk_live_51SyntheticTokenValue999"'
.\.venv\Scripts\codeshield.exe scan api-key.txt --destination public_git --output json
$LASTEXITCODE
```

Expected: valid JSON, action `block`, masked output, and exit code `2`.

### TC-M04: Password assignment

```powershell
Set-Content password.txt 'password = "SyntheticPasswordValue12345"'
.\.venv\Scripts\codeshield.exe scan password.txt --destination public_git
```

Expected: a password finding with no complete password in output.

### TC-M05: Entropy comparison

```powershell
Set-Content entropy.txt 'token = "aZ8mQ2xP7vN4kR9tY6wL3cF1"'
Set-Content low-entropy.txt 'token = "aaaaaaaaaaaaaaaaaaaaaaaa"'
.\.venv\Scripts\codeshield.exe scan entropy.txt
.\.venv\Scripts\codeshield.exe scan low-entropy.txt
```

Expected: the varied token may be an `UNKNOWN_SECRET`; the repeated fixture
must not be reported by the entropy detector.

### TC-M06: Ignore file

```powershell
New-Item -ItemType Directory -Force manual-tests
Set-Content manual-tests\ignored.txt 'password = "SyntheticIgnoredPassword123"'
Set-Content manual-tests\.codeshieldignore 'ignored.txt'
.\.venv\Scripts\codeshield.exe scan manual-tests
```

Expected: `ignored.txt` is excluded.

### TC-M07: Directory scan

Add a clean file, a synthetic sensitive fixture, and an ignored file to one
directory, then scan the directory. Expected: eligible files are scanned,
findings include file/line/column locations, and ignored files are skipped.

### TC-M08: Local API service

```powershell
docker compose up engine
```

In a second PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
Invoke-RestMethod http://127.0.0.1:8765/version
```

Expected: health reports `ok` and `local_only`; version reports `0.1.0`.
Stop the foreground service with `Ctrl+C`, then run `docker compose down`.

## Security Acceptance Checklist

- [ ] Every fixture contains synthetic data only.
- [ ] Human output contains no complete detected value.
- [ ] JSON output contains no complete detected value.
- [ ] API responses and logs contain no complete detected value.
- [ ] A credential destined for public Git receives a block decision.
- [ ] Clean and repeated-character fixtures avoid obvious false positives.
- [ ] Binary, oversized, and ignored files receive an explainable skip reason.

## Windows Troubleshooting

The pytest configuration uses `--basetemp=.pytest-tmp` because some Windows
installations deny access to `%TEMP%\pytest-of-<user>`. It also disables pytest's
optional cache provider to avoid stale ACL-related cache failures.

If `.pytest-tmp` itself is denied, close active pytest processes and verify that
your Windows account has Modify permission on the repository directory.

## Phase 1 Limitations

- Context classification is not implemented.
- Policies are encoded in baseline Python weights rather than loaded from YAML.
- Findings can be masked for display, but protected output and consistent
  pseudonymization are not implemented.
- Presidio, spaCy, and an external secret scanner are not integrated.
- False positives and false negatives remain possible with regex and entropy
  heuristics.

