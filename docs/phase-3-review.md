# Phase 3 Review: Git Protection and TypeScript Tooling

Status: implementation complete locally; GitHub publication requires an authenticated `gh` session.

Target: CodeShield Engine 0.3.0  
Feature freeze: July 31, 2026  
Review window: August 1-7, 2026

## What Phase 3 Demonstrates

CodeShield scans only added staged lines, maps masked findings to target file lines, and enforces destination-aware policy from `.codeshield.yaml`. A managed pre-commit hook blocks probable real credentials in private or public Git. Reviewable exceptions are limited to scoped placeholder/test-data paths, allowed categories, and an expiry date.

The local npm CLI forwards directly to the Python CLI without a shell. The typed SDK uses generated FastAPI OpenAPI contracts and calls only a configurable loopback service.

```text
git index -> zero-context diff -> Python detectors -> context -> policy -> hook exit
                                      ^
npm CLI ------------------------------|

TypeScript SDK -> 127.0.0.1 FastAPI -> scan/protect/restore
```

## One-Time Windows Setup

```powershell
winget install --id Python.Python.3.12 --exact
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install -e ".\engine[dev]"
npm ci
npm run generate:contracts
npm run typecheck
npm run build
$env:CODESHIELD_PYTHON = "$PWD\.venv312\Scripts\python.exe"
```

Docker remains the Python 3.12 fallback:

```powershell
docker compose build engine
docker compose run --rm engine pytest
```

## Five-Minute Demo

### 1. Confirm versions and tests

```powershell
.\.venv312\Scripts\python.exe -m codeshield.cli version
.\.venv312\Scripts\python.exe -m pytest engine\tests
npm run typecheck
npm test
```

Expected: version `0.3.0`, all Python tests pass, and both Vitest suites pass.

### 2. Install the native hook

```powershell
.\.venv312\Scripts\codeshield.exe install-hook
.\.venv312\Scripts\codeshield.exe hook-status
```

Expected: the hook is `managed`. An existing unmanaged hook is never overwritten.

### 3. Block an actual commit safely

```powershell
$reviewToken = ('sk_' + 'live_51ReviewDemo' + '93628471')
Set-Content -Path demo-blocked.py -Value "api_key = '$reviewToken'"
git add demo-blocked.py
git commit -m "demonstrate CodeShield block"
```

Expected: the commit fails. Output includes `action=block`, a masked preview, and a repository-relative line, but never the complete token.

```powershell
git restore --staged demo-blocked.py
Remove-Item demo-blocked.py
```

### 4. Show a controlled review exception

```powershell
New-Item -ItemType Directory -Force demo\review-fixtures | Out-Null
Set-Content -Path demo\review-fixtures\key.txt -Value "api_key = '$reviewToken'"
git add demo\review-fixtures\key.txt
git commit -m "add approved synthetic review fixture"
```

Expected: a warning includes `exception=review-test-api-key`; the risk remains critical, and the commit succeeds because the fixture is test data and the exception is unexpired.

### 5. Exercise the npm CLI and SDK

```powershell
node packages\cli\dist\index.js version
.\.venv312\Scripts\codeshield.exe server
```

In a second terminal:

```powershell
npm run demo:sdk
```

Expected: the npm CLI prints `0.3.0`; the SDK prints a masked scan result, a pseudonymized value, and `restore successful: true`.

## Standard Verification

```powershell
.\.venv312\Scripts\python.exe -m pytest engine\tests
npm ci
npm run generate:contracts
npm run check:contracts
npm run typecheck
npm run build
npm test
npm run pack:check
```

The Docker service can be stopped with `Ctrl+C`, or with `docker compose down` when it was started detached.

## pre-commit Framework Consumer Configuration

```yaml
repos:
  - repo: https://github.com/OWNER/codeshield-ai
    rev: phase-3-review
    hooks:
      - id: codeshield-check-staged
```

The hook declares `pass_filenames: false` because CodeShield reads the Git index itself.

## Security Boundaries

- Git commands use argument arrays, `shell=False`, timeouts, and generic errors.
- Deleted and unstaged text is not scanned; binary patches are reported as skipped.
- Repository visibility is explicit. CodeShield never infers it from a remote URL.
- Exceptions cannot cover private keys or cloud credentials and cannot use repository-wide globs.
- SDK errors omit request and response bodies.
- Native `git commit --no-verify` cannot be prevented. Pull-request CI reconstructs changed additions in an isolated Git index and scans them again.

## Known Limitations

- Python 3.12 installation is still a workstation prerequisite; Docker is the reproducible fallback.
- The npm packages are private workspaces and are not published to a registry.
- Renames are scanned only when the patch contains added lines.
- Binary contents are skipped rather than decoded or uploaded.
- GitHub repository creation, reviewer access, and the draft pull request require valid GitHub CLI authentication.
- VS Code, hosted services, dashboard, Presidio/spaCy, and the LLM proxy remain out of scope.

## Screenshot Checklist

- Green Python test summary.
- Green TypeScript build and Vitest summary.
- Managed hook status.
- Failed commit with masked `action=block` output.
- Successful exception commit with visible exception ID.
- npm CLI version output.
- SDK masked scan and restoration result.
- Private GitHub `phase-3-review` branch and green CI checks.
