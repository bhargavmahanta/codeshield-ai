# Phase 2 Context, Policy, and Protection Guide

CodeShield Engine `0.2.0` adds context classification, validated destination
policies, configurable explainable risk, protected-text generation, and local
encrypted pseudonymization.

## Processing Flow

```text
detectors -> deduplication -> context classifier -> policy -> risk -> protection
```

The original value is read transiently from the input span. It is not stored on
the `Finding` model and is not included in scan output, logs, or explanations.

## Context Labels

- `probable_real_secret`
- `placeholder`
- `test_data`
- `public_information`
- `personal_data`
- `confidential_business_data`
- `uncertain`

The classifier combines conservative rules with a scikit-learn logistic
regression model trained from deterministic synthetic feature records. Features
describe structure and context; they are not raw values or complete source text.

Evaluate the baseline model with:

```powershell
codeshield evaluate-context
```

The command reports accuracy, macro precision/recall/F1, and a confusion matrix
for a fixed synthetic train/test split.

## Policies

The packaged default policy is
`engine/codeshield/policies/default.yaml`. A user-editable example is available
at `policies/default.yaml`.

Validate a policy before scanning:

```powershell
codeshield policy validate policies/default.yaml
codeshield scan . --policy policies/default.yaml --destination public_git
```

Policies define complete scoring maps and prioritized rules. Matching uses
priority and specificity, not YAML order. Conflicting ties fail validation.
Mandatory actions are an action floor: risk scoring may choose a stricter action
but cannot weaken the mandatory rule.

## Protection Modes

- `redact`: replace each finding with `<REDACTED>`.
- `partial_mask`: use a category-specific masked preview.
- `type_placeholder`: replace with a type marker such as `<EMAIL>`.
- `pseudonymize`: use a consistent local marker such as `<EMAIL_1>`.

Protect a file without modifying the input:

```powershell
codeshield protect input.txt --mode type_placeholder --output protected.txt
```

CodeShield refuses to use the input path as the output path. A mandatory block
rule returns exit code `2` and writes no protected content.

## Encrypted Pseudonym Vault

Persistent CLI pseudonymization requires a URL-safe base64 encoded 32-byte key
in `CODESHIELD_VAULT_KEY`. Generate a key locally in PowerShell:

```powershell
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:CODESHIELD_VAULT_KEY = [Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_')
```

Protect and restore within a named session:

```powershell
codeshield protect input.txt --mode pseudonymize --session demo --vault .codeshield-vault.sqlite --output protected.txt
codeshield restore protected.txt --session demo --vault .codeshield-vault.sqlite --output restored.txt
```

The SQLite vault stores a keyed HMAC lookup token, safe metadata, a unique nonce,
and AES-GCM ciphertext. It does not store plaintext mappings. The key is not
written to the database or repository. Losing the key makes restoration
impossible.

The local API uses an in-memory encrypted vault. Its pseudonyms can be restored
only while that service process remains running.

## Local API

The existing endpoints remain:

- `GET /health`
- `GET /version`

Phase 2 adds:

- `POST /scan/text`
- `POST /protect`
- `POST /restore`

Requests are limited to 1,000,000 bytes when `Content-Length` is present, unknown
fields are rejected, CORS remains restricted to localhost origins, and the CLI
still binds to `127.0.0.1` by default.

Example scan request:

```powershell
$body = @{
  text = 'contact=user@example.test'
  destination = 'external_llm'
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8765/scan/text -ContentType application/json -Body $body
```

## Security Notes

- Use synthetic data for tests and demonstrations.
- Do not pass the vault key as a CLI argument because process listings may expose
  it.
- Do not commit vault databases or keys.
- `/restore` intentionally returns authorized plaintext and must remain local.
- Protected text can still contain undetected sensitive data; CodeShield reduces
  leakage risk but does not prove that content is safe.
- Presidio, spaCy, and external scanner adapters remain optional future work.

## Verification

```powershell
cd engine
..\.venv\Scripts\python.exe -m pytest tests
```

Python 3.12 verification:

```powershell
docker compose build engine
docker compose run --rm engine pytest
```
