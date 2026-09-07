# CodeShield management API

This separate FastAPI process handles only metadata operations that require
server-held material: one-time device tokens, device revocation, Ed25519 policy
release signing, verified bundle delivery, and bounded aggregate audit intake.
It does not accept source code, prompts, responses, previews, paths, raw
findings, pseudonyms, credentials, or vault data.

Runtime configuration is environment-only:

- `CODESHIELD_SUPABASE_URL` — exact local Supabase origin;
- `SUPABASE_SERVICE_ROLE_KEY` — server-only local service credential;
- `CODESHIELD_MANAGEMENT_SIGNING_KEY` — base64url raw Ed25519 private key;
- `CODESHIELD_MANAGEMENT_SIGNING_KEY_ID` — pinned public-key identifier;
- `CODESHIELD_MANAGEMENT_TOKEN_PEPPER` — server-only HMAC pepper;
- `CODESHIELD_MANAGEMENT_CORS_ORIGINS` — comma-separated exact dashboard origins.

Run locally after starting Supabase:

```powershell
.\.venv312\Scripts\python.exe -m pip install -e .\apps\management-api --no-deps
.\.venv312\Scripts\codeshield-management-api.exe
```

The service binds to `127.0.0.1:8766`, disables access logs, follows no
redirects, and uses `trust_env=false` for Supabase requests.
