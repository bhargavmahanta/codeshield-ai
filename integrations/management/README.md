# Local management integration

CodeShield 0.9.0 uses explicit, machine-local management configuration. Copy
`example.config.yaml` outside the repository, replace its identifiers and
public signing key, restrict it to the machine owner, and validate it:

```powershell
Copy-Item .\integrations\management\example.config.yaml C:\secure\codeshield-management.yaml
$env:CODESHIELD_MANAGEMENT_CONFIG = "C:\secure\codeshield-management.yaml"
$env:CODESHIELD_MANAGEMENT_TOKEN = "<one-time-issued-device-token>"
codeshield management validate-config $env:CODESHIELD_MANAGEMENT_CONFIG
codeshield management status
codeshield management pull-policy
```

The device token is accepted only through `CODESHIELD_MANAGEMENT_TOKEN`.
Configuration contains an exact loopback endpoint, organization/device IDs,
public verification keys, and offline-validity policy—never a credential or
private signing key. Pulls and audit uploads are manual; no polling,
background telemetry, Realtime subscription, or automatic upload occurs.

Preview aggregate audit metadata without sending it:

```powershell
codeshield management upload-audit --dry-run
codeshield management upload-audit --confirm
```

The confirmed form sends only bounded aggregate counts and HMAC event IDs.
Payload/path HMACs, per-finding records, prompts, responses, source, previews,
credentials, paths, pseudonyms, vault keys, and model output are excluded.
