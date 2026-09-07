# Phase 9 — Metadata-only management plane

## Outcome and boundary

CodeShield 0.9.0 adds an optional organizational management plane that runs
entirely on a reproducible local Supabase stack. The engine continues to scan,
classify, protect, pseudonymize, restore, and retain vault material locally.
The management boundary accepts only structured organizational metadata:
category/action counts, sensitivity, identifiers and versions, status/latency
buckets, HMAC event identifiers, and reviewed policy/profile documents.

Prompts, responses, source code, previews, raw findings, absolute paths,
credentials, pseudonyms, vault keys, payload/path HMACs, model output, and
arbitrary content fields are rejected before persistence. Phase 9 creates no
remote Supabase project and performs no deployment, publication, release,
telemetry, Realtime subscription, automatic policy pull, or automatic audit
upload.

## Local Supabase architecture

The pinned Supabase CLI version is `2.110.0`. `supabase/config.toml`, one
replayable migration, synthetic seed metadata, and pgTAP tests are committed.
The Data API exposes only the `api` schema. Authorization helpers and device
token hashes remain in the unexposed `private` schema.

All 18 business tables enable and force RLS. Default table, sequence, and
function privileges are revoked. Anonymous users have no business-data
access. Authenticated users receive only explicit table operations; the
service role alone can execute token-hash RPCs. Private-schema usage lets
authenticated calls resolve three allowlisted RLS helpers but grants no
private-table access.

Roles are read from active `api.memberships` rows on every decision:

- `administrator` manages membership, devices, destinations, mandatory
  policies, approvals, and immutable releases.
- `security_analyst` manages provider/profile and policy drafts and reviews
  aggregate audit, feedback, exceptions, and compliance metadata.
- `developer` reads released policy/profile metadata, manages an owned device,
  and submits safe aggregate audit/feedback metadata.

JWT custom metadata and user-editable Auth metadata never determine a role.
The pgTAP suite exercises all three roles in two organizations, cross-tenant
denial, grants, helper execution, revocation, immutable releases, monotonic
sequences, and prohibited JSON constraints.

## Management API and signed delivery

`apps/management-api` is a separate FastAPI application with:

- `GET /health`
- `GET /version`
- `POST /v1/device-tokens`
- `POST /v1/devices/{device_uuid}/revoke`
- `POST /v1/policy-bundles/releases`
- `GET /v1/policy-bundles/latest`
- `POST /v1/audit-events/batch`

Dashboard calls validate the Supabase user and membership row. Device tokens
are displayed once, stored only as peppered SHA-256 HMACs, and compared in
constant time. The service credential, token pepper, and Ed25519 private key
are server-only environment values. The app uses exact CORS origins, bounded
bodies/batches, no redirects, `trust_env=false`, fixed error envelopes,
no-store responses, and no access logging.

Policy bundles use canonical compact JSON and Ed25519 signatures. They contain
organization, monotonic release sequence, policy/profile/destination versions,
minimum engine version, issue/expiry times, and key ID. Releases are immutable.
Clients reject unknown keys, bad signatures, organization mismatch, future or
expired validity, engine incompatibility, and sequence downgrade.

## Engine interoperability

The management CLI is explicit:

```text
codeshield management validate-config CONFIG
codeshield management status
codeshield management pull-policy
codeshield management upload-audit --dry-run
codeshield management upload-audit --confirm
```

Configuration must be an absolute, regular, non-link YAML file and an exact
loopback HTTP origin. It contains no token. The device credential comes only
from `CODESHIELD_MANAGEMENT_TOKEN`. Verified bundles are written with
same-directory atomic replacement and rollback protection. Offline validity is
at most seven days. Once enrolled, missing, expired, tampered, downgraded, or
otherwise invalid managed policy fails closed.

Policy precedence is:

1. managed mandatory rules;
2. managed non-mandatory rules;
3. repository rules;
4. local exceptions.

A local exception cannot override a managed mandatory rule. Audit dry-run and
confirmed upload use the same `SafeAuditEvent` contract; only an explicit
`--confirm` opens a management connection.

## Dashboard

`apps/dashboard` is a private Next.js `16.2.12` App Router workspace using
React `19.2.8`, Tailwind `4.3.3`, Recharts `3.10.1`, Supabase JS `2.111.0`,
and `@supabase/ssr` `0.12.4`. Dependencies are exactly pinned and npm audit is
clean through exact PostCSS and Sharp security overrides.

Supabase Auth is invite-only: global self-registration is disabled while the
email provider remains available for administrator-created users. Cookie SSR
calls `getUser` on the server. Ordinary reads/writes go directly to the `api`
schema so RLS remains authoritative; signing, token issuance, revocation, and
audit ingestion go to the management API. Every page uses allowlisted columns
and runtime rejects prohibited field names, unsafe values, unknown fields, and
malformed aggregate objects.

Pages cover overview, aggregate findings, audit metadata, providers,
destinations, policy versions/releases, devices, attestations, safe feedback,
exceptions, component versions, members, and settings. Policy draft updates
compare revisions and fail on stale writes. Device credentials are rendered
only in the one-time action response. Responses and authentication pages are
private/no-store and include CSP, frame, MIME, referrer, and permissions
headers.

## Evaluation and measured performance

The versioned Phase 9 suite retains Phase 8 data and adds 12 deterministic
management cases. It actually signs and verifies bundles and submits metadata
to the shared strict ingestion model.

Windows Python 3.12 measurements on 2026-07-30:

- signature/tamper/expiry/rollback rejection recall: `1.0`;
- prohibited-content ingestion rejection recall: `1.0`;
- management negative-case false-positive rate: `0.0`;
- overall exact-F2 delta from Phase 8: `0.0`;
- core 100 KB warm p95: `125.49 ms` (`250 ms` budget);
- enhanced 100 KB warm p95: `830.33 ms` (`3000 ms` budget);
- 137,018-byte signed-policy pull, verification, and atomic activation warm
  p95: `60.9 ms` (`750 ms` budget).

These are local synthetic engineering measurements, not production latency or
real-world detection claims.

## Verification and security review

The local verification includes full Python and Node regression suites,
dashboard unit/browser tests, two contract checks, repeated hardened builds,
package/VSIX inspection, npm audit, Phase 6/8/9 evaluations, engine/editor/proxy
latency gates, provider evidence checks, secret-free fixtures, staged
CodeShield, Gitleaks, migration replay, database lint, 39 pgTAP assertions,
and a real local Auth/RLS/API/policy/audit/revocation integration.

Review conclusions:

- No scanning or content-processing API was moved into the management plane.
- RLS membership rows, not stale JWT role claims, are authoritative.
- Signing and service credentials cannot enter browser-public configuration.
- Device credentials are environment-only on clients and hashed server-side.
- Bundle activation and policy precedence fail closed.
- Audit upload excludes local correlation/path HMACs and per-finding records.
- Shell-free subprocess/build behavior and all Phase 8 proxy constraints remain
  unchanged.

Changed areas are `supabase/`, `apps/management-api/`, `apps/dashboard/`,
`engine/codeshield/management/`, management contracts in `packages/shared/`,
the Phase 9 evaluation/reports, hardened build orchestration, CI, integration
examples, and documentation.

Limitations: the stack is local development infrastructure, dashboard testing
uses synthetic organizations, policy pulls and audit uploads are manual, and
there is no hosted availability, backup/restore runbook, enterprise identity
provider, Realtime delivery, or deployment configuration. Those require a
separate explicit authorization and security review.
