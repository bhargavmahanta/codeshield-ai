# CodeShield private dashboard

The Phase 9 dashboard is a private Next.js App Router workspace for
organizational metadata only. It uses cookie-based Supabase SSR and direct
`api` schema access under RLS for ordinary reads and writes. The management API
is called only for device token issuance/revocation and signed policy releases.

Required local runtime variables:

- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`
- `CODESHIELD_MANAGEMENT_API_URL` (server-only)

No service-role credential, signing key, device token, raw finding, path,
prompt, response, preview, pseudonym, or vault value is accepted by client-side
configuration.
