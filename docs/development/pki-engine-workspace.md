# PKI engine workspace

The PKI workspace under Secrets Engines follows the seven-tab structure of Vault
UI 1.21.4. It is separate from the collected, indexed Certificates monitoring
catalog. The user expanded the initial read-only navigation request to include
main PKI lifecycle operations and supplied screenshots as the visual reference.

## User workflows

| Tab | Available workflows |
| --- | --- |
| Overview | Issuer and role counts, role selection for issuance, direct serial lookup, issuer lookup |
| Roles | List, view grouped settings, create, edit, delete, generate certificate, sign CSR |
| Issuers | List with default/root/intermediate metadata, certificate and chain, import bundle, generate root, generate intermediate CSR, import signed intermediate, sign intermediate, configure, revoke, delete |
| Keys | List and metadata, generate internal/exported key, import, rename, delete |
| Certificates | Stored serial list, live detail, validity/revocation, PEM download, revoke, links to monitoring and verified signing issuer |
| Tidy | Current/recent status, manual tidy, cancel, automatic tidy configuration |
| Configuration | Read/edit cluster URLs, ACME, global URLs, CRL/OCSP, default issuer; inspect mount tune; delete all issuers |

The layout uses a dedicated stylesheet: tab strip, action toolbar, two-column
Overview cards, compact object rows and property tables. It does not reuse the
monitoring search builder, collection controls or catalog stylesheet.

Advanced guided cross-signing across mounts, enterprise managed-key/KMS setup,
and full parity with every Vault version's UI are not claimed. Existing-key CSR,
intermediate signing and bundle import are available as separate operations.

## Routes and access

`/pki/engines/<mount>?tab=roles&ref=<name>` preserves mount/object navigation in
URLs. Certificate links use `certificate=<serial>` and may include `source` and
`record` to retain the monitoring observation. Nested mount paths are supported;
the route cannot shadow a KV mount named `pki` under `/secrets`.

`GET /api/pki-engine?mount=...&section=...` reads live objects using the current
user's Vault token and configured namespace. It never substitutes the background
system token. Role, issuer, key and direct certificate reads do not require
certificate LIST permission. Vault checks the actual endpoint permission. An
inaccessible count is shown as unavailable; configuration groups report their
own errors without hiding readable groups.

`POST /api/pki-engine` accepts an explicit operation registry, a current source
identity, a validated object reference and allowlisted typed fields. It is not an
arbitrary Vault proxy. The existing CSRF middleware protects mutations, and Vault
enforces write/delete capabilities. The API requires the mount name confirmation
for deletes, revocations and manual tidy. Forms expose that confirmation before
submission. Field names, types and defaults were verified against the local
Vault 1.21.4 OpenAPI schema; defaults are applied by Vault when fields are omitted.

Mount identity is checked before and after requests. This cannot make Vault mount
replacement and object operations atomic. If identity changes after a write, the
response explicitly warns that the operation may have completed; the client does
not automatically retry writes. Validation errors and Vault warnings are shown to
the caller. Failed reads cannot initialize an existing-object edit with empty
settings. Config sections save independently, avoiding misleading aggregate
success after a partial multi-endpoint update.

Issue/export responses can contain a private key. These responses have
`Cache-Control: no-store`, remain in component memory and provide explicit download.
They are not put into SQLite, browser storage or background jobs. Navigating away
clears the operation response. No database migration or new setup service is needed.

## Collection boundaries and evidence

Lists return 50 references per page. Vault still returns the full LIST response to
the backend; this is frontend paging, not Vault-side pagination. Concurrent
changes can move page boundaries. Issuer enrichment reads only the current page,
with at most four concurrent reads and a 2 MiB object limit. A failed individual
issuer read retains authorized LIST metadata. Certificate reads are limited to
1 MiB. Large inventory search remains in Certificates monitoring.

Engine certificate details distinguish a successful live read from a retained
monitoring observation. Cached data must pass catalog authorization and match the
current source identity and normalized serial. Failed live reads do not erase
observations. Fingerprint differences are displayed as conflicts rather than
silently overwriting the catalog. Issuer links require signature verification;
role `issuer_ref` is current configuration, not historical issuance evidence.

## Verification and delivery

- Fifteen PKI tests cover catalog behavior and engine authentication, endpoint
  isolation, scoped references, source replacement, typed operations and required
  destructive confirmation.
- Live API acceptance on two disposable local PKI mounts passed 28 scenarios:
  root generation, role CRUD, issue/sign/revoke, key import/generation/rename/delete,
  issuer configuration/import/revocation/delete, the complete intermediate CSR →
  sign → install flow, configuration groups, manual/automatic tidy and CSRF denial.
- Live evidence and the local acceptance script reside outside Git in
  `/Users/gabenov.s/Documents/Projects/VaultLens/integration-2026-09-13/`.
- Existing test mounts and the 2,409-record monitoring catalog were not mutated by
  the acceptance scenarios. Test-only mounts are removed after visual acceptance.
- Build passes. Full client type checking still reports ten pre-existing errors
  outside the PKI changes; the engine components add no type errors.

Development uses `feature/vault-certificate-viewer`, integration uses `develop`,
and publication is to origin only. The common local runtime is port 18302.
