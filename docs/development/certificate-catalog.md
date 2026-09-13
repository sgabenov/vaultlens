# Certificate catalog: first migration milestone

The `/certificates` workspace implements the read-only catalog model inspired by
Vault Certificate Viewer using VaultLens authentication, navigation and controls.
The implementation is independent TypeScript code; VCV agent instructions are not
part of this module's workflow.

## Included

- Explicit selection of discovered, authorized PKI mounts.
- Field/operator/value search with AND/OR conditions; CN, subject, serial,
  SHA-256 fingerprint, typed SANs, issuer DN, public key and dates.
- Separate certificate type, validity and revocation filters.
- Server-side counts and cursor pagination, up to 200 records per API page.
- Public certificate details, PEM download and cryptographically verified signer
  lookup (up to 100 issuers per interactive request).
- Streaming NDJSON export, including source coverage and observation timestamps.
- Durable collection jobs with pause, resume, partial results and recovery.

## Access contract

This is a **shared catalog of authorized mounts**, not a per-session cache.
Every API request validates the current Vault token, discovers the current mount
identity, and checks `list` capability on `<mount>/certs`. That capability grants
access to all cached public certificates for that mount, including PEM and counts,
even if the current token cannot read individual certificates directly from Vault.
This is an application authorization contract, not an emulation of per-serial Vault
ACLs. Do not deploy this contract where individual certificate bodies must have
stricter visibility than the mount's serial list.

Queries reject any unauthorized selected source. Details return 404 for hidden
records. Jobs are visible only when every included source is authorized. Exports
recheck live authorization between pages. No system-token fallback is used.

Collection uses the initiating user's token and therefore also requires read
access to `<mount>/cert/*`. Discovery uses `sys/mounts`, falling back to
`sys/internal/ui/mounts` when denied. Standard default-policy access to
`auth/token/lookup-self` and `sys/capabilities-self` is required. Issuer lookup
additionally uses `<mount>/issuers` and `<mount>/issuer/*` where available.

## Components and storage

```text
VaultLens session -> /api/pki -> live Vault identity + source authorization
                            -> parameterized SQLite query -> bounded page
                            -> collection job -> detached worker -> Vault
                                                  |                |
                                                  +---- SQLite <---+
```

- `app/src/server/pki/adapter.ts`: Vault requests with bounded responses/timeouts.
- `certificate.ts`: public X.509 parsing, canonical serials and fingerprints.
- `store.ts`: versioned SQLite schema, WAL, transactions and cursor queries.
- `query.ts`: allowlisted fields/operators and parameterized predicates.
- `worker.ts`: durable queue, four concurrent readers and a 20 request/s budget.
- `runtime.ts`: worker process startup with token passed through IPC only.
- `app/src/server/routes/pki.ts`: authorization on every operation.
- `app/src/client/pages/CertificatesPage.tsx`: native workspace and streamed export.

Source identity is `(Vault cluster ID, namespace, mount accessor)`. Remounting
updates the displayed path; disabling and recreating a mount produces a new
identity. Public DER blobs are deduplicated by SHA-256; normalized metadata and
typed SANs are separate indexed tables. Jobs persist source scopes, listed serials,
progress and sanitized errors. Tokens and private keys are never stored in this
catalog. The database is mode 0600, its new parent directory mode 0700.

Only one collection may be active per database. Serial-list insertion commits in
batches of 1,000; certificate writes use short transactions. Vault LIST itself
returns the entire serial list: this remains a memory/response-size limit (128 MiB).
Only one host may use this SQLite deployment. The worker survives HTTP-server
restart; an expired 120-second heartbeat marks a job interrupted on the next jobs
request. Resume requires a new valid session. There is no unattended token renewal.

When the revoked-serial endpoint is available, existing DER can be reused. When
that endpoint is denied or unavailable, the worker reads each certificate's
`revocation_time`; absent revocation evidence remains `unknown`. Resuming in this
fallback mode rereads completed entries to refresh revocation observations.

Coverage describes stored certificates visible during a collection, not every
certificate ever issued. `no_store`, expired retention, tidy, concurrent issuance
and access failures limit that evidence. Previously observed records are retained;
`not_observed` does not mean revoked or deleted. Role attribution remains unknown
without issuance evidence. Matching EKUs describe certificate usage, not Vault roles.

## Configuration and local preview

Use Node >= 22.13 and run from `app/`:

```sh
npm ci
npm run build
VAULT_ADDR=http://127.0.0.1:18200 \
HOST=127.0.0.1 PORT=18303 NODE_ENV=production \
VAULTLENS_CONFIG_PATH=/absolute/runtime/config.json \
VAULTLENS_PKI_DB_PATH=/absolute/runtime/certificates.sqlite \
node dist/server/server.js
```

`VAULTLENS_PKI_NAMESPACE` optionally binds this module to a namespace (empty by
default). The first milestone uses the configured Vault address and one namespace;
there is no cross-cluster connection manager yet. VaultLens login must obtain a
session valid in that namespace. The existing login flow can redirect to background
service setup; navigate directly to `/certificates` to use this module without a
system token.

Local feature preview: `http://127.0.0.1:18303/certificates`. Runtime files live in
`/Users/gabenov.s/Documents/Projects/VaultLens/pki-preview/`, outside Git. The stable
local app on port 18302 remains separate.

## Validation and remaining work

Run `npm run test:pki` for temporary SQLite/X.509 tests and a local fake Vault test.
Tests cover source isolation with OR, SAN-specific matching, wildcard escaping,
keyset pagination, rejected cursors, malformed identifiers, serial identity checks,
unknown revocation, persisted progress and authorization loss.

Live lab checks cover seven mounts / 2,409 certificates, shared access using a
restricted LIST-only token, rejection of unrelated mounts, token revocation,
field search, signing-CA verification and browser streaming download.

A metadata-only benchmark with 1,000,000 synthetic records and one DNS SAN each
measured count + first page at 20 ms, exact CN at 62 ms, CN prefix at 2 ms, exact
DNS SAN at 333 ms and CN substring at 143 ms on the local machine. This was one
warm local run with synthetic values and a shared placeholder blob, not a Vault
collection, DER parsing, concurrency or capacity guarantee.

The production build and PKI tests pass. The repository-wide client type check
has existing failures outside this module (auth-method config, graphs, secret
generator, analytics/dashboard, sharing/setup and Vault store).

Next milestones: connection/namespace UX, richer job coverage/error inspection,
collection history and retention, realistic cold-cache/concurrent load tests,
PKI roles/issuer configuration, issuance provenance and analytics. Bulk revoke and
tidy need separate controlled workflows. Localization and an independent login or
theme are intentionally excluded. Export is a live traversal rather than an atomic
snapshot: pause collection for a stable export; an interrupted export ends with an
error record and must be treated as incomplete.
