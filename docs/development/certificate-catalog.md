# Certificate catalog: first migration milestone

Implementation backlog and milestone status: [VCV migration plan](vcv-migration-plan.md).

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

The revoked-serial endpoint provides bulk status when available. When it is denied
or unavailable, the worker uses each certificate's `revocation_time`; absent evidence
remains `unknown`. Every collection/resume now rereads certificate bodies to detect
identity conflicts; DER storage is deduplicated, but it is not proof that Vault's
current response is unchanged.

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
VAULTLENS_CONFIG_PATH=/absolute/runtime/config \
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
local app on port 18302 remains separate. Background-services AppRole setup has
been completed for this preview and verified after restart. `VAULTLENS_CONFIG_PATH`
is a directory containing `config.ini`, not a JSON file.

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


## Backend stabilization: diagnostics and attempt ownership

The UI is unchanged in this iteration. `GET /api/pki/jobs/:id?errorLimit=20`
returns `job`, `sources`, `errors` and `errorsTruncated`. Each source includes its
mount/namespace, listing state, processing counts, start/finish times, status,
revocation-evidence mode, revocation fallback reason and categorized failure.
The error sample contains source ID, serial, category and a sanitized message.
`errorLimit` must be an integer from 1 to 100 (default 20). Missing jobs and jobs
containing any unauthorized source return 404. Every request still validates the
current Vault session and source capabilities. Job-list responses remain compatible.

Source status is per job, not a claim about every certificate issued by the mount.
A running source in a paused/interrupted job reports the job's current state.
Sources that were never reached remain pending. Historical jobs migrated from v1
report `legacy_unknown` for source status because phase/timing evidence was not
previously recorded. Revocation fallback is distinct from certificate-read failure:
a denied bulk endpoint can still result in complete coverage through certificate
metadata; absent metadata remains unknown.

Deployment controls (read at server startup):

| Variable | Default | Accepted integer range |
| --- | --- | --- |
| `VAULTLENS_PKI_CONCURRENCY` | 4 | 1–16 |
| `VAULTLENS_PKI_REQUESTS_PER_SECOND` | 20 | 1–100 |

Invalid settings fail startup rather than silently falling back. Each dispatch
records its limits in the job. A single rate budget covers every worker HTTP
request, including discovery, capability checks, certificate reads and retries.
429/502/503/504 responses retain up to three retries with exponential backoff;
requests retain the 30-second timeout and 128-MiB response limit. API browsing
requests are separate from this worker budget.

Each dispatch receives a monotonically increasing attempt number. Only its queued
attempt can claim a job. Every worker data write checks that attempt and running
status inside a `BEGIN IMMEDIATE` transaction. Certificate data and queue completion
commit together. Recovery/resume invalidates old attempts; stale responses,
heartbeats, completion and process-exit callbacks cannot overwrite the current job.
Pause blocks further data commits. An already in-flight Vault read may complete,
but cannot commit after pause or replacement. A queued job can pause immediately.
Worker exit is detected while its parent is alive; heartbeat recovery remains the
fallback after HTTP-server restart. Collection still requires a user session to resume.

### Schema v2 upgrade and rollback boundary

Stop the old HTTP service and ensure no legacy worker is active before upgrading.
Migration refuses queued/running/pausing v1 jobs; after a legacy crash, confirm the
worker is stopped before explicitly resolving the old job state. Back up the database
using SQLite's backup API, which includes committed WAL content; do not copy only
the main SQLite file from a live WAL database. Migration is transactional, retains
catalog records and job progress, and refuses newer unsupported schema versions.

The local upgrade retained all 2,409 catalog records. Its pre-upgrade backup is
`/Users/gabenov.s/Documents/Projects/VaultLens/pki-preview/backups/pki-before-schema-v2.sqlite`.
Do not run the old worker against the upgraded database. A rollback requires stopping
all writers and restoring the matching database backup together with the old build;
changes collected after the backup will not be present. Full restore and disk-error
acceptance remain DB-01 follow-up work.

Validation added: stale writer/heartbeat/completion rejection across SQLite
connections, delayed old Vault response after resume, single claimant, conflicting
resume, bounded/scoped diagnostics, v1 migration/active-worker rejection and invalid
limit settings. Live checks also cover HTTP restart during collection, pause/resume,
a restricted token's diagnostic access, 400 responses for invalid error limits,
and completion of 800 records with the original 2,409-record catalog preserved.
Runtime evidence is in `pki-preview/backend-check.json`; it contains no tokens.


## Source identity and certificate conflicts (schema v3)

The worker validates cluster/namespace/accessor identity, mount path and LIST access
before source listing, after listing, and before/after each certificate batch. Up to
100 certificate responses are staged without catalog writes, with a 1-MiB response
limit per certificate request. If the final identity/access check fails, the staged
batch is discarded and the job pauses with `source_changed` diagnostics. Existing
records are retained. Resume rediscovers the source path, so a remount preserving
identity can continue. A recreated mount or different cluster has a different source
ID and must be selected for a new job; old IDs do not grant access to the new source.
Namespace contributes to source identity even when mount accessors match.

These checks bound the observation window; Vault does not provide an atomic
transaction spanning mount discovery, certificate reads and SQLite commits. A change
after the final Vault check remains a race. Failed/partial observations must not be
interpreted as an authoritative issuance or deletion history.

All refreshes read certificate bodies even if a DER blob already exists and the bulk
revocation endpoint is available. This deliberately increases repeat-collection
requests in that case; the previous cache optimization could conceal a different
certificate returned under an existing serial.

For a different fingerprint at the same `(sourceId, serial)`, the original certificate
row, timestamps, SANs and revocation observation remain unchanged. The new public DER
is stored by fingerprint; `certificate_conflicts` records expected/observed
fingerprints, first/last observation times, occurrence count and latest job ID.
Repeated identical conflicts update the same evidence record. The affected queue item
fails with `identity_conflict` and the source remains partial. No automatic replacement
or conflict resolution is performed. A response with a mismatched serial is rejected
before persistence and does not become evidence for the requested serial.

The existing authenticated `GET /api/pki/certificates/:id` response now includes
`conflicts: { observations, truncated }`, limited to the most recent 20 distinct
conflicting fingerprint pairs. It exposes public fingerprint/timing evidence, not a
full additional PEM batch. The same source authorization required for the original
certificate applies. Conflicting DER remains available in storage for future explicit
review tooling; the UI is intentionally unchanged. Retention/cleanup remains DB-02.

Schema v3 adds the conflict table. Both v1 and v2 upgrades run transactionally and
require old workers to be stopped with no active queued/running/pausing jobs. Before
the local v2 -> v3 upgrade a consistent backup was saved at
`/Users/gabenov.s/Documents/Projects/VaultLens/pki-preview/backups/pki-before-schema-v3.sqlite`.
The existing 2,409 records were retained. Rollback requires the matching stopped
service/build and backup, not an old worker writing against the new schema.

Nine tests pass, including in-flight source changes, permission loss, remount resume,
namespace/source isolation, repeated identity conflict evidence and both migration
paths. These mutation scenarios use isolated fake Vault fixtures. Live validation
refreshed five existing certificates across two test mounts, verified the new detail
response, and retained all 2,409 catalog records. No live mount was replaced or
certificate reissued for these checks. Evidence: `pki-preview/identity-backend-check.json`.
