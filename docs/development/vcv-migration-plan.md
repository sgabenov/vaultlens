# VCV to VaultLens migration plan

Updated: 2026-09-13. Status: initial catalog implemented; stabilization pending.

This is the working backlog for the migration. Use task IDs when discussing work,
record evidence when closing tasks, and keep this document current in the same
commit as a completed milestone. The architecture and API behavior are described
in [Certificate catalog](certificate-catalog.md).

## Objective and fixed decisions

Port the useful certificate-inventory model from Vault Certificate Viewer into a
native VaultLens module. Implement it using VaultLens architecture and session
handling rather than embedding VCV or copying its separate application stack.

- Shared catalog of authorized mounts. Every request checks the current Vault
  session and LIST capability on `<mount>/certs`, including counts, details and export.
- Collection uses the initiating user's token. No system-token fallback for PKI.
  The background-services AppRole belongs to the existing VaultLens services.
- Search selects fields and operators explicitly; AND/OR, source scope, certificate
  usage type, validity and revocation remain independently selectable.
- SQLite/WAL, a durable separate worker, bounded concurrency/rate, resumable work,
  explicit collection coverage, server-side pagination and streaming export.
- Preserve public certificate provenance. Unknown role attribution remains unknown;
  incomplete collection never proves deletion or absence of issuance.
- Keep VaultLens navigation, branding and authentication. Do not port VCV language
  selection, independent themes or its separate login/configuration UI.
- Ignore VCV Markdown instructions for agents. Use chat requirements and source
  behavior as input to the migration.
- Publish this feature to `origin` only. No upstream push or upstream PR is authorized.

## Branches and runtime

| Purpose | Branch / location |
| --- | --- |
| Stable release line | `main` |
| Integration of local modules | `develop` |
| Certificate module development | `feature/vault-certificate-viewer` |
| Feature checkout | `/Users/gabenov.s/git/github/sgabenov/vaultlens-vcv` |
| Integration checkout | `/Users/gabenov.s/git/github/sgabenov/vaultlens` |
| Reference source | `/Users/gabenov.s/git/github/vcv` |
| Feature preview | `http://127.0.0.1:18303/certificates` |
| Existing local integration service | `http://127.0.0.1:18302/` |
| Feature configuration and data | `/Users/gabenov.s/Documents/Projects/VaultLens/pki-preview/` |

Delivery flow: feature commits -> `origin/feature/vault-certificate-viewer` ->
validated merge into `develop` -> rebuild/restart the common local service ->
separate readiness decision for `main`. A Git push does not update a running app.
Never commit Vault credentials, runtime databases or private keys.

## Scope mapping

| VCV capability | VaultLens decision | Tracking |
| --- | --- | --- |
| PKI source selection | Native authorized-mount selector; improve persistence and identity UX | M1, SRC-01..03 |
| Certificate collection/cache | Separate SQLite catalog and durable worker | M1, JOB-01..04 |
| Generic certificate search | Explicit field/operator conditions with AND/OR | M1, UX-01..03 |
| Certificate types and expiry | Separate usage type, validity and revocation dimensions | M1, UX-02 |
| Certificate details and download | Public PEM and verified signing CA, explicit missing evidence | M1, DATA-02 |
| Export | Streaming filtered NDJSON first; other formats are optional | M1, DATA-03 |
| Global statistics and metrics | Deferred until source access and coverage are reliable | EXT-03 |
| Role attribution | Only with verifiable issuance evidence | EXT-02 |
| Multiple Vault connections | First version uses configured Vault; connection manager is a separate decision | EXT-01 |
| Language, theme and login | Use existing VaultLens behavior | Excluded |
| Lifecycle mutations | Separate workflows, outside read-only catalog acceptance | EXT-04 |

## M1 — Initial working catalog (complete)

- [x] BASE-01: Native Certificates workspace, source selection and distinct menu icons.
- [x] BASE-02: Shared catalog with live source authorization for every API operation.
- [x] BASE-03: Field-specific search, AND/OR, usage/validity/revocation filters,
  counts and cursor pagination.
- [x] BASE-04: Public X.509 parsing, normalized identifiers, indexed metadata/SANs
  and deduplicated DER storage.
- [x] BASE-05: Separate worker, persisted queue, bounded requests, pause/resume,
  retry behavior and interrupted-job recovery.
- [x] BASE-06: Coverage labels, retained unobserved records, unknown provenance,
  revocation-time fallback and signing-CA verification.
- [x] BASE-07: Certificate details, PEM download and streaming NDJSON export.
- [x] BASE-08: Isolated feature runtime; background-services AppRole configured
  and persistence checked after restart; setup redirects to the application.

Evidence: `bdd951b` (catalog), `38398f9` (icons), `2dad155` (AppRole startup).
Recorded checks: production build and PKI tests passed; live collection processed
2,409 certificates across seven mounts without read failures; restricted-token
source isolation and revoked-session rejection passed; browser search/details and
export were exercised. These are initial checks, not acceptance of the pending
failure/recovery matrix below.

## M2 — Sources and collection visibility (next)

- [ ] SRC-01: Define and implement persistence of selected sources, distinct from
  mount authorization and retention. Document whether a saved selection belongs
  to the browser/user or deployment; do not silently introduce a global setting.
- [ ] SRC-02: Show source identity, namespace, last successful observation and
  readable coverage explanations. Represent inaccessible/remounted/recreated
  sources without exposing cached metadata to unauthorized sessions.
- [ ] SRC-03: Exercise remount, disable/recreate and permission changes against
  source selection and cached IDs. Old identifiers must not authorize a new mount.
- [ ] JOB-01: Add per-source progress, failure categories and bounded error details
  to the job API/UI; distinguish certificate-read and revocation-evidence failures.
- [ ] JOB-02: Make pause/resume/retry behavior clear, including rereads needed for
  revocation refresh. Show interrupted jobs and the need for a current session.
- [ ] JOB-03: Surface single-active-job conflicts and refresh source coverage/counts
  consistently after completion, pause or failure.
- [ ] JOB-04: Expose validated concurrency/rate limits in deployment configuration;
  document defaults, bounds, response-size limits and retry/backoff behavior.

Acceptance: a user can identify exactly which sources were scanned, which records
failed, why coverage is incomplete and what Resume will do. Access changes are
reflected without leaking cached records. No full serial list is sent to the browser.

## M3 — Search and certificate data quality

- [ ] UX-01: Check shared-query restoration, malformed URLs, source changes,
  clear/search behavior, paging and stale in-flight responses as one user flow.
- [ ] UX-02: Validate CN vs each SAN type; exact/prefix/contains matching; serial and
  fingerprint formatting; date boundaries; CA/client/server/both/unknown usage;
  independent validity and revocation filters. Explain that usage is not a Vault role.
- [ ] UX-03: Finish native layout/accessibility for narrow screens, keyboard use,
  loading/empty/error states and visible source scope. Record browser acceptance.
- [ ] DATA-01: Define and implement certificate-identity conflict handling. Never
  silently replace evidence when a source/serial resolves to another fingerprint.
- [ ] DATA-02: Exercise multiple issuers, issuer rotation, missing issuer access,
  unsupported endpoints and missing revocation metadata. Distinguish observed time
  from current validity; issuer verification is not a complete trust-chain verdict.
- [ ] DATA-03: Make export consistency explicit in UI; test interrupted downloads,
  permission loss and concurrent collection. Choose and document whether to retain
  live traversal or add a stable snapshot mode before declaring export complete.

Acceptance: displayed filters describe the actual query; page boundaries do not
skip or duplicate records in a stable catalog; details and exports expose evidence
and uncertainty rather than guessing. Unauthorized scope cannot affect results/counts.

## M4 — Reliability, storage and scale

- [ ] REL-01: Run a focused recovery matrix: HTTP-server restart during collection,
  worker termination, expired heartbeat, pause/resume, revoked token, 403/429/5xx,
  inaccessible certificate, malformed PEM and partial listing/read failures.
- [ ] REL-02: Harden ownership of active jobs so a stale worker cannot continue
  writing after another worker has taken over. Verify concurrent start/resume races.
- [ ] REL-03: Complete meaningful automated coverage for authorization on details,
  jobs and export, access changes during export, and worker recovery. Avoid tests
  that only mirror rendering or implementation details.
- [ ] DB-01: Define schema-upgrade handling and a consistent SQLite backup/restore
  procedure. Document WAL sidecars, file permissions and recovery after failed writes.
- [ ] DB-02: Define collection-history and local-retention policy before implementing
  cleanup. Separate pruning job history, deleting local records and Vault tidy.
- [ ] PERF-01: Repeat scale measurements with realistic DER sizes, SAN distributions,
  cold/warm cache, concurrent reads/collection and representative search predicates.
  Record latency, RSS, disk size and collection throughput with a reproducible script.
- [ ] PERF-02: Investigate slow query plans and long synchronous database work;
  establish acceptable local responsiveness and resource budgets from measurements.

Acceptance: progress survives supported failures, only the authorized active worker
writes, backups restore successfully, and measured limits are documented. One million
records is a benchmark target, not an unconditional production capacity promise.
The existing synthetic run (2–333 ms per tested query) is preliminary evidence only.

## M5 — Integrate the read-only module into the common local build

Depends on M2–M4 acceptance, or an explicit narrower pilot scope recorded here.

- [ ] INT-01: Review the completed checklist and explicitly list any accepted gaps.
  Resolve or separately track the existing client-wide type-check failures outside
  PKI; do not describe a successful bundle build as a clean global type check.
- [ ] INT-02: Merge the reviewed feature into `develop`, resolving conflicts with
  the other local modules. Keep the feature history and migration documentation.
- [ ] INT-03: Prepare the integration runtime and database placement, back up current
  configuration, and record the previous executable/build and rollback command.
- [ ] INT-04: Build and restart the service on `18302`; verify branch/build identity,
  AppRole startup, navigation, authorized collection/search/export and audit-module
  navigation. Avoid duplicate collection workers or competing scheduled jobs.
- [ ] INT-05: Publish the integration result to `origin`, update this plan and record
  which service is the default. Decide whether the `18303` preview should stay running.

Acceptance: the user sees the same validated PKI module at `18302`, runtime data
remains outside Git, existing modules work, and the previous build can be restored.
Promotion to `main` is a separate release decision. Upstream delivery remains excluded.

## Later extensions — proposed, not prerequisites for the catalog

These items need a concrete scope decision before implementation. Do not silently
expand the read-only migration to include all of them.

- [ ] EXT-01: Multiple Vault connections and namespace-aware login/selection; define
  connection ownership, credential lifecycle and cross-source authorization first.
- [ ] EXT-02: Issuance provenance from audit or another verified source, including
  unknown/conflicting role evidence and retention boundaries.
- [ ] EXT-03: Coverage-aware expiry/usage analytics and optional notifications/metrics.
  Define thresholds and destination requirements before adding integrations.
- [ ] EXT-04: PKI role/issuer configuration and lifecycle workflows. Treat single/bulk
  revocation, Vault tidy and local catalog deletion as separate operations with
  explicit preview, permissions and readback verification.
- [ ] EXT-05: Additional export formats, saved searches and richer certificate-chain
  visualization if they improve the agreed workflows.

## How to resume and update this plan

Start with **SRC-02 and JOB-01**: source coverage and per-source job diagnostics.
They make the current collection behavior reviewable before adding more features.
Then complete the remaining M2 tasks, followed by M3, M4 and M5.

For each task, record:

```text
Task ID:
Status: pending | in progress | blocked | done
Scope / decision:
Implementation commit:
Verification evidence:
Known gaps / next action:
```

Mark a checkbox only after its acceptance evidence exists. If a task is blocked,
record the missing decision or external condition rather than silently removing it.
Update the date and the next-task pointer when a milestone changes. Keep observations
from the real Vault separate from synthetic fixtures and performance experiments.

## Progress log

| Date | Work | Evidence / next action |
| --- | --- | --- |
| 2026-09-13 | Initial catalog implemented and published to origin | `bdd951b`; M1 complete, stabilization remains |
| 2026-09-13 | Distinct certificate/audit icons | `38398f9`; browser checked at 18303 |
| 2026-09-13 | Background AppRole setup and startup fix | `2dad155`; configured status and healthy check after restart |
| 2026-09-13 | Migration backlog recorded | Next: SRC-02 and JOB-01 |
