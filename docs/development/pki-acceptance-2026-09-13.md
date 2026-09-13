# Certificate catalog acceptance — 2026-09-13

## Automated and live checks

- Production bundle/server build passed. Fourteen PKI tests and 72 existing audit tests passed together (86 total).
- Tests cover authorization on records/jobs/export; concurrent export writes, access loss and abort; issuer rotation; source changes; malformed certificates; transient 429/503; 401/403; failed LIST; killed-worker recovery; stale ownership; migration; consistent backup/restore.
- Live pre-integration catalog: 2,409 public certificates across seven PKI mounts; three completed jobs. Backup/restore retained all records and jobs. Earlier live HTTP restart and pause/resume evidence is retained in runtime `backend-check.json`.
- Browser preview: CN and SAN search, next/previous pages, source selection, job diagnostics and 800 px layout exercised. Selection is browser-tab scoped. UI is a functional native baseline; further visual refinement remains possible.

## Reproducible performance measurement

Run from `app` after building the server:

```sh
node scripts/benchmark-pki.mjs PUBLIC_SAMPLE_DB NEW_BENCH_DB 1000000
node scripts/measure-pki.mjs EXISTING_BENCH_DB
```

This is synthetic metadata with unique 823–1,335 byte payloads derived from a public DER sample, 3–4 SAN entries per record and ten mounts. Payloads are intentionally not valid unique X.509 certificates. This measures database/query costs, not cryptographic parsing or Vault throughput. Fresh SQLite connections and repeated queries are measured; the OS file cache is not flushed.

| Dataset | Database size | Process RSS at completion | Synthetic insertion throughput |
| --- | ---: | ---: | ---: |
| 100,000 | 0.21 GiB | 96.3 MiB | 23,915 rows/s |
| 1,000,000 | 2.12 GiB | 92.8 MiB | 11,621 rows/s |

RSS is a completion sample, not a peak-memory guarantee. Million-record measurements:

| Query | First query, ms | Maximum repeated query, ms |
| --- | ---: | ---: |
| all | 46.06 | 19.57 |
| cn | 0.49 | 0.14 |
| sanExact | 565.73 | 22.48 |
| sanPrefix | 852.03 | 105.23 |
| sanContains | 1125.17 | 348.77 |
| expired | 30.19 | 3.26 |
| serial_equals (optimized) | 2.66 | 0.19 |
| serial_prefix (optimized) | 2.99 | 0.78 |
| fingerprint_equals (optimized) | 0.47 | 0.11 |
| fingerprint_prefix (optimized) | 0.09 | 0.09 |

Concurrent writer test: 1,000 metadata updates in a separate process, maximum measured SAN-prefix query 728.6 ms. WAL writes completed without a lock failure.

The first run exposed 3.5–7.5 second serial/fingerprint scans caused by NOCASE comparisons against binary indexes. Normalized hex equality and bounded binary prefix ranges now use the indexes. SAN predicates use an indexed ID subquery instead of a correlated per-row lookup.

Local budgets for this dataset: identifier lookup under 250 ms, repeated ordinary list/prefix queries under 1 second, substring search under 2 seconds. Measurements satisfy these budgets. SQLite queries remain synchronous; a broad substring query can temporarily delay other HTTP work. Export is capped at 120 seconds; collection stages at most 100 bounded certificate responses. A high-concurrency production deployment needs separate load qualification and may need a dedicated query worker. One million records is not an unconditional capacity promise.

## Explicit verification limits and existing issues

- No physical disk-full/hardware-failure injection and no forced OS-cache purge. Failed transactions, corrupt backups and exclusive destination creation are tested.
- Issuer, remount and recovery failure cases use isolated Vault protocol fixtures; live happy-path checks use the test Vault.
- The global client type check has ten existing errors outside PKI. Track separately: `AuthMethodConfig.tsx` field type; missing dagre declarations; `secretGenerator.ts` string-array argument and ES library target; Analytics/Dashboard/Vault store policy result types; ShareSecret configuration default; SystemTokenSetup promise and response types. PKI introduces no reported client type error.
- The 5.23 MB client bundle and existing Vite externalization/deprecation warnings remain. A bundle build is not a clean global type check.
- Additional connections, issuance provenance, analytics, lifecycle changes, main promotion and upstream publication are outside this catalog delivery.


## Integrated runtime

On `develop`, the common service at `18302` serves the matching client asset
`index-CW9CtLw_.js`. AppRole status and health checks passed after restart; `/setup`
redirected to `/app`. A fresh five-certificate collection completed with zero
failures. The full snapshot export contained 2,409 records and its completion
trailer. The existing Security Audit page showed 194 saved findings in 59 groups.
No new audit collection was started. The `18303` preview is stopped to avoid
competing background service instances. Rollback instructions are in the plan.
