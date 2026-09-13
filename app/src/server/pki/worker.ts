import { PkiStore, WorkerStopped } from "./store.js";
import { PkiAdapter, PkiError } from "./adapter.js";
import { normalizeSerial } from "./certificate.js";
import { setTimeout as delay } from "node:timers/promises";
export interface WorkerInput {
  id: string;
  attempt: number;
  dbPath: string;
  address: string;
  token: string;
  namespace: string;
  skipTls: boolean;
  concurrency: number;
  requestsPerSecond: number;
}
function failure(error: unknown, phase: string) {
  if (error instanceof PkiError)
    return {
      category: [401, 403].includes(error.status)
        ? "permission"
        : error.status === 404
          ? "not_found"
          : error.status === 429
            ? "rate_limit"
            : phase,
      message: error.message,
    };
  return {
    category: phase,
    message:
      phase === "certificate_parse"
        ? "Certificate parsing or identity check failed"
        : "Collection operation failed",
  };
}
export async function collectPki(input: WorkerInput) {
  const store = new PkiStore(input.dbPath);
  if (!store.claim(input.id, input.attempt)) {
    store.close();
    return;
  }
  const heartbeat = setInterval(
    () => store.heartbeat(input.id, input.attempt),
    5000,
  );
  let lastRequest = 0;
  const beforeRequest = async () => {
    store.assertWorker();
    const now = Date.now();
    lastRequest = Math.max(now, lastRequest) + 1000 / input.requestsPerSecond;
    await delay(Math.max(0, lastRequest - now));
    store.assertWorker();
  };
  const adapter = new PkiAdapter(
    input.address,
    input.token,
    input.namespace,
    input.skipTls,
    beforeRequest,
  );
  const request = async <T>(fn: () => Promise<T>): Promise<T> => {
    for (let retry = 0; ; retry++) {
      store.assertWorker();
      try {
        const result = await fn();
        store.assertWorker();
        return result;
      } catch (e) {
        if (
          e instanceof WorkerStopped ||
          retry >= 3 ||
          !(e instanceof PkiError) ||
          ![429, 502, 503, 504].includes(e.status)
        )
          throw e;
        await delay(Math.min(8000, 500 * 2 ** retry));
      }
    }
  };
  const sourceUpdate = (
    sourceId: string,
    values: Record<string, string | null>,
  ) =>
    store.transaction(() => {
      // Keys are internal call-site constants, never request fields.
      store.db
        .prepare(
          `UPDATE job_sources SET ${Object.keys(values)
            .map((key) => key + "=?")
            .join(",")} WHERE jobId=? AND sourceId=?`,
        )
        .run(...Object.values(values), input.id, sourceId);
    });
  try {
    const job = store.job(input.id)!;
    await request(() => adapter.verifyToken());
    const discovered = await request(() => adapter.discover());
    const available = await request(() => adapter.allowed(discovered));
    if (!job.sources.every((id) => available.some((s) => s.id === id)))
      throw new PkiError(403, "Source access or mount identity changed");
    let partial = false;
    for (const id of job.sources) {
      store.assertWorker();
      const source = available.find((s) => s.id === id)!;
      store.transaction(() => store.source(source));
      sourceUpdate(id, {
        status: "running",
        startedAt: new Date().toISOString(),
        finishedAt: null,
        error: null,
        errorCategory: null,
        revocationError: null,
      });
      let phase = "revocation_list";
      try {
        let revoked: string[] | null,
          revocationError: string | null = null;
        try {
          revoked = await request(() => adapter.serials(source, true));
        } catch (e) {
          if (e instanceof PkiError && [403, 404].includes(e.status)) {
            revoked = null;
            revocationError = e.message;
          } else throw e;
        }
        sourceUpdate(id, {
          revocationMode: revoked ? "bulk_list" : "certificate_metadata",
          revocationError,
        });
        phase = "certificate_list";
        const state = store.db
          .prepare(
            "SELECT listed FROM job_sources WHERE jobId=? AND sourceId=?",
          )
          .get(job.id, id)!;
        if (!state.listed) {
          const serials = await request(() => adapter.serials(source));
          store.enqueue(job.id, id, serials, revoked);
        }
        const revokedSet = revoked
          ? new Set(revoked.map(normalizeSerial))
          : null;
        // Refresh observations on resume, reusing cached DER when bulk status is available.
        store.transaction(() =>
          store.db
            .prepare(
              "UPDATE job_items SET state='pending' WHERE jobId=? AND sourceId=? AND state='done'",
            )
            .run(job.id, id),
        );
        phase = "certificate_read";
        for (;;) {
          store.assertWorker();
          await request(() => adapter.verifyToken());
          const stillAllowed = await request(() => adapter.allowed([source]));
          if (!stillAllowed.length)
            throw new PkiError(403, "Source access revoked");
          const batch = store.db
            .prepare(
              "SELECT serial FROM job_items WHERE jobId=? AND sourceId=? AND state='pending' LIMIT 100",
            )
            .all(job.id, id);
          if (!batch.length) break;
          let offset = 0,
            fatal: unknown;
          await Promise.all(
            Array.from(
              { length: Math.min(input.concurrency, batch.length) },
              async () => {
                while (offset < batch.length && !fatal) {
                  const raw = String(batch[offset++].serial);
                  let itemPhase = "certificate_read";
                  try {
                    store.assertWorker();
                    const normalized = normalizeSerial(raw);
                    const existing = store.db
                      .prepare(
                        "SELECT fingerprint FROM certificates WHERE sourceId=? AND serial=?",
                      )
                      .get(id, normalized);
                    const observation =
                      existing && revokedSet
                        ? {
                            pem: store.pem(String(existing.fingerprint))!,
                            revocation: "unknown" as const,
                          }
                        : await request(() => adapter.certificate(source, raw));
                    if (fatal) return;
                    itemPhase = "certificate_parse";
                    store.save(
                      id,
                      observation.pem,
                      revokedSet
                        ? revokedSet.has(normalized)
                          ? "revoked"
                          : "not_revoked"
                        : observation.revocation,
                      normalized,
                      () => {
                        store.db
                          .prepare(
                            "UPDATE job_items SET state='done',error=NULL,errorCategory=NULL WHERE jobId=? AND sourceId=? AND serial=?",
                          )
                          .run(job.id, id, raw);
                      },
                    );
                  } catch (e) {
                    if (
                      e instanceof WorkerStopped ||
                      (e instanceof PkiError && [401, 403].includes(e.status))
                    ) {
                      fatal = e;
                      return;
                    }
                    const error = failure(e, itemPhase);
                    try {
                      store.transaction(() =>
                        store.db
                          .prepare(
                            "UPDATE job_items SET state='failed',error=?,errorCategory=? WHERE jobId=? AND sourceId=? AND serial=?",
                          )
                          .run(error.message, error.category, job.id, id, raw),
                      );
                    } catch (stopped) {
                      fatal = stopped;
                      return;
                    }
                    partial = true;
                  }
                }
              },
            ),
          );
          if (fatal) throw fatal;
        }
        const failed = Number(
          store.db
            .prepare(
              "SELECT COUNT(*) AS n FROM job_items WHERE jobId=? AND sourceId=? AND state!='done'",
            )
            .get(job.id, id)!.n,
        );
        const unknown = Number(
          store.db
            .prepare(
              "SELECT COUNT(*) AS n FROM certificates WHERE sourceId=? AND revoked='unknown' AND lastSeen>=?",
            )
            .get(id, job.createdAt)!.n,
        );
        const coverage = failed
            ? "partial"
            : unknown
              ? "revocation_unknown"
              : "complete",
          now = new Date().toISOString();
        store.transaction(() => {
          store.db
            .prepare("UPDATE sources SET lastCollected=?,coverage=? WHERE id=?")
            .run(now, coverage, id);
          store.db
            .prepare(
              "UPDATE job_sources SET status=?,finishedAt=? WHERE jobId=? AND sourceId=?",
            )
            .run(coverage, now, job.id, id);
          if (!failed)
            store.db
              .prepare(
                "UPDATE certificates SET presence='not_observed' WHERE sourceId=? AND lastSeen<?",
              )
              .run(id, job.createdAt);
        });
        partial ||= failed > 0 || unknown > 0;
      } catch (e) {
        if (e instanceof WorkerStopped) throw e;
        const error = failure(e, phase);
        sourceUpdate(id, {
          status: "failed",
          finishedAt: new Date().toISOString(),
          error: error.message,
          errorCategory: error.category,
        });
        store.transaction(() =>
          store.db
            .prepare("UPDATE sources SET coverage='partial' WHERE id=?")
            .run(id),
        );
        if (e instanceof PkiError && [401, 403].includes(e.status)) throw e;
        partial = true;
      }
    }
    store.finish(
      input.id,
      input.attempt,
      partial ? "partial" : "completed",
      partial
        ? "Some records or revocation information could not be read"
        : null,
    );
  } catch (e) {
    store.finish(
      input.id,
      input.attempt,
      e instanceof WorkerStopped ||
        (e instanceof PkiError && [401, 403].includes(e.status))
        ? "paused"
        : "interrupted",
      e instanceof WorkerStopped
        ? null
        : e instanceof PkiError
          ? e.message
          : "Collection interrupted; resume with a valid Vault session",
    );
  } finally {
    clearInterval(heartbeat);
    store.close();
  }
}
if (process.send) {
  process.once("message", (input: WorkerInput) => {
    process.disconnect();
    void collectPki(input).catch(() => {
      process.exitCode = 1;
    });
  });
}
