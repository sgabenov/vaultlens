import { PkiStore } from "./store.js";
import { PkiAdapter, PkiError } from "./adapter.js";
import { normalizeSerial } from "./certificate.js";
import { setTimeout as delay } from "node:timers/promises";
export interface WorkerInput {
  id: string;
  dbPath: string;
  address: string;
  token: string;
  namespace: string;
  skipTls: boolean;
  concurrency: number;
  requestsPerSecond: number;
}
export async function collectPki(input: WorkerInput) {
  const store = new PkiStore(input.dbPath),
    adapter = new PkiAdapter(
      input.address,
      input.token,
      input.namespace,
      input.skipTls,
    );
  const heartbeat = setInterval(
    () =>
      store.db
        .prepare("UPDATE jobs SET updatedAt=? WHERE id=?")
        .run(new Date().toISOString(), input.id),
    5000,
  );
  let lastRequest = 0;
  // Reserve start times synchronously: one rate budget shared by all workers.
  const rate = async () => {
    const now = Date.now();
    lastRequest = Math.max(now, lastRequest) + 1000 / input.requestsPerSecond;
    await delay(Math.max(0, lastRequest - now));
  };
  const request = async <T>(fn: () => Promise<T>): Promise<T> => {
    for (let retry = 0; ; retry++) {
      await rate();
      try {
        return await fn();
      } catch (e) {
        if (
          retry >= 3 ||
          !(e instanceof PkiError) ||
          ![429, 502, 503, 504].includes(e.status)
        )
          throw e;
        await delay(Math.min(8000, 500 * 2 ** retry));
      }
    }
  };
  const paused = () =>
    ["pausing", "paused", "interrupted"].includes(
      String(
        store.db.prepare("SELECT status FROM jobs WHERE id=?").get(input.id)
          ?.status,
      ) ?? "interrupted",
    );
  try {
    if (paused()) {
      store.state(input.id, "paused");
      return;
    }
    store.state(input.id, "running");
    const job = store.job(input.id)!;
    await adapter.verifyToken();
    const available = await adapter.allowed(await adapter.discover());
    if (!job.sources.every((id) => available.some((s) => s.id === id)))
      throw new PkiError(403, "Source access or mount identity changed");
    let partial = false;
    for (const id of job.sources) {
      if (paused()) break;
      const source = available.find((s) => s.id === id)!;
      store.source(source);
      let state = store.db
        .prepare("SELECT * FROM job_sources WHERE jobId=? AND sourceId=?")
        .get(job.id, id)!;
      try {
        let revoked: string[] | null;
        try {
          revoked = await request(() => adapter.serials(source, true));
        } catch (e) {
          if (e instanceof PkiError && [403, 404].includes(e.status))
            revoked = null;
          else throw e;
        }
        if (!state.listed) {
          const serials = await request(() => adapter.serials(source));
          store.enqueue(job.id, id, serials, revoked);
        }
        state = store.db
          .prepare("SELECT * FROM job_sources WHERE jobId=? AND sourceId=?")
          .get(job.id, id)!;
        const revokedSet = revoked
          ? new Set(revoked.map(normalizeSerial))
          : null;
        // Refresh revocation observations on resume; cached public bodies remain reusable.
        if (state.listed)
          store.db
            .prepare(
              "UPDATE job_items SET state='pending' WHERE jobId=? AND sourceId=? AND state='done'",
            )
            .run(job.id, id);

        for (;;) {
          if (paused()) break;
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
                while (offset < batch.length && !fatal && !paused()) {
                  const raw = String(batch[offset++].serial);
                  try {
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
                    store.save(
                      id,
                      observation.pem,
                      revokedSet
                        ? revokedSet.has(normalized)
                          ? "revoked"
                          : "not_revoked"
                        : observation.revocation,
                      normalized,
                    );
                    store.db
                      .prepare(
                        "UPDATE job_items SET state='done',error=NULL WHERE jobId=? AND sourceId=? AND serial=?",
                      )
                      .run(job.id, id, raw);
                  } catch (e) {
                    if (
                      e instanceof PkiError &&
                      [401, 403].includes(e.status)
                    ) {
                      fatal = e;
                      return;
                    }
                    store.db
                      .prepare(
                        "UPDATE job_items SET state='failed',error=? WHERE jobId=? AND sourceId=? AND serial=?",
                      )
                      .run(
                        e instanceof PkiError
                          ? e.message
                          : "Certificate parsing or identity check failed",
                        job.id,
                        id,
                        raw,
                      );
                    partial = true;
                  }
                }
              },
            ),
          );
          if (fatal) throw fatal;
        }
        if (paused()) break;
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
        store.transaction(() => {
          store.db
            .prepare("UPDATE sources SET lastCollected=?,coverage=? WHERE id=?")
            .run(
              new Date().toISOString(),
              failed ? "partial" : unknown ? "revocation_unknown" : "complete",
              id,
            );
          if (!failed)
            store.db
              .prepare(
                "UPDATE certificates SET presence='not_observed' WHERE sourceId=? AND lastSeen<?",
              )
              .run(id, job.createdAt);
        });
        partial ||= failed > 0 || unknown > 0;
      } catch (e) {
        if (e instanceof PkiError && [401, 403].includes(e.status)) throw e;
        store.db
          .prepare(
            "UPDATE job_sources SET error=? WHERE jobId=? AND sourceId=?",
          )
          .run(
            e instanceof PkiError ? e.message : "Collection failed",
            job.id,
            id,
          );
        store.db
          .prepare("UPDATE sources SET coverage='partial' WHERE id=?")
          .run(id);
        partial = true;
      }
    }
    store.state(
      input.id,
      paused() ? "paused" : partial ? "partial" : "completed",
      partial
        ? "Some records or revocation information could not be read"
        : null,
    );
  } catch (e) {
    store.state(
      input.id,
      e instanceof PkiError && [401, 403].includes(e.status)
        ? "paused"
        : "interrupted",
      e instanceof PkiError
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
