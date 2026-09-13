import { DatabaseSync } from "node:sqlite";
import { mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import type {
  CertificateRecord,
  PkiJob,
  PkiQuery,
  PkiSource,
  Revocation,
} from "../../shared/pki.js";
import { parseCertificate } from "./certificate.js";
import { queryKey, whereQuery } from "./query.js";
import { PkiError } from "./adapter.js";
export class PkiStore {
  db: DatabaseSync;
  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    chmodSync(path, 0o600);
    this.db
      .exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS pki_schema(version INTEGER PRIMARY KEY);
      INSERT OR IGNORE INTO pki_schema VALUES(1);
      CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY, cluster TEXT NOT NULL, namespace TEXT NOT NULL, accessor TEXT NOT NULL, path TEXT NOT NULL, description TEXT NOT NULL, lastCollected TEXT, coverage TEXT NOT NULL DEFAULT 'not_collected');
      CREATE TABLE IF NOT EXISTS blobs(fingerprint TEXT PRIMARY KEY, der BLOB NOT NULL);
      CREATE TABLE IF NOT EXISTS certificates(id INTEGER PRIMARY KEY, sourceId TEXT NOT NULL REFERENCES sources(id), serial TEXT NOT NULL, fingerprint TEXT NOT NULL REFERENCES blobs(fingerprint), cn TEXT NOT NULL COLLATE NOCASE, subject TEXT NOT NULL, issuer TEXT NOT NULL, notBefore INTEGER NOT NULL, notAfter INTEGER NOT NULL, algorithm TEXT NOT NULL, keySize INTEGER NOT NULL, curve TEXT NOT NULL, type TEXT NOT NULL, revoked TEXT NOT NULL, revocationObservedAt TEXT, firstSeen TEXT NOT NULL, lastSeen TEXT NOT NULL, presence TEXT NOT NULL DEFAULT 'present', eku TEXT NOT NULL, UNIQUE(sourceId,serial));
      CREATE INDEX IF NOT EXISTS cert_source_expiry ON certificates(sourceId,notAfter,id);
      CREATE INDEX IF NOT EXISTS cert_source_cn ON certificates(sourceId,cn,id);
      CREATE INDEX IF NOT EXISTS cert_fingerprint ON certificates(fingerprint);
      CREATE TABLE IF NOT EXISTS sans(certificateId INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE, type TEXT NOT NULL, value TEXT NOT NULL COLLATE NOCASE, PRIMARY KEY(certificateId,type,value));
      CREATE INDEX IF NOT EXISTS san_lookup ON sans(type,value,certificateId);
      CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,sources TEXT NOT NULL,status TEXT NOT NULL,createdAt TEXT NOT NULL,updatedAt TEXT NOT NULL,error TEXT,pid INTEGER);
      CREATE UNIQUE INDEX IF NOT EXISTS single_active_job ON jobs((1)) WHERE status IN ('queued','running','pausing');
      CREATE TABLE IF NOT EXISTS job_sources(jobId TEXT NOT NULL REFERENCES jobs(id), sourceId TEXT NOT NULL REFERENCES sources(id), listed INTEGER NOT NULL DEFAULT 0, revoked TEXT, error TEXT, PRIMARY KEY(jobId,sourceId));
      CREATE TABLE IF NOT EXISTS job_items(jobId TEXT NOT NULL REFERENCES jobs(id),sourceId TEXT NOT NULL,serial TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',error TEXT,PRIMARY KEY(jobId,sourceId,serial));
      CREATE INDEX IF NOT EXISTS pending_items ON job_items(jobId,sourceId,state,serial);
    `);
  }
  close() {
    this.db.close();
  }
  transaction(fn: () => void) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      fn();
      this.db.exec("COMMIT");
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  source(source: PkiSource) {
    this.db
      .prepare(
        `INSERT INTO sources(id,cluster,namespace,accessor,path,description) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET path=excluded.path,description=excluded.description`,
      )
      .run(
        source.id,
        source.cluster,
        source.namespace,
        source.accessor,
        source.path,
        source.description,
      );
  }
  sources(ids: string[]): PkiSource[] {
    if (!ids.length) return [];
    return this.db
      .prepare(
        `SELECT s.*, (SELECT COUNT(*) FROM certificates c WHERE c.sourceId=s.id) AS certificateCount FROM sources s WHERE s.id IN (${ids.map(() => "?")}) ORDER BY s.path`,
      )
      .all(...ids) as unknown as PkiSource[];
  }
  save(
    sourceId: string,
    pem: string,
    revoked: Revocation,
    expectedSerial?: string,
  ) {
    const c = parseCertificate(pem),
      now = new Date().toISOString();
    if (expectedSerial !== undefined && c.serial !== expectedSerial)
      throw new Error("Returned certificate serial mismatch");
    this.transaction(() => {
      this.db
        .prepare("INSERT OR IGNORE INTO blobs VALUES(?,?)")
        .run(c.fingerprint, c.der);
      this.db
        .prepare(
          `INSERT INTO certificates(sourceId,serial,fingerprint,cn,subject,issuer,notBefore,notAfter,algorithm,keySize,curve,type,revoked,revocationObservedAt,firstSeen,lastSeen,eku) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(sourceId,serial) DO UPDATE SET fingerprint=excluded.fingerprint,cn=excluded.cn,subject=excluded.subject,issuer=excluded.issuer,notBefore=excluded.notBefore,notAfter=excluded.notAfter,algorithm=excluded.algorithm,keySize=excluded.keySize,curve=excluded.curve,type=excluded.type,revoked=excluded.revoked,revocationObservedAt=excluded.revocationObservedAt,lastSeen=excluded.lastSeen,presence='present',eku=excluded.eku`,
        )
        .run(
          sourceId,
          c.serial,
          c.fingerprint,
          c.cn,
          c.subject,
          c.issuer,
          c.notBefore,
          c.notAfter,
          c.algorithm,
          c.keySize,
          c.curve,
          c.type,
          revoked,
          revoked === "unknown" ? null : now,
          now,
          now,
          JSON.stringify(c.eku),
        );
      const id = this.db
        .prepare("SELECT id FROM certificates WHERE sourceId=? AND serial=?")
        .get(sourceId, c.serial)!.id;
      this.db.prepare("DELETE FROM sans WHERE certificateId=?").run(id);
      for (const san of c.sans)
        this.db
          .prepare("INSERT OR IGNORE INTO sans VALUES(?,?,?)")
          .run(id, san.type, san.value);
    });
    return c;
  }
  decorate(row: any): CertificateRecord {
    return {
      ...row,
      eku: JSON.parse(row.eku),
      role: null,
      sans: this.db
        .prepare("SELECT type,value FROM sans WHERE certificateId=?")
        .all(row.id),
    };
  }
  certificate(id: number, ids: string[]) {
    const row = this.db
      .prepare(
        "SELECT c.*,s.path AS sourcePath FROM certificates c JOIN sources s ON s.id=c.sourceId WHERE c.id=?",
      )
      .get(id);
    return row && ids.includes(String(row.sourceId))
      ? this.decorate(row)
      : null;
  }
  pem(fingerprint: string) {
    const row = this.db
      .prepare("SELECT der FROM blobs WHERE fingerprint=?")
      .get(fingerprint);
    if (!row) return null;
    const base64 = Buffer.from(row.der as Uint8Array).toString("base64");
    return (
      "-----BEGIN CERTIFICATE-----\n" +
      base64.match(/.{1,64}/g)!.join("\n") +
      "\n-----END CERTIFICATE-----\n"
    );
  }
  query(query: PkiQuery, count = true) {
    const base = whereQuery(query);
    let sql = base.sql;
    const params = [...base.params],
      key = queryKey(query);
    const total = count
      ? Number(
          this.db
            .prepare(
              "SELECT COUNT(*) AS n FROM certificates c WHERE " + base.sql,
            )
            .get(...base.params)!.n,
        )
      : 0;
    if (query.cursor) {
      try {
        const cursor = JSON.parse(
          Buffer.from(query.cursor, "base64url").toString(),
        );
        if (
          cursor.key !== key ||
          !Number.isSafeInteger(cursor.id) ||
          !["string", "number"].includes(typeof cursor.value)
        )
          throw new Error();
        const cmp = query.direction === "desc" ? "<" : ">";
        sql += ` AND (c.${query.sort} ${cmp} ? OR (c.${query.sort}=? AND c.id ${cmp} ?))`;
        params.push(cursor.value, cursor.value, cursor.id);
      } catch {
        throw new PkiError(400, "Cursor does not match the query");
      }
    }
    const rows = this.db
      .prepare(
        `SELECT c.*,s.path AS sourcePath FROM certificates c JOIN sources s ON s.id=c.sourceId WHERE ${sql} ORDER BY c.${query.sort} ${query.direction},c.id ${query.direction} LIMIT ?`,
      )
      .all(...params, query.limit + 1);
    const hasMore = rows.length > query.limit;
    const page = rows.slice(0, query.limit);
    const last = page.at(-1);
    return {
      certificates: page.map((r) => this.decorate(r)),
      total,
      nextCursor:
        hasMore && last
          ? Buffer.from(
              JSON.stringify({ key, id: last.id, value: last[query.sort] }),
            ).toString("base64url")
          : null,
    };
  }
  recover() {
    this.db
      .prepare(
        "UPDATE jobs SET status='interrupted',error='Worker heartbeat expired; resume with a valid Vault session' WHERE status IN ('queued','running','pausing') AND updatedAt<?",
      )
      .run(new Date(Date.now() - 120000).toISOString());
  }
  createJob(sources: string[]) {
    this.recover();
    const id = randomUUID(),
      now = new Date().toISOString();
    try {
      this.transaction(() => {
        this.db
          .prepare(
            "INSERT INTO jobs(id,sources,status,createdAt,updatedAt) VALUES(?,?,?,?,?)",
          )
          .run(id, JSON.stringify(sources), "queued", now, now);
        for (const s of sources)
          this.db
            .prepare("INSERT INTO job_sources(jobId,sourceId) VALUES(?,?)")
            .run(id, s);
      });
    } catch {
      throw new PkiError(409, "Another collection is active");
    }
    return id;
  }
  job(id: string): PkiJob | null {
    const row = this.db.prepare("SELECT * FROM jobs WHERE id=?").get(id);
    if (!row) return null;
    const counts = this.db
      .prepare(
        "SELECT COUNT(*) AS total,SUM(state='done') AS completed,SUM(state='failed') AS failed FROM job_items WHERE jobId=?",
      )
      .get(id)!;
    return {
      ...row,
      sources: JSON.parse(String(row.sources)),
      total: Number(counts.total),
      completed: Number(counts.completed ?? 0),
      failed: Number(counts.failed ?? 0),
    } as unknown as PkiJob;
  }
  jobs(ids: string[]): PkiJob[] {
    if (!ids.length) return [];
    return this.db
      .prepare("SELECT id FROM jobs ORDER BY createdAt DESC LIMIT 100")
      .all()
      .map((r) => this.job(String(r.id))!)
      .filter((j) => j.sources.every((s) => ids.includes(s)));
  }
  state(id: string, status: string, error: string | null = null) {
    this.db
      .prepare("UPDATE jobs SET status=?,error=?,updatedAt=? WHERE id=?")
      .run(status, error, new Date().toISOString(), id);
  }
  enqueue(
    job: string,
    source: string,
    serials: string[],
    revoked: string[] | null,
  ) {
    const stmt = this.db.prepare(
      "INSERT OR IGNORE INTO job_items(jobId,sourceId,serial) VALUES(?,?,?)",
    );
    for (let offset = 0; offset < serials.length; offset += 1000)
      this.transaction(() => {
        for (const serial of serials.slice(offset, offset + 1000))
          stmt.run(job, source, serial);
      });
    this.db
      .prepare(
        "UPDATE job_sources SET listed=1,revoked=?,error=NULL WHERE jobId=? AND sourceId=?",
      )
      .run(revoked ? JSON.stringify(revoked) : null, job, source);
  }
}
