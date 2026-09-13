// Run after build:server: node scripts/benchmark-pki.mjs PUBLIC_SAMPLE_DB NEW_BENCH_DB [COUNT]
// Synthetic metadata and unique padded DER-sized payloads measure storage/query cost, not X.509 validation.
import { DatabaseSync } from "node:sqlite";
import { PkiStore } from "../dist/server/pki/store.js";
import { existsSync, statSync } from "node:fs";
import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
const [samplePath, path, n = "1000000"] = process.argv.slice(2),
  count = Number(n);
if (
  !samplePath ||
  !path ||
  existsSync(path) ||
  !Number.isSafeInteger(count) ||
  count < 100
)
  throw Error("Provide sample DB, unused destination and count >=100");
const sample = new DatabaseSync(samplePath, { readOnly: true });
const der = Buffer.from(
  sample.prepare("SELECT der FROM blobs LIMIT 1").get().der,
);
sample.close();
let store = new PkiStore(path);
for (let i = 0; i < 10; i++)
  store.source({
    id: "source-" + i,
    cluster: "benchmark",
    namespace: "",
    accessor: "accessor-" + i,
    path: "pki-" + i,
    description: "Synthetic benchmark",
    coverage: "complete",
    lastCollected: new Date().toISOString(),
  });
const blob = store.db.prepare("INSERT INTO blobs VALUES (?,?)");
const insert = store.db.prepare(
  `INSERT INTO certificates(sourceId,serial,fingerprint,cn,subject,issuer,notBefore,notAfter,algorithm,keySize,curve,type,revoked,firstSeen,lastSeen,eku) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
);
const san = store.db.prepare("INSERT INTO sans VALUES(?,?,?)");
const now = Date.now(),
  start = performance.now();
for (let offset = 0; offset < count; offset += 1000)
  store.transaction(() => {
    for (let i = offset; i < Math.min(offset + 1000, count); i++) {
      const fp = i.toString(16).padStart(64, "0"),
        cn = `host-${i}.service-${i % 100}.test`;
      const payload = Buffer.alloc(der.length + (i % 3) * 256);
      der.copy(payload);
      payload.writeUInt32BE(i, 0);
      blob.run(fp, payload);
      const id = insert.run(
        "source-" + (i % 10),
        i.toString(16),
        fp,
        cn,
        "CN=" + cn,
        "CN=CA-" + (i % 10),
        now - 86400000,
        now + ((i % 366) - 30) * 86400000,
        "rsa",
        2048,
        "",
        ["server", "client", "both", "ca", "unknown"][i % 5],
        i % 31 === 0 ? "revoked" : "not_revoked",
        new Date(now).toISOString(),
        new Date(now).toISOString(),
        "[]",
      ).lastInsertRowid;
      san.run(id, "dns", cn);
      san.run(id, "dns", `service-${i % 100}.test`);
      san.run(
        id,
        "ip",
        `10.${i % 256}.${Math.floor(i / 256) % 256}.${Math.floor(i / 65536) % 256}`,
      );
      if (i % 5 === 0) san.run(id, "uri", "spiffe://test/service/" + (i % 100));
    }
  });
const insertMs = performance.now() - start;
store.db.exec("ANALYZE; PRAGMA wal_checkpoint(TRUNCATE)");
store.close();
const base = {
  sources: Array.from({ length: 10 }, (_, i) => "source-" + i),
  conditions: [],
  match: "all",
  sort: "notAfter",
  direction: "asc",
  limit: 50,
};
const cases = {
  all: {},
  cn: {
    conditions: [
      { field: "cn", operator: "equals", value: "host-501.service-1.test" },
    ],
  },
  sanExact: {
    conditions: [
      { field: "san_dns", operator: "equals", value: "service-1.test" },
    ],
  },
  sanPrefix: {
    conditions: [{ field: "san_dns", operator: "prefix", value: "service-1" }],
  },
  sanContains: {
    conditions: [
      { field: "san_dns", operator: "contains", value: "service-1" },
    ],
  },
  serial: {
    conditions: [{ field: "serial", operator: "equals", value: "1f5" }],
  },
  fingerprint: {
    conditions: [
      {
        field: "fingerprint",
        operator: "equals",
        value: (501).toString(16).padStart(64, "0"),
      },
    ],
  },
  expired: { validity: "expired" },
};
const results = {};
store = new PkiStore(path);
for (const [name, patch] of Object.entries(cases)) {
  const times = [];
  for (let i = 0; i < 6; i++) {
    const t = performance.now();
    store.query({ ...base, ...patch });
    times.push(performance.now() - t);
  }
  results[name] = { firstMs: times[0], warmMaxMs: Math.max(...times.slice(1)) };
}
const child = spawn(
  process.execPath,
  [
    "--input-type=module",
    "-e",
    `import {DatabaseSync} from 'node:sqlite';const db=new DatabaseSync(process.argv[1]);db.exec('PRAGMA busy_timeout=5000');const q=db.prepare('UPDATE certificates SET lastSeen=? WHERE id=?');for(let i=1;i<=1000;i++)q.run(new Date().toISOString(),i);db.close();`,
    path,
  ],
  { stdio: "ignore" },
);
const concurrent = [];
for (let i = 0; i < 5; i++) {
  const t = performance.now();
  store.query({ ...base, ...cases.sanPrefix });
  concurrent.push(performance.now() - t);
}
await new Promise((resolve, reject) => {
  child.on("exit", (code) =>
    code ? reject(Error("Concurrent writer failed")) : resolve(),
  );
  child.on("error", reject);
});
store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
store.close();
console.log(
  JSON.stringify(
    {
      count,
      derSampleBytes: der.length,
      syntheticPayloadBytes: [der.length, der.length + 512],
      diskBytes: statSync(path).size,
      rssBytes: process.memoryUsage().rss,
      insertMs,
      rowsPerSecond: count / (insertMs / 1000),
      results,
      concurrentReadMaxMs: Math.max(...concurrent),
      cacheNote:
        "Fresh SQLite connection then repeated queries; OS file cache is not flushed. Synthetic payloads are not valid certificates.",
    },
    null,
    2,
  ),
);
