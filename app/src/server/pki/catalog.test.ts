import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { PkiStore } from "./store.js";
import { PkiAdapter } from "./adapter.js";
import { validateQuery } from "./query.js";
import { parseCertificate, parseSans } from "./certificate.js";
import { collectPki } from "./worker.js";
import type { PkiSource } from "../../shared/pki.js";

test("catalog scopes OR searches, escapes wildcards, paginates and preserves identity", () => {
  const dir = mkdtempSync(join(tmpdir(), "pki-test-")),
    store = new PkiStore(join(dir, "catalog.sqlite"));
  try {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        join(dir, "key.pem"),
        "-out",
        join(dir, "cert.pem"),
        "-subj",
        "/CN=api.example.test",
        "-days",
        "1",
        "-addext",
        "subjectAltName=DNS:other.example.test,IP:127.0.0.1",
      ],
      { stdio: "ignore" },
    );
    const pem = readFileSync(join(dir, "cert.pem"), "utf8");
    for (const id of ["allowed", "hidden"])
      store.source({
        id,
        cluster: "test",
        namespace: "",
        accessor: id,
        path: id,
        description: "",
        coverage: "not_collected",
        lastCollected: null,
      });
    store.save("allowed", pem, "unknown");
    store.save("hidden", pem, "revoked");
    const query = (
      conditions: unknown[] = [],
      match = "all",
      sources = ["allowed"],
    ) => validateQuery({ sources, conditions, match, sort: "cn", limit: 1 });
    assert.equal(
      store.query(
        query(
          [
            { field: "cn", operator: "contains", value: "api" },
            { field: "cn", operator: "contains", value: "example" },
          ],
          "any",
        ),
      ).total,
      1,
    );
    assert.equal(
      store.query(
        query([{ field: "san_dns", operator: "contains", value: "api" }]),
      ).total,
      0,
    );
    assert.equal(
      store.query(
        query([
          { field: "san_dns", operator: "equals", value: "OTHER.example.test" },
        ]),
      ).total,
      1,
    );
    assert.equal(
      store.query(query([{ field: "cn", operator: "contains", value: "%" }]))
        .total,
      0,
    );
    assert.equal(store.query(query([], "all", [])).total, 0);
    const all = query([], "all", ["allowed", "hidden"]),
      first = store.query(all);
    assert.ok(first.nextCursor);
    const second = store.query({ ...all, cursor: first.nextCursor });
    assert.notEqual(first.certificates[0].id, second.certificates[0].id);
    assert.equal(second.nextCursor, null);
    assert.throws(
      () => store.query({ ...query(), cursor: first.nextCursor! }),
      /Cursor/,
    );
    const hidden =
      second.certificates[0].sourceId === "hidden"
        ? second.certificates[0]
        : first.certificates[0];
    assert.equal(store.certificate(hidden.id, ["allowed"]), null);
    assert.throws(
      () => store.save("allowed", pem, "revoked", "bad"),
      /mismatch/,
    );
    assert.equal(store.query(query()).certificates[0].revoked, "unknown");
    assert.throws(() =>
      validateQuery({
        sources: [],
        conditions: [{ field: "constructor", operator: "equals", value: "x" }],
      }),
    );
    assert.throws(() =>
      validateQuery({
        sources: [],
        conditions: [{ field: "serial", operator: "equals", value: "xyz" }],
      }),
    );
    assert.deepEqual(
      parseSans(
        'DNS:example.test, URI:"https://example.test/a,b", IP Address:127.0.0.1',
      ),
      [
        { type: "dns", value: "example.test" },
        { type: "uri", value: "https://example.test/a,b" },
        { type: "ip", value: "127.0.0.1" },
      ],
    );
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("worker persists progress, marks unknown revocation and pauses on lost access", async () => {
  const dir = mkdtempSync(join(tmpdir(), "pki-worker-")),
    dbPath = join(dir, "catalog.sqlite"),
    store = new PkiStore(dbPath);
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      join(dir, "key.pem"),
      "-out",
      join(dir, "cert.pem"),
      "-subj",
      "/CN=worker.test",
      "-days",
      "1",
    ],
    { stdio: "ignore" },
  );
  const pem = readFileSync(join(dir, "cert.pem"), "utf8"),
    serial = parseCertificate(pem).serial;
  let allowed = true,
    reads = 0;
  const server = createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    const path = req.url!.split("?")[0];
    if (path.includes("/sys/health"))
      res.end(JSON.stringify({ cluster_id: "test" }));
    else if (path.endsWith("/auth/token/lookup-self")) res.end('{"data":{}}');
    else if (path.endsWith("/sys/mounts"))
      res.end('{"data":{"pki/":{"type":"pki","accessor":"accessor"}}}');
    else if (path.endsWith("/sys/capabilities-self"))
      res.end(JSON.stringify({ "pki/certs": [allowed ? "list" : "deny"] }));
    else if (path.endsWith("/certs/revoked")) {
      res.statusCode = 403;
      res.end("{}");
    } else if (path.endsWith("/certs"))
      res.end(JSON.stringify({ data: { keys: [serial] } }));
    else if (path.includes("/cert/")) {
      reads++;
      res.end(JSON.stringify({ data: { certificate: pem } }));
    } else {
      res.statusCode = 404;
      res.end("{}");
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const address = `http://127.0.0.1:${(server.address() as { port: number }).port}`,
    adapter = new PkiAdapter(address, "test-token");
  try {
    const source = (await adapter.discover())[0];
    store.source(source);
    const input = {
      id: store.createJob([source.id]),
      dbPath,
      address,
      token: "test-token",
      namespace: "",
      skipTls: false,
      concurrency: 2,
      requestsPerSecond: 10000,
    };
    await collectPki(input);
    assert.equal(store.job(input.id)!.status, "partial");
    assert.equal(
      store.job(input.id)!.completed,
      1,
      JSON.stringify(store.db.prepare("SELECT * FROM job_items").all()),
    );
    assert.equal(store.sources([source.id])[0].coverage, "revocation_unknown");
    store.state(input.id, "queued");
    await collectPki(input);
    assert.equal(reads, 2);
    allowed = false;
    const denied = { ...input, id: store.createJob([source.id]) };
    await collectPki(denied);
    assert.equal(store.job(denied.id)!.status, "paused");
    assert.equal(reads, 2);
    const paused = { ...input, id: store.createJob([source.id]) };
    store.state(paused.id, "pausing");
    await collectPki(paused);
    assert.equal(store.job(paused.id)!.status, "paused");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
