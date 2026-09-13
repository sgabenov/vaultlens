import {
  Router,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import { resolve } from "node:path";
import { findIssuer } from "../pki/issuer.js";
import { config } from "../config/index.js";
import { PkiAdapter, PkiError } from "../pki/adapter.js";
import { PkiStore } from "../pki/store.js";
import { validateQuery } from "../pki/query.js";
import { launchCollection } from "../pki/runtime.js";
import type { PkiSource } from "../../shared/pki.js";
import { collectionSettings } from "../pki/settings.js";
const limits = collectionSettings();
const router = Router();
const dbPath = resolve(
  process.env["VAULTLENS_PKI_DB_PATH"] || "data/pki-certificates.sqlite",
);
const namespace = process.env["VAULTLENS_PKI_NAMESPACE"] || "";
// A deployment is bound to its configured Vault/namespace; requests cannot inject a target URL.
let instance: PkiStore | undefined;
const store = () => (instance ??= new PkiStore(dbPath));
type Context = { adapter: PkiAdapter; token: string; sources: PkiSource[] };
const contexts = new WeakMap<Request, Context>();
router.use(async (req: Request, res: Response, next: NextFunction) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const token = req.headers.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.slice(7)
      : req.cookies?.vault_token;
    if (typeof token !== "string" || !token)
      throw new PkiError(401, "Authentication required");
    const adapter = new PkiAdapter(
      config.vaultAddr,
      token,
      namespace,
      config.vaultSkipTlsVerify,
    );
    await adapter.verifyToken();
    const sources = await adapter.allowed(await adapter.discover());
    for (const source of sources) store().source(source);
    contexts.set(req, { adapter, token, sources });
    next();
  } catch (e) {
    next(e);
  }
});
const wrap =
  (fn: (req: Request, res: Response, ctx: Context) => Promise<void> | void) =>
  (req: Request, res: Response, next: NextFunction) =>
    Promise.resolve()
      .then(() => fn(req, res, contexts.get(req)!))
      .catch(next);
function authorized(ids: unknown, ctx: Context): string[] {
  if (
    !Array.isArray(ids) ||
    ids.length > 100 ||
    ids.some((x) => typeof x !== "string")
  )
    throw new PkiError(400, "Invalid source selection");
  const result = [...new Set(ids)] as string[];
  if (result.some((id) => !ctx.sources.some((s) => s.id === id)))
    throw new PkiError(
      403,
      "Selected source is not authorized or no longer exists",
    );
  return result;
}
router.get(
  "/sources",
  wrap((_req, res, ctx) => {
    res.json({
      sources: store().sources(ctx.sources.map((s) => s.id)),
      namespace,
    });
  }),
);
router.post(
  "/query",
  wrap((req, res, ctx) => {
    const query = validateQuery(req.body);
    query.sources = authorized(query.sources, ctx);
    res.json(store().query(query));
  }),
);
router.get(
  "/certificates/:id",
  wrap(async (req, res, ctx) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id))
      throw new PkiError(400, "Invalid certificate ID");
    const c = store().certificate(
      id,
      ctx.sources.map((s) => s.id),
    );
    if (!c) throw new PkiError(404, "Certificate not found");
    const pem = store().pem(c.fingerprint);
    const conflicts = store().conflicts(c.sourceId, c.serial);
    const source = ctx.sources.find((s) => s.id === c.sourceId)!;
    const { issuer, issuerState } = await findIssuer(pem!, source, ctx.adapter);
    res.json({ certificate: c, pem, issuer, issuerState, conflicts });
  }),
);
router.route("/export").get(wrap(exportRecords)).post(wrap(exportRecords));
async function exportRecords(req: Request, res: Response, ctx: Context) {
  let raw = req.body;
  if (req.method === "GET") {
    try {
      raw = JSON.parse(String(req.query.filter));
    } catch {
      throw new PkiError(400, "Invalid export query");
    }
  }
  const query = validateQuery({ ...raw, limit: 200, cursor: undefined });
  query.sources = authorized(query.sources, ctx);
  res.setHeader("Content-Type", "application/x-ndjson");
  res.setHeader(
    "Content-Disposition",
    'attachment; filename="certificates.ndjson"',
  );
  const snapshot = new PkiStore(dbPath);
  const exportedAt = new Date().toISOString();
  let closed = false,
    count = 0;
  const release = () => {
    if (closed) return;
    closed = true;
    try {
      if (snapshot.db.isTransaction) snapshot.db.exec("ROLLBACK");
    } finally {
      snapshot.close();
    }
  };
  const timeout = setTimeout(() => res.destroy(), 120000);
  const onClose = () => {
    clearTimeout(timeout);
    release();
  };
  res.once("close", onClose);
  try {
    snapshot.db.exec("BEGIN");
    // Pin the snapshot before streaming; concurrent WAL writers can still commit.
    const coverage = snapshot.sources(query.sources);
    res.write(
      JSON.stringify({
        kind: "coverage",
        consistency: "snapshot",
        sources: coverage,
        exportedAt,
      }) + "\n",
    );
    while (!res.destroyed) {
      await ctx.adapter.verifyToken();
      const current = await ctx.adapter.allowed(await ctx.adapter.discover());
      if (
        !query.sources.every((id) => current.some((source) => source.id === id))
      )
        throw new PkiError(403, "Source access changed during export");
      if (res.destroyed) return;
      const page = snapshot.query(query, false, Date.parse(exportedAt));
      for (const certificate of page.certificates) {
        if (res.destroyed) return;
        if (!res.write(JSON.stringify(certificate) + "\n"))
          await new Promise<void>((resolve) => {
            const done = () => {
              res.off("drain", done);
              res.off("close", done);
              resolve();
            };
            res.once("drain", done);
            res.once("close", done);
          });
        count++;
      }
      if (!page.nextCursor) break;
      query.cursor = page.nextCursor;
    }
    if (!res.destroyed)
      res.end(JSON.stringify({ kind: "complete", count, exportedAt }) + "\n");
  } finally {
    clearTimeout(timeout);
    res.off("close", onClose);
    release();
  }
}
router.get(
  "/jobs",
  wrap((_req, res, ctx) => {
    store().recover();
    res.json({ jobs: store().jobs(ctx.sources.map((s) => s.id)) });
  }),
);
router.get(
  "/jobs/:id",
  wrap((req, res, ctx) => {
    store().recover();
    const raw =
      req.query.errorLimit === undefined ? "20" : String(req.query.errorLimit);
    if (!/^\d+$/.test(raw) || Number(raw) < 1 || Number(raw) > 100)
      throw new PkiError(400, "errorLimit must be between 1 and 100");
    const details = store().jobDetails(
      String(req.params.id),
      ctx.sources.map((s) => s.id),
      Number(raw),
    );
    if (!details) throw new PkiError(404, "Job not found");
    res.json(details);
  }),
);
router.post(
  "/jobs",
  wrap((req, res, ctx) => {
    const ids = authorized(req.body.sources, ctx);
    if (!ids.length) throw new PkiError(400, "Select at least one source");
    const id = store().createJob(ids);
    launchCollection({
      id,
      dbPath,
      address: config.vaultAddr,
      token: ctx.token,
      namespace,
      skipTls: config.vaultSkipTlsVerify,
      ...limits,
    });
    res.status(202).json({ job: store().job(id) });
  }),
);
router.post(
  "/jobs/:id/:action",
  wrap((req, res, ctx) => {
    store().recover();
    const job = store().job(String(req.params.id));
    if (!job) throw new PkiError(404, "Job not found");
    authorized(job.sources, ctx);
    const action = req.params.action;
    if (action === "pause" && ["queued", "running"].includes(job.status)) {
      store().pause(job.id);
    } else if (
      action === "resume" &&
      ["paused", "partial", "interrupted"].includes(job.status)
    ) {
      store().resume(job.id);
      launchCollection({
        id: job.id,
        dbPath,
        address: config.vaultAddr,
        token: ctx.token,
        namespace,
        skipTls: config.vaultSkipTlsVerify,
        ...limits,
      });
    } else
      throw new PkiError(
        409,
        "Job cannot perform that action in its current state",
      );
    res.json({ job: store().job(job.id) });
  }),
);
router.use((e: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (res.headersSent) {
    res.end(
      JSON.stringify({
        kind: "error",
        error: "Export interrupted; results are incomplete",
      }) + "\n",
    );
    return;
  }
  res.status(e instanceof PkiError ? e.status : 500).json({
    error: e instanceof PkiError ? e.message : "Certificate operation failed",
  });
});
export default router;
