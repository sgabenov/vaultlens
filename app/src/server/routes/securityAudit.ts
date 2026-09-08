import { Router } from 'express';
import { Worker } from 'node:worker_threads';
import path from 'node:path';
import { config } from '../config/index.js';
import { authMiddleware } from '../middleware/auth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import type { AuthenticatedRequest } from '../types/index.js';
import { AuditStore } from '../security-audit/store.js';
import { RULES } from '../security-audit/engine.js';
const router = Router();
const dbPath = path.resolve(
  process.env['VAULTLENS_AUDIT_DB'] || 'data/security-audit.sqlite',
);
let store: AuditStore | undefined;
let active: Worker | undefined;
function storage() {
  if (!store) {
    store = new AuditStore(dbPath);
    store.recover();
  }
  return store;
}
router.use(authMiddleware, requireAdmin);
router.use((_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});
router.get('/rules', (_req, res) => res.json({ rules: RULES }));
router.get('/runs', (_req, res) =>
  res.json({ runs: storage().list(config.vaultAddr) }),
);
router.get('/runs/:id', (req, res) => {
  const detail = storage().get(String(req.params['id']), config.vaultAddr);
  if (!detail) {
    res.status(404).json({ error: 'Audit run not found' });
    return;
  }
  res.json(detail);
});
router.post('/runs', (req: AuthenticatedRequest, res, next) => {
  if (active) {
    res.status(409).json({ error: 'An audit is already running' });
    return;
  }
  const db = storage();
  let id: string;
  try {
    id = db.create(config.vaultAddr);
  } catch {
    res.status(409).json({ error: 'An audit is already running' });
    return;
  }
  try {
    const entry = import.meta.url.endsWith('.ts')
      ? new URL(
          'data:text/javascript,' +
            encodeURIComponent(
              `import {tsImport} from ${JSON.stringify(import.meta.resolve('tsx/esm/api'))}; await tsImport(${JSON.stringify(new URL('../security-audit/worker.ts', import.meta.url).href)}, ${JSON.stringify(import.meta.url)});`,
            ),
        )
      : new URL('../security-audit/worker.js', import.meta.url);
    active = new Worker(entry, {
      workerData: {
        dbPath,
        id,
        target: config.vaultAddr,
        token: req.vaultToken,
        skipTlsVerify: config.vaultSkipTlsVerify,
      },
    });
    active.once('error', () => db.fail(id));
    active.once('exit', () => {
      db.fail(id);
      active = undefined;
    });
    res.status(202).json({ id });
  } catch (error) {
    db.fail(id);
    next(error);
  }
});
export default router;
