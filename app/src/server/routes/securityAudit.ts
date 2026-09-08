import { Router } from 'express';
import { Worker } from 'node:worker_threads';
import path from 'node:path';
import { config } from '../config/index.js';
import { authMiddleware } from '../middleware/auth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import type { AuthenticatedRequest } from '../types/index.js';
import { AuditStore } from '../security-audit/store.js';
import { catalog, SUPPORTED_DETECTORS } from '../security-audit/catalog.js';
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
router.get('/rules', (_req, res) => {
  const settings = storage().settings();
  res.json({
    settings,
    catalog: catalog(settings),
    detectors: SUPPORTED_DETECTORS,
  });
});
router.put('/rules', (req, res) => {
  const { revision, configYaml, customRulesYaml } = req.body ?? {};
  if (
    !Number.isInteger(revision) ||
    revision < 0 ||
    typeof configYaml !== 'string' ||
    typeof customRulesYaml !== 'string'
  ) {
    res
      .status(400)
      .json({ error: 'Expected revision, configYaml and customRulesYaml' });
    return;
  }
  try {
    const settings = storage().saveSettings({
      revision,
      configYaml,
      customRulesYaml,
    });
    res.json({
      settings,
      catalog: catalog(settings),
      detectors: SUPPORTED_DETECTORS,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'Invalid configuration';
    res
      .status(message.includes('Settings changed') ? 409 : 400)
      .json({ error: message });
  }
});
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
        settings: db.settings(),
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
