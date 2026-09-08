import { prepareResume } from '../security-audit/resume.js';
import { snapshotNamespaces } from '../security-audit/namespaces.js';
import { parseBaseline, applyBaseline, createBaseline } from '../security-audit/baseline.js';
import { parseExceptions } from '../security-audit/exceptions.js';
import { settingsFingerprint } from '../security-audit/catalog.js';
import { ENGINE_VERSION } from '../security-audit/engine.js';
import { parseCollectionOptions } from '../security-audit/requestPolicy.js';
import { exportAudit, EXPORT_FORMATS, type ExportFormat } from '../security-audit/exporter.js';
import { compareRuns } from '../security-audit/diff.js';
import { Router, raw } from 'express';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
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
function workerEntry() {
  return import.meta.url.endsWith('.ts')
      ? new URL(
          'data:text/javascript,' +
            encodeURIComponent(
              `import {tsImport} from ${JSON.stringify(import.meta.resolve('tsx/esm/api'))}; await tsImport(${JSON.stringify(new URL('../security-audit/worker.ts', import.meta.url).href)}, ${JSON.stringify(import.meta.url)});`,
            ),
        )
      : new URL('../security-audit/worker.js', import.meta.url);
}
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
router.post('/imports/python', raw({type:'application/octet-stream',limit:'32mb'}), (req,res,next) => {
  if (!Buffer.isBuffer(req.body) || req.body.length<16 || req.body.subarray(0,16).toString('binary')!=='SQLite format 3\0') {
    res.status(400).json({error:'Expected a Python SQLite snapshot as application/octet-stream'});return;
  }
  const db=storage();
  let directory:string|undefined,id:string|undefined;
  try {
    id=db.create(config.vaultAddr);
    directory=mkdtempSync(path.join(tmpdir(),'vaultlens-python-import-'));
    const importPath=path.join(directory,'snapshot.sqlite');
    writeFileSync(importPath,req.body,{mode:0o600,flag:'wx'});
    const worker=new Worker(workerEntry(),{workerData:{dbPath,id,target:config.vaultAddr,importPath}});
    active=worker;
    const runId=id,uploadDirectory=directory;
    worker.once('error',()=>db.fail(runId));
    worker.once('exit',()=>{db.fail(runId);rmSync(uploadDirectory,{recursive:true,force:true});if(active===worker) active=undefined;});
    res.status(202).json({id});
  } catch(error) {
    if(directory) rmSync(directory,{recursive:true,force:true});
    if(id) {db.fail(id);next(error);}
    else res.status(409).json({error:'An audit is already running'});
  }
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
router.get('/diff', (req, res) => {
  if (typeof req.query['old'] !== 'string' || typeof req.query['new'] !== 'string') {
    res.status(400).json({error:'Expected old and new run IDs'}); return;
  }
  const old = storage().get(req.query['old'], config.vaultAddr);
  const next = storage().get(req.query['new'], config.vaultAddr);
  if (!old || !next) { res.status(404).json({error:'Audit run not found'}); return; }
  try { res.json(compareRuns(old, next)); }
  catch(error) { res.status(400).json({error:error instanceof Error ? error.message : 'Snapshots cannot be compared'}); }
});
router.get('/runs/:id/baseline', (req,res)=>{
  const detail=storage().get(String(req.params['id']),config.vaultAddr);
  if(!detail) {res.status(404).json({error:'Audit run not found'});return;}
  try {res.json(createBaseline(detail));}
  catch(error) {res.status(400).json({error:error instanceof Error?error.message:'Baseline unavailable'});}
});
router.get('/runs/:id/export', (req, res) => {
  const format=req.query['format'] ?? 'json';
  if(typeof format!=='string' || !EXPORT_FORMATS.includes(format as ExportFormat)) {
    res.status(400).json({error:'Unsupported export format'});return;
  }
  const redact = req.query['redactPolicySource'] ?? 'false';
  if (redact !== 'true' && redact !== 'false') {
    res.status(400).json({error:'redactPolicySource must be true or false'});return;
  }
  const detail=storage().get(String(req.params['id']),config.vaultAddr);
  if(!detail) {res.status(404).json({error:'Audit run not found'});return;}
  try {
    const body=exportAudit(detail,format as ExportFormat,redact === 'true');
    const contentTypes={json:'application/json',jsonl:'application/x-ndjson',yaml:'application/yaml',csv:'text/csv'};
    res.type(contentTypes[format as ExportFormat]);
    res.setHeader('Content-Disposition', `attachment; filename="audit-report.${format}"`);
    res.send(body);
  } catch(error) {res.status(400).json({error:error instanceof Error?error.message:'Export failed'});}
});
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
  let collectionOptions;
  try {collectionOptions=parseCollectionOptions(req.body?.collectionOptions);}
  catch(error) {res.status(400).json({error:error instanceof Error?error.message:'Invalid collection options'});return;}
  const db = storage();
  const sourceRunId=req.body?.sourceRunId;
  const resumeRunId=req.body?.resumeRunId;
  const checkpointMaxAgeMs=req.body?.checkpointMaxAgeMs??86400000;
  if(resumeRunId!==undefined) {
    if(typeof resumeRunId!=='string' || sourceRunId!==undefined || req.body?.collectionOptions!==undefined) {
      res.status(400).json({error:'Resume requires its own run ID and the saved collection options'});return;
    }
    const source=db.get(resumeRunId,config.vaultAddr);
    if(!source?.snapshot || !['failed','interrupted'].includes(source.run.status)) {
      res.status(404).json({error:'Failed or interrupted checkpoint not found'});return;
    }
    try {collectionOptions=prepareResume(source.snapshot,config.vaultAddr,checkpointMaxAgeMs).options;}
    catch(error) {res.status(400).json({error:error instanceof Error?error.message:'Invalid checkpoint'});return;}
  }

  if(sourceRunId!==undefined) {
    if(typeof sourceRunId!=='string') {res.status(400).json({error:'Invalid source run ID'});return;}
    const source=db.get(sourceRunId,config.vaultAddr);
    if(!source?.snapshot || !['collected','completed','partial'].includes(source.run.status)) {
      res.status(404).json({error:'Finished source snapshot not found'});return;
    }
  }
  const settings=db.settings(),definitions=catalog(settings);
  let baseline;
  let exceptions;
  try {
    for(const key of ['baselineYaml','exceptionsYaml'])
      if(req.body?.[key]!==undefined && typeof req.body[key]!=='string') throw new Error(`${key} must be text`);
    baseline=req.body?.baselineYaml?.trim() ? parseBaseline(req.body.baselineYaml) : undefined;
    exceptions=req.body?.exceptionsYaml?.trim() ? parseExceptions(req.body.exceptionsYaml,new Set(definitions.map(rule=>rule.id))) : [];
    applyBaseline([],{...settings,catalog:definitions,fingerprint:settingsFingerprint(settings,definitions),engineVersion:ENGINE_VERSION,issues:[]},config.vaultAddr,baseline,exceptions,undefined,sourceRunId?snapshotNamespaces(db.get(sourceRunId,config.vaultAddr)!.snapshot!):collectionOptions.recursiveNamespaces && baseline ? baseline.namespaces??[''] :[collectionOptions.namespace]);
  } catch(error) {res.status(400).json({error:error instanceof Error?error.message:'Invalid audit controls'});return;}
  let id: string;
  try {
    id = db.create(config.vaultAddr);
  } catch {
    res.status(409).json({ error: 'An audit is already running' });
    return;
  }
  try {
    active = new Worker(workerEntry(), {
      workerData: {
        dbPath,
        id,
        target: config.vaultAddr,
        token: req.vaultToken,
        skipTlsVerify: config.vaultSkipTlsVerify,
        settings,
        baseline,
        exceptions,
        collectionOptions,
        sourceRunId,
        resumeRunId,
        checkpointMaxAgeMs,
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
