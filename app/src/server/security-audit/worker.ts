import { importPythonSnapshot } from './pythonImport.js';
import { snapshotNamespaces } from './namespaces.js';
import { applyBaseline } from './baseline.js';
import { workerData } from 'node:worker_threads';
import { collect } from './collector.js';
import { execute } from './engine.js';
import { AuditStore } from './store.js';
const { importPath, dbPath, id, target, token, skipTlsVerify, settings, collectionOptions, sourceRunId, baseline, exceptions } = workerData;
const store = new AuditStore(dbPath);
try {
  if (importPath) {
    store.finish(id,importPythonSnapshot(importPath,target),[]);
  } else {
  const snapshot = sourceRunId ? store.get(sourceRunId,target)?.snapshot : await collect(target, token, skipTlsVerify, collectionOptions);
  if(!snapshot) throw new Error('Source snapshot not found');
  if(sourceRunId) snapshot.sourceRunId=sourceRunId;
  const result = execute(snapshot, settings ?? store.settings());
  snapshot.controls = applyBaseline(result.findings,result.configuration,target,baseline,exceptions,undefined,snapshotNamespaces(snapshot));
  snapshot.analysisPerformed = true;
  snapshot.identity = result.identity;
  store.finish(id, snapshot, result.findings, result.configuration);
  }
} catch {
  store.fail(id);
} finally {
  store.close();
}
