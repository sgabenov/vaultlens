import { workerData } from 'node:worker_threads';
import { collect } from './collector.js';
import { execute } from './engine.js';
import { AuditStore } from './store.js';
const { dbPath, id, target, token, skipTlsVerify, settings } = workerData;
const store = new AuditStore(dbPath);
try {
  const snapshot = await collect(target, token, skipTlsVerify);
  const result = execute(snapshot, settings ?? store.settings());
  snapshot.identity = result.identity;
  store.finish(id, snapshot, result.findings, result.configuration);
} catch {
  store.fail(id);
} finally {
  store.close();
}
