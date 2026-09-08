import { workerData } from 'node:worker_threads';
import { collect } from './collector.js';
import { analyze } from './engine.js';
import { AuditStore } from './store.js';
const { dbPath, id, target, token, skipTlsVerify } = workerData;
const store = new AuditStore(dbPath);
try {
  const snapshot = await collect(target, token, skipTlsVerify);
  store.finish(id, snapshot, analyze(snapshot));
} catch {
  store.fail(id);
} finally {
  store.close();
}
