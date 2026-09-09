import { mergeRefresh } from './refresh.js';
import { importFailureReason } from './failureReason.js';
import { importPythonSnapshot } from './pythonImport.js';
import { snapshotNamespaces } from './namespaces.js';
import { applyBaseline } from './baseline.js';
import { workerData } from 'node:worker_threads';
import { collect } from './collector.js';
import { execute } from './engine.js';
import { AuditStore } from './store.js';
const {
  refreshRunId,
  resumeRunId,
  checkpointMaxAgeMs,
  importPath,
  dbPath,
  id,
  target,
  token,
  skipTlsVerify,
  settings,
  collectionOptions,
  sourceRunId,
  baseline,
  exceptions,
} = workerData;
const store = new AuditStore(dbPath);
let lastUpdate = 0,
  lastStage = '';
const progress = (
  value: import('../../shared/securityAudit.js').AuditProgress,
) => {
  const stage = `${value.namespace}:${value.phase}`;
  if (stage !== lastStage || Date.now() - lastUpdate >= 250) {
    store.updateProgress(id, value);
    lastUpdate = Date.now();
    lastStage = stage;
  }
};
try {
  if (importPath) {
    progress({
      namespace: '',
      phase: 'Importing Python snapshot',
      resources: 0,
      requests: 0,
      updatedAt: new Date().toISOString(),
    });
    store.finish(id, importPythonSnapshot(importPath, target), []);
  } else {
    const resumeSource = resumeRunId ? store.get(resumeRunId, target) : null;
    if (
      resumeRunId &&
      (!resumeSource?.snapshot ||
        !['failed', 'interrupted'].includes(resumeSource.run.status))
    )
      throw new Error('Checkpoint unavailable');
    const resume = resumeSource?.snapshot
      ? { snapshot: resumeSource.snapshot, maxAgeMs: checkpointMaxAgeMs }
      : undefined;
    const refreshSource = refreshRunId ? store.get(refreshRunId, target) : null;
    if (
      refreshRunId &&
      (!refreshSource?.snapshot ||
        !['collected', 'completed', 'partial'].includes(
          refreshSource.run.status,
        ))
    )
      throw new Error('Refresh source unavailable');
    let snapshot = sourceRunId
      ? store.get(sourceRunId, target)?.snapshot
      : await collect(
          target,
          token,
          skipTlsVerify,
          collectionOptions,
          progress,
          (snapshot) => store.saveCheckpoint(id, snapshot),
          resume,
        );
    if (!snapshot) throw new Error('Source snapshot not found');
    if (refreshSource?.snapshot)
      snapshot = mergeRefresh(
        refreshSource.snapshot,
        snapshot,
        collectionOptions.sources,
      );
    if (sourceRunId || resumeRunId || refreshRunId)
      snapshot.sourceRunId = sourceRunId ?? resumeRunId ?? refreshRunId;
    progress({
      namespace: '',
      phase: 'Analyzing snapshot',
      resources: snapshot.resources.length,
      requests: snapshot.collection?.metrics.requests ?? 0,
      updatedAt: new Date().toISOString(),
    });
    const result = execute(snapshot, settings ?? store.settings());
    snapshot.controls = applyBaseline(
      result.findings,
      result.configuration,
      target,
      baseline,
      exceptions,
      undefined,
      snapshotNamespaces(snapshot),
    );
    snapshot.analysisPerformed = true;
    snapshot.identity = result.identity;
    store.finish(id, snapshot, result.findings, result.configuration);
  }
} catch (error) {
  store.fail(
    id,
    importPath
      ? importFailureReason(error)
      : 'Audit analysis failed. Check the selected rules and snapshot compatibility.',
  );
} finally {
  store.close();
}
