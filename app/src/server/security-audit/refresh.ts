import type { AuditSnapshot } from '../../shared/securityAudit.js';
import { RESOURCE_STAGE, stageKey } from './collectionStages.js';

/** Replace absence only within a successfully collected stage. */
export function mergeRefresh(
  base: AuditSnapshot,
  fresh: AuditSnapshot,
  sources: string[],
): AuditSnapshot {
  if (base.target !== fresh.target || !base.finishedAt || !fresh.finishedAt)
    throw new Error('Refresh requires matching finished snapshots');
  const complete = new Set(
    fresh.collection?.stageResults
      ?.filter((stage) => stage.complete)
      .map((stage) => stageKey(stage.namespace, stage.stage)) ?? [],
  );
  const key = (resource: AuditSnapshot['resources'][number]) =>
    JSON.stringify([resource.namespace ?? '', resource.kind, resource.path]);
  const resources = new Map<string, AuditSnapshot['resources'][number]>(
    base.resources
      .filter(
        (resource) =>
          !complete.has(
            stageKey(resource.namespace ?? '', RESOURCE_STAGE[resource.kind]),
          ),
      )
      .map((resource) => [
        key(resource),
        {
          ...structuredClone(resource),
          retainedFromSnapshotAt:
            resource.retainedFromSnapshotAt ?? base.finishedAt,
        },
      ]),
  );
  let retained = resources.size;
  for (const resource of fresh.resources) {
    if (resources.has(key(resource))) retained--;
    resources.set(key(resource), structuredClone(resource));
  }
  const namespaces = [
    ...new Set([...(base.namespaces ?? ['']), ...(fresh.namespaces ?? [''])]),
  ].sort();
  const policyCoverage: Record<string, boolean> = {},
    aliasCoverage: Record<string, boolean> = {};
  const refreshedStages = new Set(
    fresh.collection?.stageResults?.map((stage) =>
      stageKey(stage.namespace, stage.stage),
    ) ?? [],
  );
  for (const namespace of namespaces) {
    policyCoverage[namespace] = refreshedStages.has(
      stageKey(namespace, 'Policies'),
    )
      ? (fresh.namespacePolicyCompleteness?.[namespace] ?? false)
      : (base.namespacePolicyCompleteness?.[namespace] ??
        base.policiesComplete);
    aliasCoverage[namespace] = refreshedStages.has(
      stageKey(namespace, 'Identity aliases'),
    )
      ? (fresh.namespaceAliasCompleteness?.[namespace] ?? false)
      : (base.namespaceAliasCompleteness?.[namespace] ?? false);
  }
  return {
    ...fresh,
    resources: [...resources.values()],
    namespaces,
    namespacePolicyCompleteness: policyCoverage,
    namespaceAliasCompleteness: aliasCoverage,
    policiesComplete: namespaces.every(
      (namespace) => policyCoverage[namespace],
    ),
    issues: [
      ...base.issues,
      ...fresh.issues.filter(
        (issue) => issue.path !== 'collection/source-scope',
      ),
    ],
    collection: fresh.collection
      ? {
          ...fresh.collection,
          requestPolicy: {
            ...fresh.collection.requestPolicy,
            sources: base.collection?.requestPolicy.sources,
          },
          scope: base.collection?.scope,
        }
      : undefined,
    refresh: {
      sources,
      retainedResources: retained,
      retainedFrom: base.refresh?.retainedFrom ?? base.finishedAt,
    },
  };
}
