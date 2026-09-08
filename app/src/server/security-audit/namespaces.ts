import type { AuditSnapshot } from '../../shared/securityAudit.js';
export function snapshotNamespaces(snapshot:AuditSnapshot):string[] {
  const observed=snapshot.resources.map(resource=>resource.namespace??'');
  return [...new Set([...(snapshot.namespaces??[]),...observed,...(!observed.length&&!snapshot.namespaces?.length?['']:[])])].sort();
}
