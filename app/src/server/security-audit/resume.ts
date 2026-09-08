import type { AuditSnapshot } from '../../shared/securityAudit.js';
import { parseCollectionOptions } from './requestPolicy.js';

export function prepareResume(snapshot:AuditSnapshot,target:string,maxAgeMs=86400000,now=Date.now()) {
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs<1 || maxAgeMs>604800000) throw new Error('Checkpoint max age must be from 1 to 604800000 ms');
  if (!snapshot.checkpoint || snapshot.finishedAt || snapshot.target!==target || !snapshot.collection)
    throw new Error('A matching unfinished collection checkpoint is required');
  const started=Date.parse(snapshot.startedAt),saved=Date.parse(snapshot.checkpoint.savedAt);
  if (!Number.isFinite(started) || !Number.isFinite(saved) || saved>now || started>saved || now-started>maxAgeMs)
    throw new Error('Checkpoint is too old or has invalid timestamps');
  const options=parseCollectionOptions(snapshot.collection.requestPolicy);
  const reusable=snapshot.checkpoint.completedNamespaces.filter(namespace=>
    !snapshot.issues.some(issue=>(issue.namespace??'')===namespace) &&
    !snapshot.resources.some(resource=>(resource.namespace??'')===namespace && resource.kind==='policy' && typeof resource.data.hcl!=='string'));
  return {options,reusable:new Set(reusable)};
}
