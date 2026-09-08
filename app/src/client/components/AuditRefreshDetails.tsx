import { useState } from 'react';
import type { AuditSnapshot } from '../../shared/securityAudit';
export default function AuditRefreshDetails({snapshot}:{snapshot:AuditSnapshot}) {
  const [query,setQuery]=useState('');
  const [limit,setLimit]=useState(100);
  if(!snapshot.refresh) return null;
  const retained=snapshot.resources.filter(resource=>resource.retainedFromSnapshotAt &&
    [resource.namespace||'root',resource.kind,resource.path].some(value=>value.toLowerCase().includes(query.toLowerCase())));
  return <details className="rounded border p-3 text-sm">
    <summary>Refresh freshness · {snapshot.refresh.retainedResources} retained resources</summary>
    <p className="my-2">Refreshed sources: {snapshot.refresh.sources.join(', ')}.</p>
    <p className="text-xs text-gray-500">Retained resources were not successfully replaced in this refresh. A snapshot timestamp is shown when the original read time is unavailable.</p>
    <input aria-label="Filter retained resources" placeholder="Filter namespace, kind or path" className="my-2 w-full rounded border p-2" value={query} onChange={event=>{setQuery(event.target.value);setLimit(100);}} />
    <p className="mb-2 text-xs">Showing {Math.min(limit,retained.length)} of {retained.length} retained resources</p>
    {retained.slice(0,limit).map(resource=><div className="border-t py-2 break-all" key={JSON.stringify([resource.namespace,resource.kind,resource.path])}>
      <p>{resource.namespace||'root'} · {resource.kind} · {resource.path}</p>
      <p className="text-xs">{resource.observedAt?`Observed ${resource.observedAt}`:`From snapshot ${resource.retainedFromSnapshotAt}`}</p>
    </div>)}
    {retained.length>limit && <button className="rounded border px-3 py-2" onClick={()=>setLimit(limit+100)}>Load more retained resources</button>}
  </details>;
}
