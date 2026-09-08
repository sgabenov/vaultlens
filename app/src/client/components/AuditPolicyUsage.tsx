import { useMemo, useState } from 'react';
import type { AuditSnapshot } from '../../shared/securityAudit';
import { policyUsage } from '../../shared/policyUsage';

export default function AuditPolicyUsage({snapshot}:{snapshot:AuditSnapshot}) {
  const [query,setQuery] = useState('');
  const [unassigned,setUnassigned] = useState(false);
  const [limit,setLimit] = useState(100);
  const rows = useMemo(() => policyUsage(snapshot),[snapshot]);
  const visible = rows.filter(row => (!unassigned || !row.references.length) &&
    [row.namespace,row.name,...row.references.map(reference => reference.path)].some(value => value.toLowerCase().includes(query.toLowerCase())));
  return <details className="rounded border p-3 text-sm">
    <summary>Policy usage · {rows.length}</summary>
    <p className="my-2 text-xs text-gray-500">Observed assignments and inherited policies. No observed references does not prove a policy is unused: existing tokens, allowed globs and collection gaps are not covered.</p>
    <input aria-label="Filter policy usage" placeholder="Filter namespace, policy or subject" className="my-2 w-full rounded border p-2" value={query} onChange={event => {setQuery(event.target.value);setLimit(100);}} />
    <label className="flex gap-2"><input type="checkbox" checked={unassigned} onChange={event => {setUnassigned(event.target.checked);setLimit(100);}} />No observed references</label>
    <p className="my-2 text-xs">Showing {Math.min(limit,visible.length)} of {visible.length} policies</p>
    {visible.slice(0,limit).map(row => <details key={JSON.stringify([row.namespace,row.name])} className="my-2 rounded border p-2">
      <summary>{row.namespace || 'root'} · {row.name} · {row.references.length} references{row.collected ? '' : ' · policy document not collected'}</summary>
      <ul className="mt-2 space-y-1">{row.references.map((reference,index) => <li key={index} className="break-all">
        {reference.relationship} · {reference.kind} · {reference.path}{reference.relationship === 'inherited' && ` · via ${reference.sourcePath}`}
      </li>)}</ul>
    </details>)}
    {visible.length > limit && <button className="rounded border px-3 py-2" onClick={() => setLimit(limit + 100)}>Load more policies</button>}
  </details>;
}
