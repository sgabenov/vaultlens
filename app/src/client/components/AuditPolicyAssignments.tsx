import { useState } from 'react';
import type { PolicyUsage } from '../../shared/policyUsage';

export default function AuditPolicyAssignments({usage}:{usage:PolicyUsage}) {
  const [query,setQuery]=useState(''),[page,setPage]=useState(1);
  const rows=usage.references.filter(reference=>[reference.path,reference.kind,reference.relationship,reference.sourcePath].some(value=>value.toLowerCase().includes(query.toLowerCase())));
  const current=Math.min(page,Math.max(1,Math.ceil(rows.length/25)));
  return <details>
    <summary className="cursor-pointer">Policy assignments · {usage.references.length}</summary>
    <p className="mt-2 text-xs text-gray-500">{usage.namespace||'root'} · {usage.name}. Observed assignments and allowed policy references; existing tokens, allowed globs and collection gaps may not be covered.</p>
    {!usage.references.length?<p className="mt-2 text-sm">No assignments found in the available data. This does not prove the policy is unused.</p>:<>
      <label className="mt-3 block text-xs">Filter assignments<input className="mt-1 block w-full rounded border p-2" value={query} placeholder="Object path, relationship or source" onChange={event=>{setQuery(event.target.value);setPage(1);}}/></label>
      <ul className="mt-2 space-y-2">{rows.slice((current-1)*25,current*25).map((reference,index)=><li key={index} className="break-all text-xs">
        <span className="font-medium">{reference.relationship} · {reference.kind}</span> · {usage.namespace||'root'} · {reference.path}
        {reference.relationship==='inherited'&&<span className="block text-gray-500">Via {reference.sourcePath}</span>}
      </li>)}</ul>
      {!rows.length&&<p className="mt-2 text-xs">No matching assignments.</p>}
      {rows.length>25&&<div className="mt-3 flex items-center gap-3 text-xs"><span>{rows.length} matches · page {current}</span><button disabled={current<=1} className="rounded border px-2 py-1 disabled:opacity-40" onClick={()=>setPage(current-1)}>Previous</button><button disabled={current*25>=rows.length} className="rounded border px-2 py-1 disabled:opacity-40" onClick={()=>setPage(current+1)}>Next</button></div>}
    </>}
  </details>;
}
