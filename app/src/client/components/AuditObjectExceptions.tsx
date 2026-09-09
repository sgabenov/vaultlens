import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getAuditObjectExceptions, removeAuditObjectException } from '../lib/api';
export default function AuditObjectExceptions() {
  const client=useQueryClient();
  const query=useQuery({queryKey:['audit-object-exceptions'],queryFn:getAuditObjectExceptions});
  const [search,setSearch]=useState(''),[requested,setPage]=useState(1);
  const remove=useMutation({mutationFn:removeAuditObjectException,onSuccess:()=>client.invalidateQueries({queryKey:['audit-object-exceptions']})});
  const matches=query.data?.filter(entry=>[entry.rule_id,entry.namespace,entry.object_path,entry.owner,entry.reason].some(value=>value.toLowerCase().includes(search.toLowerCase())))??[];
  const page=Math.min(requested,Math.max(1,Math.ceil(matches.length/10)));
  const now=new Date(),today=`${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`;
  return <details className="rounded border p-4">
    <summary className="cursor-pointer text-sm font-medium">Saved object exceptions · {query.data?.length??0}</summary>
    <p className="my-3 text-xs text-gray-500">These exceptions apply to new analyses of this Vault. Removing one does not rewrite historical results. Create an exception from an individual finding.</p>
    {query.isPending&&<p>Loading exceptions…</p>}
    {(query.error||remove.error)&&<p role="alert" className="text-sm text-red-700">Could not load or update exceptions.</p>}
    <input aria-label="Search saved exceptions" placeholder="Check, object, owner or reason" className="mb-3 w-full rounded border p-2 text-sm" value={search} onChange={event=>{setSearch(event.target.value);setPage(1);}}/>
    {matches.slice((page-1)*10,page*10).map(entry=><div key={entry.id} className="space-y-1 border-t py-3 text-sm">
      <p className="font-medium">{entry.rule_id} · {entry.expires<today?'Expired':'Active'}</p>
      <p className="break-all font-mono text-xs">{entry.namespace||'root'} · {entry.object_path}</p>
      <p>{entry.reason}</p><p className="text-xs text-gray-500">{entry.owner} · expires {entry.expires}</p>
      <button className="mt-2 rounded border px-3 py-1 text-xs disabled:opacity-50" disabled={remove.isPending} onClick={()=>remove.mutate(entry.id)}>Remove from future analyses</button>
    </div>)}
    {!query.isPending&&!matches.length&&<p className="text-sm text-gray-500">No matching object exceptions.</p>}
    <div className="mt-3 flex items-center justify-end gap-3 text-xs"><span>{matches.length} matches · page {page}</span><button disabled={page<=1} onClick={()=>setPage(page-1)} className="rounded border px-2 py-1 disabled:opacity-40">Previous</button><button disabled={page*10>=matches.length} onClick={()=>setPage(page+1)} className="rounded border px-2 py-1 disabled:opacity-40">Next</button></div>
  </details>;
}
