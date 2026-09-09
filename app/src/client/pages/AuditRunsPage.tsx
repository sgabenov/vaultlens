import AuditDiffPanel from '../components/AuditDiffPanel';
import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getSecurityAuditRuns } from '../lib/api';

export default function AuditRunsPage() {
  const [params] = useSearchParams();
  const runs = useQuery({ queryKey: ['security-audit-runs'], queryFn: getSecurityAuditRuns, refetchInterval: 3000 });
  const [requested,setPage]=useState(1),[size,setSize]=useState(10);
  const [selected,setSelected]=useState<string[]>([]);
  const [comparison,setComparison]=useState<{oldId:string;currentId:string}|null>(null);
  const eligible=runs.data?.filter(run=>['completed','partial'].includes(run.status))??[];
  const selectedRuns=eligible.filter(run=>selected.includes(run.id)).sort((a,b)=>a.startedAt.localeCompare(b.startedAt)||a.id.localeCompare(b.id));
  function toggle(id:string) {
    setSelected(current=>current.includes(id)?current.filter(value=>value!==id):current.length<2?[...current,id]:current);
    setComparison(null);
  }
  const total=runs.data?.length??0;
  const page=Math.min(requested,Math.max(1,Math.ceil(total/size)));
  return <section className="space-y-4">
    <div className="flex items-center justify-between gap-3"><h2 className="text-lg font-semibold">Runs</h2><Link className="rounded bg-blue-600 px-4 py-2 text-sm text-white" to="/security-audit/findings?collect=1">Run audit</Link></div>
    <p className="text-sm text-gray-500">Open a saved run to review its findings, coverage and collection details.</p>
    <div className="flex flex-wrap items-center gap-3 text-sm">
      <span>Select two completed runs to compare · {selectedRuns.length}/2 selected</span>
      <button className="rounded border px-3 py-2 disabled:opacity-40" disabled={selectedRuns.length!==2} onClick={()=>setComparison({oldId:selectedRuns[0].id,currentId:selectedRuns[1].id})}>Compare</button>
      {!!selected.length&&<button className="rounded border px-3 py-2" onClick={()=>{setSelected([]);setComparison(null);}}>Clear selection</button>}
    </div>
    {comparison&&<>
      <p className="text-sm text-gray-500">Before: {eligible.find(run=>run.id===comparison.oldId)?.startedAt ? new Date(eligible.find(run=>run.id===comparison.oldId)!.startedAt).toLocaleString() : comparison.oldId} → After: {eligible.find(run=>run.id===comparison.currentId)?.startedAt ? new Date(eligible.find(run=>run.id===comparison.currentId)!.startedAt).toLocaleString() : comparison.currentId}</p>
      <AuditDiffPanel key={`${comparison.oldId}:${comparison.currentId}`} oldId={comparison.oldId} currentId={comparison.currentId}/>
    </>}
    {runs.isPending && <p>Loading runs…</p>}
    {runs.error && <p role="alert">Could not load audit runs. Administrator access is required.</p>}
    {runs.data?.length === 0 && <p>No runs yet. <Link className="text-blue-700 underline" to="/security-audit/findings?collect=1">Start the first audit</Link>.</p>}
    {!!runs.data?.length && <><div className="flex flex-wrap items-center justify-between gap-3 text-sm"><p className="text-gray-500">Most recent runs · up to 100 retained in this list</p><label>Per page<select className="ml-2 rounded border p-1" value={size} onChange={event=>{setSize(Number(event.target.value));setPage(1);}}>{[10,25,50].map(value=><option key={value}>{value}</option>)}</select></label></div><div className="overflow-x-auto"><table className="w-full text-left text-sm">
      <thead className="text-gray-500"><tr><th className="p-3">Compare</th><th className="p-3">Collected</th><th className="p-3">Vault</th><th className="p-3">Status</th><th className="p-3">Resources</th><th className="p-3">Findings</th><th className="p-3">Coverage gaps</th></tr></thead>
      <tbody>{runs.data.slice((page-1)*size,page*size).map(run => <tr key={run.id} className={`border-t ${params.get('run') === run.id ? 'bg-blue-50' : ''}`}>
        <td className="p-3"><input type="checkbox" aria-label={`Select run ${new Date(run.startedAt).toLocaleString()} · ${run.id.slice(0,8)} for comparison`} checked={selected.includes(run.id)} disabled={!['completed','partial'].includes(run.status)||(!selected.includes(run.id)&&selected.length>=2)} onChange={()=>toggle(run.id)}/></td>
        <td className="p-3"><Link className="text-blue-700 underline" to={`/security-audit/findings?${new URLSearchParams({ run: run.id })}`}>{new Date(run.startedAt).toLocaleString()}</Link></td>
        <td className="p-3">{run.target}</td><td className="p-3">{run.status}</td><td className="p-3">{run.resourceCount}</td><td className="p-3">{run.findingCount}</td><td className="p-3">{run.issueCount}</td>
      </tr>)}</tbody>
    </table></div><div className="flex items-center justify-end gap-3 text-sm"><span>{(page-1)*size+1}–{Math.min(page*size,total)} of {total}</span><button className="rounded border px-2 py-1 disabled:opacity-40" disabled={page<=1} onClick={()=>setPage(page-1)}>Previous</button><button className="rounded border px-2 py-1 disabled:opacity-40" disabled={page*size>=total} onClick={()=>setPage(page+1)}>Next</button></div></>}
  </section>;
}
