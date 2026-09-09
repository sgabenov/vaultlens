import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import AuditRefreshPanel from '../components/AuditRefreshPanel';
import AuditImportUpload from '../components/AuditImportUpload';
import { getSecurityAuditRun, getSecurityAuditRuns } from '../lib/api';

export default function AuditSourcesPage() {
  const navigate = useNavigate();
  const client = useQueryClient();
  const runs = useQuery({ queryKey: ['security-audit-runs'], queryFn: getSecurityAuditRuns, refetchInterval: 3000 });
  const [params] = useSearchParams();
  const runId = params.get('run') || runs.data?.[0]?.id || '';
  const detail = useQuery({queryKey:['security-audit-run',runId],queryFn:()=>getSecurityAuditRun(runId),enabled:!!runId,
    refetchInterval:query=>query.state.data?.run.status==='running'?2000:false});
  const disabled = runs.isPending || !!runs.error || !!runs.data?.some(run=>run.status==='running');
  const openResult = (id:string) => {
    client.invalidateQueries({queryKey:['security-audit-runs']});
    navigate(`/security-audit/findings?${new URLSearchParams({run:id})}`);
  };
  return <section className="space-y-4">
    <h2 className="text-lg font-semibold">Sources</h2>
    <div className="rounded border border-gray-200 p-4">
      <h3 className="font-medium">Current Vault session</h3>
      <p className="my-2 text-sm text-gray-500">Live collection uses the Vault connection and authentication configured in VaultLens.</p>
      <Link className="text-sm text-blue-700 underline" to="/security-audit/findings?collect=1">Collect and run audit</Link>
    </div>
    <section className="space-y-3">
      <h3 className="font-medium">Refresh saved snapshot</h3>
      {runId ? <>
        <p className="text-sm text-gray-500">Source run: {detail.data ? new Date(detail.data.run.startedAt).toLocaleString() : runId}. <Link className="text-blue-700 underline" to={`/security-audit/runs?${new URLSearchParams({run:runId})}`}>Choose another run</Link></p>
        {detail.isPending && <p className="text-sm">Loading snapshot…</p>}
        {detail.error && <p role="alert" className="text-sm text-red-700">Could not load the selected snapshot.</p>}
        {detail.data && (detail.data.snapshot?.collection && ['collected','completed','partial'].includes(detail.data.run.status)
          ? <AuditRefreshPanel key={runId} runId={runId} disabled={disabled} controls={{baselineYaml:'',exceptionsYaml:''}} onRefreshed={openResult}/>
          : <p className="text-sm text-gray-500">This run has no completed collection to refresh. Select another run or start a new collection.</p>)}
      </> : !runs.isPending && !runs.error && <p className="text-sm text-gray-500">Collect a snapshot before refreshing selected sources.</p>}
    </section>
    {runs.error && <p role="alert">Could not check running audits. Retry before refreshing or importing a snapshot.</p>}
    <AuditImportUpload disabled={disabled} onImported={openResult} />
    <p className="text-sm text-gray-500">Imported snapshots are stored separately. Analyze them explicitly to produce findings.</p>
  </section>;
}
