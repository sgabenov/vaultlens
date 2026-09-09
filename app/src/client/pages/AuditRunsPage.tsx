import { Link, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getSecurityAuditRuns } from '../lib/api';

export default function AuditRunsPage() {
  const [params] = useSearchParams();
  const runs = useQuery({ queryKey: ['security-audit-runs'], queryFn: getSecurityAuditRuns, refetchInterval: 3000 });
  return <section className="space-y-4">
    <div className="flex items-center justify-between gap-3"><h2 className="text-lg font-semibold">Runs</h2><Link className="rounded bg-blue-600 px-4 py-2 text-sm text-white" to="/security-audit/findings?collect=1">Run audit</Link></div>
    <p className="text-sm text-gray-500">Open a saved run to review its findings, coverage and collection details.</p>
    {runs.isPending && <p>Loading runs…</p>}
    {runs.error && <p role="alert">Could not load audit runs. Administrator access is required.</p>}
    {runs.data?.length === 0 && <p>No runs yet. <Link className="text-blue-700 underline" to="/security-audit/findings?collect=1">Start the first audit</Link>.</p>}
    {!!runs.data?.length && <div className="overflow-x-auto"><table className="w-full text-left text-sm">
      <thead className="text-gray-500"><tr><th className="p-3">Collected</th><th className="p-3">Vault</th><th className="p-3">Status</th><th className="p-3">Resources</th><th className="p-3">Findings</th><th className="p-3">Coverage gaps</th></tr></thead>
      <tbody>{runs.data.map(run => <tr key={run.id} className={`border-t ${params.get('run') === run.id ? 'bg-blue-50' : ''}`}>
        <td className="p-3"><Link className="text-blue-700 underline" to={`/security-audit/findings?${new URLSearchParams({ run: run.id })}`}>{new Date(run.startedAt).toLocaleString()}</Link></td>
        <td className="p-3">{run.target}</td><td className="p-3">{run.status}</td><td className="p-3">{run.resourceCount}</td><td className="p-3">{run.findingCount}</td><td className="p-3">{run.issueCount}</td>
      </tr>)}</tbody>
    </table></div>}
  </section>;
}
