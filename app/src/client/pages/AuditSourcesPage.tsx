import { Link, useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import AuditImportUpload from '../components/AuditImportUpload';
import { getSecurityAuditRuns } from '../lib/api';

export default function AuditSourcesPage() {
  const navigate = useNavigate();
  const client = useQueryClient();
  const runs = useQuery({ queryKey: ['security-audit-runs'], queryFn: getSecurityAuditRuns, refetchInterval: 3000 });
  return <section className="space-y-4">
    <h2 className="text-lg font-semibold">Sources</h2>
    <div className="rounded border border-gray-200 p-4">
      <h3 className="font-medium">Current Vault session</h3>
      <p className="my-2 text-sm text-gray-500">Live collection uses the Vault connection and authentication configured in VaultLens.</p>
      <Link className="text-sm text-blue-700 underline" to="/security-audit/findings?collect=1">Collect and run audit</Link>
    </div>
    {runs.error && <p role="alert">Could not check running audits. Retry before importing a snapshot.</p>}
    <AuditImportUpload disabled={runs.isPending || !!runs.error || !!runs.data?.some(run => run.status === 'running')}
      onImported={id => {
        client.invalidateQueries({ queryKey: ['security-audit-runs'] });
        navigate(`/security-audit/findings?${new URLSearchParams({ run: id })}`);
      }} />
    <p className="text-sm text-gray-500">Imported snapshots are stored separately. Analyze them explicitly to produce findings.</p>
  </section>;
}
