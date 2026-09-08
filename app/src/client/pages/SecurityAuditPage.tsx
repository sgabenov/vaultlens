import AuditExportButton from '../components/AuditExportButton';
import AuditDiffPanel from '../components/AuditDiffPanel';
import { Link } from 'react-router-dom';
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  getSecurityAuditRuns,
  getSecurityAuditRun,
  startSecurityAudit,
  reanalyzeSecurityAudit,
} from '../lib/api';
export default function SecurityAuditPage() {
  const [collectionOptions,setCollectionOptions]=useState({workers:10,requestsPerSecond:10,retries:3,retryBackoffMs:500,timeoutMs:30000,maxDurationMs:7200000});
  const [selected, setSelected] = useState('');
  const [identityLimit, setIdentityLimit] = useState(100);
  const [identityFilter, setIdentityFilter] = useState('');
  const [severity, setSeverity] = useState('all');
  const queryClient = useQueryClient();
  const runs = useQuery({
    queryKey: ['security-audit-runs'],
    queryFn: getSecurityAuditRuns,
    refetchInterval: 3000,
  });
  const id = selected || runs.data?.[0]?.id || '';
  const detail = useQuery({
    queryKey: ['security-audit-run', id],
    queryFn: () => getSecurityAuditRun(id),
    enabled: !!id,
    refetchInterval: (q) =>
      q.state.data?.run.status === 'running' ? 2000 : false,
  });
  const start = useMutation({
    mutationFn: () => startSecurityAudit(collectionOptions),
    onSuccess: (result) => {
      setSelected(result.id);
      queryClient.invalidateQueries({ queryKey: ['security-audit-runs'] });
    },
  });
  const reanalyze=useMutation({mutationFn:()=>reanalyzeSecurityAudit(id),onSuccess:result=>{
    setSelected(result.id);queryClient.invalidateQueries({queryKey:['security-audit-runs']});
  }});
  const running = runs.data?.some((r) => r.status === 'running');
  const findings =
    detail.data?.findings.filter(
      (f) => severity === 'all' || f.severity === severity,
    ) ?? [];
  const issues = [
    ...(detail.data?.snapshot?.issues ?? []),
    ...(detail.data?.configuration?.issues ?? []),
  ];
  const identityAssignments = detail.data?.snapshot?.identity?.assignments.filter(a =>
    [a.subjectPath, a.policy, a.sourcePath].some(v => v.toLowerCase().includes(identityFilter.toLowerCase()))) ?? [];
  const error = runs.error || detail.error || start.error || reanalyze.error;
  return (
    <div className="space-y-6">
      <Link
        to="/security-audit/rules"
        className="text-sm text-blue-700 underline"
      >
        Rules and configuration
      </Link>
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">
            Security Audit
          </h1>
          <p className="mt-2 text-sm text-gray-500">
            Collect a configuration snapshot and review policy assignments and
            authentication risks.
          </p>
        </div>
        <button
          className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          disabled={
            !!running || start.isPending || runs.isPending || !!runs.error
          }
          onClick={() => start.mutate()}
        >
          {running
            ? 'Audit running…'
            : start.isPending
              ? 'Starting…'
              : 'Run audit'}
        </button>
      </div>
      <details className="rounded border p-3 text-sm">
        <summary>Collection settings</summary>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          {([
            ['timeoutMs','Request timeout (ms)',1,86400000,1000],
            ['maxDurationMs','Collection duration limit (ms)',1,86400000,1000],
            ['workers','Concurrent workers',1,32,1],
            ['requestsPerSecond','Requests per second',0.1,1000,0.1],
            ['retries','Retries per request',0,10,1],
            ['retryBackoffMs','Initial retry delay (ms)',0,10000,100],
          ] as const).map(([key,label,min,max,step])=><label key={key}>{label}
            <input type="number" aria-label={label} min={min} max={max} step={step}
              className="ml-2 rounded border p-2" disabled={!!running||start.isPending}
              value={collectionOptions[key]} onChange={event=>setCollectionOptions(current=>({...current,[key]:Number(event.target.value)}))} />
          </label>)}
        </div>
      </details>
      <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-900">
        Read-only collection using your current Vault session. No secret values
        are collected. Rules use a saved configuration revision. Pending
        detectors are reported as coverage gaps; this assessment does not prove
        effective access.
      </div>
      {error && (
        <p
          role="alert"
          className="rounded border border-red-200 bg-red-50 p-3 text-red-800"
        >
          {error.message}. Audit access requires root or vaultlens-admin.
        </p>
      )}
      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
        <section className="space-y-3">
          <h2 className="font-semibold">Run history</h2>
          {runs.isPending && <p>Loading runs…</p>}
          {runs.data?.length === 0 && (
            <p className="text-sm text-gray-500">
              No snapshots yet. Run an audit to create the first one.
            </p>
          )}
          {runs.data?.map((run) => (
            <button
              key={run.id}
              onClick={() => setSelected(run.id)}
              className={`block w-full rounded-lg border p-3 text-left ${id === run.id ? 'border-blue-500 bg-blue-50' : 'border-gray-200 bg-white'}`}
            >
              <div className="text-sm font-medium">
                {new Date(run.startedAt).toLocaleString()}
              </div>
              <div className="mt-1 text-sm">
                {run.status} · {run.findingCount} findings
              </div>
              <div className="mt-1 truncate text-xs text-gray-500">
                {run.target}
              </div>
            </button>
          ))}
        </section>
        <section className="min-w-0 space-y-4">
          {detail.data && (
            <>
              <div className="grid grid-cols-3 gap-3">
                {[
                  ['Resources', detail.data.run.resourceCount],
                  ['Findings', detail.data.run.findingCount],
                  ['Coverage gaps', detail.data.run.issueCount],
                ].map(([label, count]) => (
                  <div
                    key={label}
                    className="rounded-lg border border-gray-200 bg-white p-4"
                  >
                    <div className="text-xs text-gray-500">{label}</div>
                    <div className="mt-1 text-2xl font-semibold">{count}</div>
                  </div>
                ))}
              </div>
              {['failed', 'interrupted'].includes(detail.data.run.status) && (
                <p role="alert" className="text-red-700">
                  This run did not finish. Start a new audit; it has no valid
                  completed snapshot.
                </p>
              )}
              {detail.data.run.status === 'running' && (
                <p className="text-sm text-gray-600">
                  Collecting configuration in the background. You can leave this
                  page.
                </p>
              )}
              {!!issues.length && (
                <details
                  className="rounded-lg border border-amber-300 bg-amber-50 p-4"
                  open
                >
                  <summary className="font-medium text-amber-900">
                    Incomplete coverage — unavailable data is not a passing
                    check
                  </summary>
                  <ul className="mt-2 space-y-1 text-sm">
                    {issues.map((issue, i) => (
                      <li key={i}>
                        <code>{issue.path}</code>: {issue.reason}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
              <div className="flex items-center justify-between">
                <h2 className="font-semibold">Findings</h2>
                <select
                  aria-label="Filter severity"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  className="rounded border border-gray-300 p-2 text-sm"
                >
                  <option value="all">All severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
              {detail.data.snapshot?.controls && <details className="rounded border p-3 text-sm">
                <summary>Baseline and exceptions · applied {detail.data.snapshot.controls.appliedOn}</summary>
                <p className="my-2">{detail.data.snapshot.controls.states.filter(s=>s.gate).length} findings count toward the severity gate; {detail.data.snapshot.controls.states.filter(s=>s.suppressed).length} have active exceptions.</p>
                <p>Historical evaluation: expiration is assessed on the application date. Apply controls explicitly during a new analysis to assess them today.</p>
                <pre className="mt-2 overflow-auto text-xs">{JSON.stringify(detail.data.snapshot.controls,null,2)}</pre>
              </details>}
              {detail.data.snapshot?.collection && <details className="rounded border p-3 text-sm">
                <summary>Collection parameters and metrics</summary>
                <pre className="mt-2 overflow-auto text-xs">{JSON.stringify(detail.data.snapshot.collection,null,2)}</pre>
              </details>}
              <div className="rounded border p-3 text-sm">
                <button className="rounded border px-3 py-2 disabled:opacity-50" disabled={!!running||reanalyze.isPending}
                  onClick={()=>reanalyze.mutate()}>Analyze saved snapshot with current rules</button>
                <p className="mt-2 text-xs text-gray-500">Creates a new result with current rules and no baseline or exceptions. Collection timestamps remain unchanged.</p>
                {detail.data.snapshot?.sourceRunId && <p className="mt-2 text-xs">Source run: {detail.data.snapshot.sourceRunId}</p>}
              </div>
              <AuditExportButton key={`export:${id}`} runId={id} />
              <AuditDiffPanel key={id} currentId={id} runs={runs.data ?? []} />
              {detail.data.snapshot?.identity && (
                <details className="rounded border p-3 text-sm">
                  <summary>Identity policy assignments · {detail.data.snapshot.identity.assignments.length}</summary>
                  <input aria-label="Filter Identity assignments" placeholder="Filter entity, group or policy"
                    className="my-3 w-full rounded border p-2" value={identityFilter}
                    onChange={event => { setIdentityFilter(event.target.value); setIdentityLimit(100); }} />
                  <p className="mb-2 text-xs text-gray-500">Showing {Math.min(identityLimit, identityAssignments.length)} of {identityAssignments.length} matches. Group inheritance does not prove access through an auth role.</p>
                  <div className="overflow-auto">
                    <table className="w-full text-left text-xs">
                      <thead><tr><th>Subject</th><th>Policy</th><th>Assignment</th><th>Source</th></tr></thead>
                      <tbody>{identityAssignments.slice(0, identityLimit).map((assignment, index) => (
                        <tr key={index} className="border-t">
                          <td className="p-2">{assignment.subjectPath}</td><td>{assignment.policy}</td>
                          <td>{assignment.relationship}</td><td>{assignment.sourcePath}</td>
                        </tr>
                      ))}</tbody>
                    </table>
                    {identityAssignments.length > identityLimit && (
                      <button className="mt-3 rounded border px-3 py-2" onClick={() => setIdentityLimit(limit => limit + 100)}>Show 100 more assignments</button>
                    )}
                  </div>
                </details>
              )}
              {detail.data.configuration && (
                <details className="rounded border p-3 text-sm">
                  <summary>
                    Configuration revision {detail.data.configuration.revision}{' '}
                    · engine {detail.data.configuration.engineVersion}
                  </summary>
                  <pre className="mt-2 overflow-auto text-xs">
                    {detail.data.configuration.configYaml}
                  </pre>
                </details>
              )}
              {detail.data.snapshot?.analysisPerformed === false && <p className="rounded border p-3 text-sm">
                Configuration collected. Audit rules have not been run for this snapshot. Analyze this saved snapshot to evaluate it.
              </p>}
              {detail.data.snapshot && detail.data.snapshot.analysisPerformed !== false && findings.length === 0 && (
                <p className="text-sm text-gray-500">
                  No findings match this filter within the implemented checks.
                  This is not a clean bill of health for the cluster.
                </p>
              )}
              {findings.map((finding, i) => (
                <article
                  key={i}
                  className="rounded-lg border border-gray-200 bg-white p-4"
                >
                  <div className="flex gap-2">
                    <span
                      className={`rounded px-2 py-1 text-xs font-semibold ${['critical', 'high'].includes(finding.severity) ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800'}`}
                    >
                      {finding.severity}
                    </span>
                    <h3 className="font-medium">{finding.title}</h3>
                  </div>
                  <p className="mt-2 break-all font-mono text-xs text-gray-600">
                    {finding.path}
                  </p>
                  <p className="mt-3 text-sm">{finding.evidence}</p>
                  {!!finding.relatedObjects?.length && (
                    <details className="mt-3 rounded border p-3 text-sm">
                      <summary>Related resources</summary>
                      <ul className="mt-2 space-y-1">
                        {finding.relatedObjects.map(object => (
                          <li key={`${object.kind}:${object.path}`} className="break-all font-mono text-xs">
                            {object.path}
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                  {finding.matchedBlock && (
                    <details className="mt-3 rounded border p-3 text-sm">
                      <summary>
                        Matched policy block · line {finding.line}
                      </summary>
                      <pre className="mt-2 overflow-auto whitespace-pre-wrap text-xs">
                        {finding.matchedBlock}
                      </pre>
                    </details>
                  )}
                  <p className="mt-2 text-sm text-gray-600">
                    {finding.recommendation}
                  </p>
                  <p className="mt-3 text-xs text-gray-400">{finding.ruleId}</p>
                </article>
              ))}
            </>
          )}
        </section>
      </div>
    </div>
  );
}
