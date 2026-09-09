import AuditFindings from '../components/AuditFindings';
import AuditRefreshDetails from '../components/AuditRefreshDetails';
import AuditRefreshPanel from '../components/AuditRefreshPanel';
import AuditResumeButton from '../components/AuditResumeButton';
import AuditImportDetails from '../components/AuditImportDetails';
import AuditPolicyUsage from '../components/AuditPolicyUsage';
import AuditRunDialog from '../components/AuditRunDialog';
import AuditExportButton from '../components/AuditExportButton';
import AuditDiffPanel from '../components/AuditDiffPanel';
import { Link, useSearchParams } from 'react-router-dom';
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  getSecurityAuditRuns,
  getSecurityAuditRun,
  startSecurityAudit,
  reanalyzeSecurityAudit,
} from '../lib/api';
export default function SecurityAuditPage() {
  const [recursiveNamespaces,setRecursiveNamespaces]=useState(false);
  const [namespace,setNamespace]=useState('');
  const [scopeText,setScopeText]=useState({namespaceFilters:'',policyFilters:'',authMountFilters:'',authTypeFilters:''});
  const [redactPolicySource,setRedactPolicySource]=useState(false);
  const [skipIdentity,setSkipIdentity]=useState(false);
  const patterns=(text:string)=>text.split('\n').map(value=>value.trim()).filter(Boolean);
  const controlDocuments={baselineYaml:'',exceptionsYaml:''};
  const [collectionOptions,setCollectionOptions]=useState({workers:10,requestsPerSecond:10,retries:3,retryBackoffMs:500,timeoutMs:30000,maxDurationMs:7200000,maxObjects:0});
  const [params, setParams] = useSearchParams();
  const collecting=params.get('collect')==='1';
  const closeCollection=()=>setParams(current=>{const next=new URLSearchParams(current);next.delete('collect');return next;},{replace:true});
  const selected = params.get('run') ?? '';
  const setSelected = (run: string) => setParams({ run });
  const [identityLimit, setIdentityLimit] = useState(100);
  const [identityFilter, setIdentityFilter] = useState('');
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
    mutationFn: () => startSecurityAudit({...collectionOptions,namespace,namespaceFilters:patterns(scopeText.namespaceFilters),policyFilters:patterns(scopeText.policyFilters),authMountFilters:patterns(scopeText.authMountFilters),authTypeFilters:patterns(scopeText.authTypeFilters),skipIdentity,redactPolicySource,recursiveNamespaces},controlDocuments),
    onSuccess: (result) => {
      setSelected(result.id);
      queryClient.invalidateQueries({ queryKey: ['security-audit-runs'] });
    },
  });
  const reanalyze=useMutation({mutationFn:()=>reanalyzeSecurityAudit(id,controlDocuments),onSuccess:result=>{
    setSelected(result.id);queryClient.invalidateQueries({queryKey:['security-audit-runs']});
  }});
  const running = runs.data?.some((r) => r.status === 'running');
  const issues = [
    ...(detail.data?.snapshot?.issues ?? []),
    ...(detail.data?.configuration?.issues ?? []),
  ];
  const identityAssignments = detail.data?.snapshot?.identity?.assignments.filter(a =>
    [a.subjectPath, a.policy, a.sourcePath].some(v => v.toLowerCase().includes(identityFilter.toLowerCase()))) ?? [];
  const error = runs.error || detail.error || start.error || reanalyze.error;
  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">
            Findings
          </h2>
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
          onClick={() => {start.reset();setParams(current=>{const next=new URLSearchParams(current);next.set('collect','1');return next;});}}
        >
          {running
            ? 'Audit running…'
            : start.isPending
              ? 'Starting…'
              : 'Run audit'}
        </button>
      </div>
      <AuditRunDialog open={collecting} onClose={closeCollection} onStart={()=>start.mutate()}
        busy={start.isPending} disabled={!!running||start.isPending||runs.isPending||!!runs.error}
        error={start.error?.message||runs.error?.message|| (running?'Another audit is running. Wait for it to finish.':undefined)}>
        <p className="rounded border bg-gray-50 p-3 text-sm">Source: current Vault connection. The latest saved checks and object exceptions will be applied.</p>
        <label className="mt-3 block">Vault namespace (empty = root)
          <input aria-label="Vault namespace" className="ml-2 rounded border p-2" disabled={!!running||start.isPending} value={namespace} onChange={event=>setNamespace(event.target.value)} />
        </label>
        <label className="mt-3 block"><input type="checkbox" checked={recursiveNamespaces} disabled={!!running||start.isPending} onChange={event=>setRecursiveNamespaces(event.target.checked)} /> Include child namespaces recursively</label>
      <details className="rounded border p-3 text-sm">
        <summary>Advanced collection settings</summary>
        <p className="mt-3 text-xs text-gray-500">Optional glob filters, one per line. Empty means all. Auth mount names omit the trailing slash.</p>
        <div className="mt-3 grid gap-3 lg:grid-cols-3">
          {(['namespaceFilters','policyFilters','authMountFilters','authTypeFilters'] as const).map(key=><label key={key}>
            {{namespaceFilters:'Namespace filters (root for root namespace)',policyFilters:'Policy filters',authMountFilters:'Auth mount filters',authTypeFilters:'Auth type filters'}[key]}
            <textarea aria-label={key} rows={3} className="mt-2 w-full rounded border p-2 font-mono text-xs" disabled={!!running||start.isPending}
              value={scopeText[key]} onChange={event=>setScopeText(current=>({...current,[key]:event.target.value}))} />
          </label>)}
        </div>
        <label className="mt-3 block"><input type="checkbox" checked={redactPolicySource} disabled={!!running||start.isPending} onChange={event=>setRedactPolicySource(event.target.checked)} /> Do not store full policy source</label>
        <p className="text-xs text-gray-500">Initial analysis uses the source in memory. Matched ACL blocks remain in findings; later offline analysis will have coverage gaps.</p>
        <label className="mt-3 block"><input type="checkbox" checked={skipIdentity} disabled={!!running||start.isPending} onChange={event=>setSkipIdentity(event.target.checked)} /> Skip Identity collection (reported as a coverage gap)</label>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          {([
            ['maxObjects','Maximum objects (0 = unlimited)',0,10000000,1],
            ['timeoutMs','Request timeout (ms)',1,86400000,1],
            ['maxDurationMs','Collection duration limit (ms)',1,86400000,1],
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
        <p className="text-xs text-gray-500">No secret values are collected. Missing permissions and unavailable data are reported as coverage gaps.</p>
      </AuditRunDialog>
      {error && (
        <p
          role="alert"
          className="rounded border border-red-200 bg-red-50 p-3 text-red-800"
        >
          {error.message}. Audit access requires root or vaultlens-admin.
        </p>
      )}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span>{detail.data ? `Selected run: ${new Date(detail.data.run.startedAt).toLocaleString()}` : 'Select a saved run or start an audit.'}</span>
          <Link className="text-blue-700 underline" to={`/security-audit/runs${id ? `?${new URLSearchParams({run:id})}` : ''}`}>View run history</Link>
        </div>
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
                  {detail.data.run.failureReason || 'This run did not finish and has no valid completed snapshot.'}
                </p>
              )}
              {detail.data.snapshot?.checkpoint && ['failed','interrupted'].includes(detail.data.run.status) && <p className="text-sm">
                Checkpoint retained from {detail.data.snapshot.checkpoint.savedAt}: {detail.data.snapshot.resources.length} resources. Collection did not finish.
              </p>}
              {detail.data.snapshot?.checkpoint && ['failed','interrupted'].includes(detail.data.run.status) && <AuditResumeButton key={`resume:${id}`} runId={id} disabled={!!running} controls={controlDocuments} onResumed={id=>{setSelected(id);queryClient.invalidateQueries({queryKey:['security-audit-runs']});}} />}
              {detail.data.run.status === 'running' && (
                <p className="text-sm text-gray-600">
                  {detail.data.run.progress ? `${detail.data.run.progress.phase} · namespace ${detail.data.run.progress.namespace || 'root'} · ${detail.data.run.progress.resources} resources · ${detail.data.run.progress.requests} requests` : 'Audit is running in the background. You can leave this page.'}
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
              {detail.data.snapshot?.analysisPerformed !== false && <AuditFindings key={id} detail={detail.data} />}
              {detail.data.snapshot && <AuditImportDetails key={`import:${id}`} snapshot={detail.data.snapshot} />}
              {detail.data.snapshot?.collection && <details className="rounded border p-3 text-sm">
                <summary>Collection parameters and metrics</summary>
                <pre className="mt-2 overflow-auto text-xs">{JSON.stringify(detail.data.snapshot.collection,null,2)}</pre>
              </details>}
              <div className="rounded border p-3 text-sm">
                <button className="rounded border px-3 py-2 disabled:opacity-50" disabled={!!running||reanalyze.isPending||!['collected','completed','partial'].includes(detail.data.run.status)}
                  onClick={()=>reanalyze.mutate()}>Analyze saved snapshot with current rules</button>
                <p className="mt-2 text-xs text-gray-500">Creates a new result with saved checks and object exceptions. Collection timestamps remain unchanged.</p>
                {detail.data.snapshot?.sourceRunId && <p className="mt-2 text-xs">Source run: {detail.data.snapshot.sourceRunId}</p>}
              </div>
              {detail.data.snapshot?.collection && ['collected','completed','partial'].includes(detail.data.run.status) && <AuditRefreshPanel key={`refresh:${id}`} runId={id} disabled={!!running} controls={controlDocuments} onRefreshed={id=>{setSelected(id);queryClient.invalidateQueries({queryKey:['security-audit-runs']});}} />}
              {detail.data.snapshot?.refresh && <AuditRefreshDetails key={`freshness:${id}`} snapshot={detail.data.snapshot} />}
              <AuditExportButton key={`export:${id}`} runId={id} />
              <AuditDiffPanel key={id} currentId={id} runs={runs.data ?? []} />
              {detail.data.snapshot && <AuditPolicyUsage key={`usage:${id}`} snapshot={detail.data.snapshot} />}
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
                          <td className="p-2">{assignment.namespace ? `${assignment.namespace}: ` : ''}{assignment.subjectPath}</td><td>{assignment.policy}</td>
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
            </>
          )}
        </section>
      </div>
    </div>
  );
}
