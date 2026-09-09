import type { AuditFinding } from '../../shared/securityAudit';
import AuditDisclosureIcon from './AuditDisclosureIcon';

export default function AuditFindingReason({finding}:{finding:AuditFinding}) {
  let formatted=finding.evidence;
  let data:Record<string,unknown>={};
  try {
    const parsed:unknown=JSON.parse(finding.evidence);
    formatted=JSON.stringify(parsed,null,2);
    if(parsed&&typeof parsed==='object'&&!Array.isArray(parsed))data=parsed as Record<string,unknown>;
  } catch { /* Preserve historical plain-text evidence. */ }
  const path=typeof data.path==='string'?data.path:finding.policyPath;
  const capabilities=Array.isArray(data.capabilities)?data.capabilities.filter((value):value is string=>typeof value==='string'):[];
  const sudo=finding.ruleId==='POL-002'&&capabilities.includes('sudo');
  return <section aria-label="Why this was flagged" className="rounded-lg border border-slate-200 bg-slate-50 p-4">
    <h4 className="text-sm font-semibold text-slate-900">Why this was flagged</h4>
    <p className="mt-2 text-sm leading-relaxed text-slate-800">{sudo?'This policy grants the sudo capability on the path below.':finding.title}</p>
    {path&&<div className="mt-3"><p className="text-xs font-medium text-slate-500">Policy path</p><code className="mt-1 block break-all text-xs">{path}</code></div>}
    {!!capabilities.length&&<div className="mt-3"><p className="text-xs font-medium text-slate-500">Granted capabilities</p><ul className="mt-1 flex flex-wrap gap-1.5">{[...new Set(capabilities)].map(capability=><li key={capability} className={`rounded border px-2 py-0.5 font-mono text-xs ${sudo&&capability==='sudo'?'border-amber-300 bg-amber-100 font-semibold text-amber-900':'border-slate-200 bg-white text-slate-700'}`}>{capability}</li>)}</ul></div>}
    {sudo&&typeof data.known_root_protected_scope==='boolean'&&<p className="mt-3 text-xs leading-relaxed text-slate-600">{data.known_root_protected_scope?'The analyzer recognizes this path as a scope containing endpoints that may require sudo.':'The analyzer did not recognize this path as a scope requiring sudo. This does not establish that the policy is safe.'}</p>}
    <details className="mt-3 border-t border-slate-200 pt-3">
      <summary className="audit-disclosure-summary text-xs text-slate-600"><AuditDisclosureIcon level="detail"/><span>Technical details</span></summary>
      <pre className="mt-2 overflow-auto whitespace-pre-wrap break-words rounded bg-white p-3 text-xs">{formatted}</pre>
    </details>
  </section>;
}
