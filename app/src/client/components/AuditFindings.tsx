import AuditDisclosureIcon from './AuditDisclosureIcon';
import AuditPolicyAssignments from './AuditPolicyAssignments';
import { policyUsage, type PolicyUsage } from '../../shared/policyUsage';
import AuditExceptionForm from './AuditExceptionForm';
import { useMemo, useState } from 'react';
import { SEVERITIES } from '../../shared/auditRules';
import { CHECK_GROUPS, checkGroup } from '../../shared/auditCheckGroups';
import { groupAuditFindings, type FindingGrouping } from '../../shared/auditFindingGroups';
import type { AuditDetail, AuditFinding, AuditControls } from '../../shared/securityAudit';

function Pager({page,total,size,onChange}:{page:number;total:number;size:number;onChange:(page:number)=>void}) {
  return <div className="flex flex-wrap items-center justify-end gap-3 py-3 text-xs text-gray-600">
    <span>{total?(page-1)*size+1:0}–{Math.min(page*size,total)} of {total}</span>
    <button className="rounded border px-2 py-1 disabled:opacity-40" disabled={page<=1} onClick={()=>onChange(page-1)}>Previous</button>
    <button className="rounded border px-2 py-1 disabled:opacity-40" disabled={page*size>=total} onClick={()=>onChange(page+1)}>Next</button>
  </div>;
}
type FindingControl = AuditControls['states'][number] | null;
function Evidence({finding,control,usage}:{finding:AuditFinding;control:FindingControl;usage?:PolicyUsage}) {
  let evidence=finding.evidence;
  try {evidence=JSON.stringify(JSON.parse(evidence),null,2);} catch { /* Historical plain text. */ }
  return <div className="space-y-3 py-3 text-sm">
    <p className="text-gray-500">{finding.ruleId} · {finding.namespace||'root'} · {finding.severity}</p>
    <pre className="overflow-auto whitespace-pre-wrap break-words rounded bg-gray-50 p-3 text-xs">{evidence}</pre>
    {finding.matchedBlock&&<details><summary className="audit-disclosure-summary"><AuditDisclosureIcon level="detail"/><span>Matched policy block{finding.line?` · line ${finding.line}`:''}</span></summary><pre className="mt-2 overflow-auto whitespace-pre-wrap break-words text-xs">{finding.matchedBlock}</pre></details>}
    {usage&&<AuditPolicyAssignments usage={usage}/>}
    {!!finding.relatedObjects?.length&&<details><summary className="audit-disclosure-summary"><AuditDisclosureIcon level="detail"/><span>Related resources · {finding.relatedObjects.length}</span></summary><ul>{finding.relatedObjects.map((object,index)=><li key={index} className="mt-1 break-all font-mono text-xs">{object.kind} · {object.path}</li>)}</ul></details>}
    <p>{finding.recommendation}</p>
    {control?.exception && <div className="rounded border border-blue-200 bg-blue-50 p-3">
      <h4 className="font-medium">Exception applied to this run</h4>
      <p>{control.exception.reason}</p><p className="mt-1 text-xs">Owner: {control.exception.owner} · Expires: {control.exception.expires}</p>
      <p className="mt-1 break-all text-xs">{control.exception.id} · {control.exception.object_path}</p>
    </div>}
  </div>;
}
function FindingRows({findings,size,controls,statusOf,detail,usages}:{usages:Map<string,PolicyUsage>;detail:AuditDetail;findings:AuditFinding[];size:number;controls:Map<AuditFinding,FindingControl>;statusOf:(finding:AuditFinding)=>string}) {
  const [requested,setPage]=useState(1),page=Math.min(requested,Math.max(1,Math.ceil(findings.length/size)));
  return <div className="px-4">
    {findings.slice((page-1)*size,page*size).map((finding,index)=><details key={`${page}:${index}`} className="border-t py-3">
      <summary className="audit-disclosure-summary text-sm"><AuditDisclosureIcon level="finding"/><span className="min-w-0"><span className="mr-2 text-xs font-medium">{finding.severity}</span><span className="break-all font-mono text-xs">{finding.namespace||'root'} · {finding.path}</span><span className="ml-2 text-xs text-gray-500">{finding.ruleId} · {statusOf(finding)}</span></span></summary>
      <Evidence finding={finding} control={controls.get(finding)??null} usage={usages.get(JSON.stringify([finding.namespace??'',finding.path]))}/>
      {['completed','partial'].includes(detail.run.status)&&<AuditExceptionForm runId={detail.run.id} index={detail.findings.indexOf(finding)} finding={finding}/>}
    </details>)}
    <Pager page={page} total={findings.length} size={size} onChange={setPage}/>
  </div>;
}
export default function AuditFindings({detail}:{detail:AuditDetail}) {
  const usages=useMemo(()=>{
    const result=new Map<string,PolicyUsage>();
    if(!detail.snapshot)return result;
    const byName=new Map(policyUsage(detail.snapshot).map(row=>[JSON.stringify([row.namespace,row.name]),row]));
    for(const resource of detail.snapshot.resources){
      if(resource.kind!=='policy'||typeof resource.data.name!=='string')continue;
      const usage=byName.get(JSON.stringify([resource.namespace??'',resource.data.name]));
      if(usage)result.set(JSON.stringify([resource.namespace??'',resource.path]),usage);
    }
    return result;
  },[detail.snapshot]);
  const [status,setStatus]=useState('all');
  const controls=useMemo(()=>new Map(detail.findings.map((finding,index)=>[finding,detail.findingControls?.[index]??null])),[detail.findings,detail.findingControls]);
  const statusOf=(finding:AuditFinding)=>controls.get(finding)?.suppressed?'Excluded':detail.snapshot?.controls&&!controls.get(finding)?'Unknown':'Open';
  const [query,setQuery]=useState(''),[severity,setSeverity]=useState('all'),[namespace,setNamespace]=useState('all'),[category,setCategory]=useState('all');
  const [grouping,setGrouping]=useState<FindingGrouping>('check'),[size,setSize]=useState(10),[requested,setPage]=useState(1),[expanded,setExpanded]=useState<string|null>(null);
  const ruleCategories=useMemo(()=>new Map(detail.configuration?.catalog?.map(rule=>[rule.id,rule.source==='builtin'?checkGroup(rule):'Legacy custom'])??[]),[detail.configuration]);
  const namespaces=useMemo(()=>[...new Set(detail.findings.map(f=>f.namespace??''))].sort(),[detail.findings]);
  const matched=useMemo(()=>detail.findings.filter(f=>(status==='all'||statusOf(f)===status)&&(severity==='all'||f.severity===severity)&&(namespace==='all'||(f.namespace??'')===namespace)&&(category==='all'||ruleCategories.get(f.ruleId)===category)&&[f.path,f.title,f.ruleId,f.namespace??''].some(text=>text.toLowerCase().includes(query.toLowerCase()))),[detail.findings,severity,namespace,category,query,ruleCategories,status,controls,detail.snapshot]);
  const groups=useMemo(()=>groupAuditFindings(matched,grouping),[matched,grouping]);
  const page=Math.min(requested,Math.max(1,Math.ceil(groups.length/size)));
  function reset(){setPage(1);setExpanded(null);}
  const filters=[{label:'Status',value:status,change:setStatus,options:['Open','Excluded','Unknown'].map(x=>[x,x])},{label:'Severity',value:severity,change:setSeverity,options:SEVERITIES.map(x=>[x,x])},{label:'Namespace',value:namespace,change:setNamespace,options:namespaces.map(x=>[x,x||'root'])},{label:'Category',value:category,change:setCategory,options:[...CHECK_GROUPS,'Legacy custom'].map(x=>[x,x])}];
  return <section className="space-y-4" aria-label="Audit findings">
    <div className="flex flex-wrap items-end gap-3">
      <label className="min-w-48 flex-1 text-sm">Search<input className="mt-1 block w-full rounded border p-2" placeholder="Check, object path or namespace" value={query} onChange={event=>{setQuery(event.target.value);reset();}}/></label>
      <label className="text-sm">Group by<select className="mt-1 block rounded border p-2" value={grouping} onChange={event=>{setGrouping(event.target.value as FindingGrouping);reset();}}><option value="check">Check</option><option value="object">Object</option><option value="none">No grouping</option></select></label>
      {filters.map(filter=><label key={filter.label} className="text-sm">{filter.label}<select className="mt-1 block max-w-full rounded border p-2" value={filter.value} onChange={event=>{filter.change(event.target.value);reset();}}><option value="all">All</option>{filter.options.map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>)}
    </div>
    {detail.snapshot?.controls&&<p className="text-xs text-gray-500">Exception status was evaluated on {detail.snapshot.controls.appliedOn}. Reanalyze to evaluate current expiry; historical results are unchanged.</p>}
    <div className="flex flex-wrap items-center justify-between gap-3 text-sm"><p>{matched.length.toLocaleString()} of {detail.findings.length.toLocaleString()} findings{grouping!=='none'?` · ${groups.length} groups`:''}</p><label>Per page<select className="ml-2 rounded border p-1" value={size} onChange={event=>{setSize(Number(event.target.value));reset();}}>{[10,25,50].map(n=><option key={n}>{n}</option>)}</select></label></div>
    {!matched.length&&<p className="rounded border p-4 text-sm text-gray-500">No findings match these filters. Review collection and analysis gaps before drawing conclusions.</p>}
    <div className="divide-y rounded border">{groups.slice((page-1)*size,page*size).map(group=><div key={group.key}>
      <button className="flex w-full items-center gap-3 p-4 text-left" aria-expanded={expanded===group.key} onClick={()=>setExpanded(expanded===group.key?null:group.key)}>
        <AuditDisclosureIcon level="group"/><span className={`rounded px-2 py-1 text-xs ${['critical','high'].includes(group.severity)?'bg-red-50 text-red-800':'bg-amber-50 text-amber-900'}`}>{group.severity}</span>
        <span className="min-w-0 flex-1 break-words text-sm font-medium">{group.title}<span className="mt-1 block text-xs font-normal text-gray-500">{grouping==='check'?group.key:''}</span></span><span className="text-sm">{group.findings.length}</span>
      </button>
      {expanded===group.key&&<FindingRows key={`${group.key}:${query}:${severity}:${namespace}:${category}:${status}:${size}`} findings={group.findings} size={size} controls={controls} statusOf={statusOf} detail={detail} usages={usages}/>}
    </div>)}</div>
    <Pager page={page} total={groups.length} size={size} onChange={next=>{setPage(next);setExpanded(null);}}/>
  </section>;
}
