import { useAuditDraft } from '../components/AuditDraftContext';
import AuditListParameters from '../components/AuditListParameters';
import AuditObjectExceptions from '../components/AuditObjectExceptions';
import { useState } from 'react';
import { parseDocument } from 'yaml';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getAuditRules, saveAuditRules } from '../lib/api';
import { SEVERITIES, type RuleView } from '../../shared/auditRules';
import { CHECK_GROUPS, checkGroup, type CheckGroup } from '../../shared/auditCheckGroups';

const parameters: {group:CheckGroup; section:string; key:string; label:string; fallback:string|number|boolean}[] = [
  {group:'AppRole',section:'approle',key:'secret_id_ttl_warning',label:'SecretID TTL warning',fallback:'24h'},
  {group:'AppRole',section:'approle',key:'secret_id_num_uses_warning',label:'SecretID use-count warning',fallback:100},
  {group:'AppRole',section:'approle',key:'require_cidr_for_privileged_roles',label:'Require CIDR restrictions for privileged roles',fallback:true},
];
const ttlParameters = [
  ['token_ttl_warning','Token TTL warning','8h'],['token_ttl_high','Token TTL high-risk threshold','24h'],
  ['token_max_ttl_warning','Token maximum TTL warning','24h'],['token_max_ttl_high','Token maximum TTL high-risk threshold','72h'],
] as const;

export default function AuditRulesPage() {
  const client=useQueryClient();
  const query=useQuery({queryKey:['audit-rules'],queryFn:getAuditRules});
  const {draft,setDraft,group,setGroup,selected,setSelected,saving,setSaving,editorVersion,discard}=useAuditDraft();
  const [message,setMessage]=useState('');
  const save=useMutation({mutationFn:saveAuditRules,onMutate:()=>setSaving(true),onSettled:()=>setSaving(false),onSuccess:data=>{
    client.setQueryData(['audit-rules'],data);setDraft(null);setMessage(`Settings revision ${data.settings.revision} saved. Existing runs are unchanged.`);
  }});
  const settings=draft??query.data?.settings;
  const document=settings?parseDocument(settings.configYaml):null;
  const value=(path:string[],fallback:unknown)=>document?.getIn(path)??fallback;
  const rules=query.data?.catalog.filter(rule=>rule.source==='builtin')??[];
  const inGroup=rules.filter(rule=>checkGroup(rule)===group);
  const chosen=inGroup.find(rule=>rule.id===selected)??inGroup[0];
  const active=(rule:RuleView)=>Boolean(value(['rules',rule.id,'enabled'],rule.active));
  const severity=(rule:RuleView)=>String(value(['rules',rule.id,'severity'],rule.effectiveSeverity));
  function update(changes:{path:string[];value:unknown}[]) {
    if(!settings||!document||saving)return;
    for(const change of changes)document.setIn(change.path,change.value);
    setDraft({...settings,configYaml:document.toString()});setMessage('');
  }
  const legacy=query.data?.catalog.filter(rule=>rule.source==='custom')??[];
  function persist() {
    if(!settings||!document)return;
    // Keep historical definitions readable, but the managed UI only runs built-in checks.
    for(const rule of legacy)document.setIn(['rules',rule.id,'enabled'],false);
    save.mutate({...settings,configYaml:document.toString()});
  }
  const error=save.error as {response?:{data?:{error?:string}};message?:string}|null;
  return <section className="space-y-5">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 className="text-lg font-semibold">Checks</h2><p className="mt-1 text-sm text-gray-500">Built-in checks for the current Vault. Changes apply to new analyses.</p></div>
      <div className="flex gap-2">{draft&&<button disabled={saving} className="rounded border px-3 py-2 text-sm disabled:opacity-50" onClick={()=>{discard();save.reset();setMessage('Unsaved changes discarded.');}}>Discard changes</button>}<button className="rounded bg-blue-600 px-4 py-2 text-sm text-white disabled:opacity-50" disabled={!settings||saving||(!draft&&!legacy.some(rule=>rule.active))} onClick={persist}>{saving?'Saving…':'Save changes'}</button></div>
    </div>
    {query.isPending&&<p>Loading checks…</p>}
    {query.error&&<p role="alert">Could not load check settings. Administrator access is required.</p>}
    {error&&<p role="alert" className="text-sm text-red-700">{error.response?.data?.error??error.message}. Your unsaved changes are retained.</p>}
    {message&&<p role="status" className="text-sm text-green-800">{message}</p>}
    {settings&&<>
      <p className="text-sm text-gray-500">Revision {settings.revision} {draft?'· Unsaved changes':''} · {rules.filter(active).length} of {rules.length} built-in checks enabled</p>
      {draft&&<p className="text-xs text-gray-500">Your draft is retained when switching audit tabs. Save before leaving Security Audit or reloading the page.</p>}
      {draft&&query.data&&draft.revision!==query.data.settings.revision&&<p role="alert" className="text-sm text-amber-800">Saved settings changed since this draft began. Your draft is retained; discard it to load the current revision. Saving cannot overwrite a newer revision.</p>}
      {!!legacy.length&&<p className="rounded border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">This workspace has {legacy.length} legacy custom definitions. Saving these settings disables them for future analyses; historical runs retain their original definitions.</p>}
      <div className="flex flex-wrap gap-2" aria-label="Check categories">{CHECK_GROUPS.map(category=>{
        const members=rules.filter(rule=>checkGroup(rule)===category);
        return <button key={category} aria-pressed={category===group} onClick={()=>{setGroup(category);setSelected('');}} className={`rounded border px-3 py-2 text-sm ${category===group?'border-blue-600 bg-blue-50 text-blue-700':'border-gray-200'}`}>{category} <span className="ml-2 text-xs">{members.filter(active).length}/{members.length}</span></button>;
      })}</div>
      {!inGroup.length?<p className="rounded border p-4 text-sm text-gray-500">No dedicated built-in checks in this category yet. Collection of these objects does not imply they have passed a check.</p>:<>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={inGroup.every(active)} disabled={saving} onChange={event=>update(inGroup.map(rule=>({path:['rules',rule.id,'enabled'],value:event.target.checked})))} />Enable all {group} checks</label>
        <div className="grid gap-5 lg:grid-cols-[minmax(220px,1fr)_minmax(280px,1.4fr)]">
          <div className="divide-y rounded border">{inGroup.map(rule=><button key={rule.id} onClick={()=>setSelected(rule.id)} aria-pressed={rule.id===chosen?.id} className={`block w-full p-4 text-left ${rule.id===chosen?.id?'bg-blue-50':''}`}>
            <span className="text-xs text-gray-500">{rule.id} · {active(rule)?'Enabled':'Disabled'} · {severity(rule)}</span><strong className="mt-1 block text-sm font-medium">{rule.title}</strong>
          </button>)}</div>
          {chosen&&<div className="space-y-4 rounded border p-5">
            <div><span className="text-xs text-gray-500">Built-in · {chosen.status}</span><h3 className="mt-1 font-semibold">{chosen.title}</h3></div>
            <p className="text-sm text-gray-600">{chosen.description}</p>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={saving} checked={active(chosen)} onChange={event=>update([{path:['rules',chosen.id,'enabled'],value:event.target.checked}])} />Enable this check</label>
            <label className="block text-sm">Severity<select aria-label="Check severity" className="mt-2 block rounded border p-2" disabled={saving} value={severity(chosen)} onChange={event=>update([{path:['rules',chosen.id,'severity'],value:event.target.value}])}>{SEVERITIES.map(level=><option key={level} value={level}>{level}</option>)}</select></label>
            <p className="text-xs text-gray-500">Default: {chosen.severity}. Selecting a severity creates an explicit override for this check.</p>
            <h4 className="text-sm font-medium">Recommendation</h4><p className="text-sm text-gray-600">{chosen.remediation}</p>
            {!chosen.supported&&<p className="text-sm text-amber-800">This detector is unavailable. Enabling it produces a coverage gap.</p>}
          </div>}
        </div>
      </>}
      {!!parameters.filter(p=>p.group===group).length&&<details className="rounded border p-4"><summary className="cursor-pointer text-sm font-medium">{group} parameters</summary><div className="mt-3 space-y-3">{parameters.filter(p=>p.group===group).map(p=><label key={p.key} className="block text-sm">{p.label}{typeof p.fallback==='boolean'?<input className="ml-2" type="checkbox" disabled={saving} checked={Boolean(value([p.section,p.key],p.fallback))} onChange={event=>update([{path:[p.section,p.key],value:event.target.checked}])}/>:<input className="ml-2 rounded border p-2" disabled={saving} type={typeof p.fallback==='number'?'number':'text'} min={0} value={String(value([p.section,p.key],p.fallback))} onChange={event=>update([{path:[p.section,p.key],value:typeof p.fallback==='number'?Number(event.target.value):event.target.value}])}/>}</label>)}</div></details>}
      <details className="rounded border p-4"><summary className="cursor-pointer text-sm font-medium">Shared token lifetime thresholds</summary><p className="mt-2 text-xs text-gray-500">These thresholds apply to every detector that uses token lifetime limits. Durations accept seconds or values such as 8h and 1d.</p><div className="mt-3 grid gap-3 sm:grid-cols-2">{ttlParameters.map(([key,label,fallback])=><label key={key} className="text-sm">{label}<input className="mt-1 block w-full rounded border p-2" disabled={saving} value={String(value(['thresholds',key],fallback))} onChange={event=>update([{path:['thresholds',key],value:event.target.value}])}/></label>)}</div></details>
      <AuditListParameters key={`${settings.revision}:${group}:${editorVersion}`} group={group} configuration={document?.toJS()??{}} disabled={saving} onChange={update} />
      <AuditObjectExceptions />
    </>}
  </section>;
}
