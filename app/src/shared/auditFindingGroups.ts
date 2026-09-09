import { SEVERITIES } from './auditRules.js';
import type { AuditFinding } from './securityAudit.js';
export type FindingGrouping = 'check' | 'object' | 'none';
export interface FindingGroup { key:string; title:string; severity:AuditFinding['severity']; findings:AuditFinding[] }
export function groupAuditFindings(findings:AuditFinding[], mode:FindingGrouping):FindingGroup[] {
  const groups=new Map<string,FindingGroup>();
  findings.forEach((finding,index)=>{
    const key=mode==='check'?finding.ruleId:mode==='object'?JSON.stringify([finding.namespace??'',finding.path]):String(index);
    const title=mode==='check'?finding.title:mode==='object'?`${finding.namespace||'root'} · ${finding.path}`:finding.title;
    const group=groups.get(key);
    if(!group)groups.set(key,{key,title,severity:finding.severity,findings:[finding]});
    else {group.findings.push(finding);if(SEVERITIES.indexOf(finding.severity)<SEVERITIES.indexOf(group.severity))group.severity=finding.severity;}
  });
  return [...groups.values()].sort((a,b)=>SEVERITIES.indexOf(a.severity)-SEVERITIES.indexOf(b.severity)||b.findings.length-a.findings.length||a.key.localeCompare(b.key));
}
