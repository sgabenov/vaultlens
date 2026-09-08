import { createHash } from 'node:crypto';
import { parseDocument } from 'yaml';
import { canonical } from './diff.js';
import type { AuditDetail, AuditFinding } from '../../shared/securityAudit.js';
import type { RunConfiguration } from '../../shared/auditRules.js';

export interface AuditBaseline {
  version: 1;
  tool: 'vaultlens';
  target: string;
  source_scan_id: string;
  config_hash: string;
  engine_version: string;
  fingerprints: string[];
}
export function findingFingerprint(finding: AuditFinding): string {
  let evidence:unknown=finding.evidence;
  try { evidence=JSON.parse(finding.evidence); } catch { /* Legacy plain text. */ }
  return createHash('sha256').update(canonical({rule:finding.ruleId,path:finding.path,
    policy_path:finding.policyPath??null,evidence})).digest('hex');
}
export function createBaseline(detail: AuditDetail): AuditBaseline {
  if(!detail.snapshot || !detail.configuration || !['completed','partial'].includes(detail.run.status))
    throw new Error('Baseline requires a finished, analyzed snapshot');
  return {version:1,tool:'vaultlens',target:detail.snapshot.target,source_scan_id:detail.run.id,
    config_hash:detail.configuration.fingerprint,engine_version:detail.configuration.engineVersion,
    fingerprints:[...new Set(detail.findings.map(findingFingerprint))].sort()};
}
export function parseBaseline(source:string): AuditBaseline {
  if(Buffer.byteLength(source)>1024*1024) throw new Error('Baseline exceeds 1 MiB');
  const document=parseDocument(source,{uniqueKeys:true});
  if(document.errors.length) throw new Error('Invalid baseline YAML');
  const raw=document.toJS({maxAliasCount:0});
  if(!raw || typeof raw!=='object' || Array.isArray(raw) || raw.version!==1 || raw.tool!=='vaultlens')
    throw new Error('Expected a version 1 VaultLens baseline');
  const allowed=['version','tool','target','source_scan_id','config_hash','engine_version','fingerprints'];
  if(Object.keys(raw).some(k=>!allowed.includes(k))) throw new Error('Unknown baseline field');
  for(const key of ['target','source_scan_id','config_hash','engine_version'])
    if(typeof raw[key]!=='string' || !raw[key]) throw new Error(`Baseline requires ${key}`);
  if(!Array.isArray(raw.fingerprints) || raw.fingerprints.some((v:unknown)=>typeof v!=='string'||!/^[a-f0-9]{64}$/.test(v)))
    throw new Error('Invalid baseline fingerprints');
  return raw as AuditBaseline;
}
export function applyBaseline(findings:AuditFinding[], configuration:RunConfiguration, target:string, baseline?:AuditBaseline) {
  if(baseline && (baseline.target!==target || baseline.config_hash!==configuration.fingerprint || baseline.engine_version!==configuration.engineVersion))
    throw new Error('Baseline target, configuration or engine version is incompatible');
  const known=new Set(baseline?.fingerprints??[]), current=new Set<string>();
  const states=findings.map(finding=>{
    const fingerprint=findingFingerprint(finding);current.add(fingerprint);
    const baselineStatus=baseline ? known.has(fingerprint)?'unchanged':'new' : null;
    return {fingerprint,baselineStatus,gate:baselineStatus!=='unchanged'};
  });
  return {states,absentFingerprints:[...known].filter(f=>!current.has(f)).sort()};
}
