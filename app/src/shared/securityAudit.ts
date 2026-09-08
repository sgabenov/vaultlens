export interface AuditResource {
  kind: string;
  path: string;
  data: Record<string, unknown>;
}
export interface AuditIssue {
  path: string;
  reason: string;
}
export interface AuditSnapshot {
  version: 1;
  target: string;
  startedAt: string;
  finishedAt: string;
  resources: AuditResource[];
  issues: AuditIssue[];
  policiesComplete: boolean;
}
export interface AuditFinding {
  relatedObjects?: { kind: string; path: string; name: string }[];
  policyPath?: string;
  line?: number;
  matchedBlock?: string;
  attributes?: Record<string, unknown>;
  ruleId: string;
  severity: import('./auditRules.js').Severity;
  path: string;
  title: string;
  evidence: string;
  recommendation: string;
}
export interface AuditRun {
  id: string;
  target: string;
  startedAt: string;
  finishedAt: string | null;
  status: 'running' | 'completed' | 'partial' | 'failed' | 'interrupted';
  resourceCount: number;
  issueCount: number;
  findingCount: number;
}
export interface AuditDetail {
  run: AuditRun;
  snapshot: AuditSnapshot | null;
  findings: AuditFinding[];
  configuration?: import('./auditRules.js').RunConfiguration | null;
}
