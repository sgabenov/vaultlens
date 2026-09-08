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
  ruleId: string;
  severity: 'high' | 'medium';
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
}
