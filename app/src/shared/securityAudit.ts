export interface AuditResource {
  kind: string;
  path: string;
  data: Record<string, unknown>;
}
export interface AuditIssue {
  path: string;
  reason: string;
}
export interface IdentityAnalysis {
  assignments: {subjectPath:string; subjectKind:string; policy:string; relationship:'assigned'|'inherited'; sourcePath:string}[];
  issues: AuditIssue[];
  groupCount: number;
  entityCount: number;
}
export interface AuditSnapshot {
  analysisPerformed?: boolean;
  sourceRunId?: string;
  collection?: {
    workers?: number;
    requestPolicy: {retries:number;requestsPerSecond:number;retryBackoffMs:number};
    metrics: {requests:number;retries:number;rateWaitMs:number;retryWaitMs:number};
  };
  identity?: IdentityAnalysis;
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
  status: 'running' | 'collected' | 'completed' | 'partial' | 'failed' | 'interrupted';
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

export interface AuditDiff {
  oldRunId: string;
  newRunId: string;
  target: string;
  warnings: string[];
  statistics: Record<string, Record<string, number>>;
  changes: Record<string, {change: 'added'|'removed'|'changed'|'unchanged'; old?: unknown; new?: unknown}[]>;
}
