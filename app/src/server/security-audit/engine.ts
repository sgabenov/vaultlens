import type {
  AuditSnapshot,
  AuditFinding,
} from '../../shared/securityAudit.js';
export const ENGINE_VERSION = '1';
export const RULES = [
  { id: 'assignment.root', title: 'Root policy assigned to a principal' },
  { id: 'assignment.missing-policy', title: 'Assigned policy does not exist' },
  {
    id: 'approle.unbound-login',
    title: 'AppRole login has no SecretID or CIDR restriction',
  },
  {
    id: 'kubernetes.unbounded-subject',
    title: 'Kubernetes role accepts all service accounts and namespaces',
  },
];
const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];
export function analyze(snapshot: AuditSnapshot): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const policies = new Set(
    snapshot.resources
      .filter((r) => r.kind === 'policy')
      .map((r) => String(r.data.name)),
  );
  policies.add('root');
  for (const r of snapshot.resources) {
    if (!['role', 'entity', 'group'].includes(r.kind)) continue;
    const add = (
      ruleId: string,
      title: string,
      evidence: string,
      recommendation: string,
      severity: 'high' | 'medium' = 'high',
    ) =>
      findings.push({
        ruleId,
        severity,
        path: r.path,
        title,
        evidence,
        recommendation,
      });
    const assigned = [
      ...new Set([
        ...strings(r.data.token_policies),
        ...strings(r.data.policies),
      ]),
    ];
    if (assigned.includes('root'))
      add(
        'assignment.root',
        'Root policy assignment',
        'Assigned policies include root. This is a configuration finding, not proof that this auth method can issue a root token.',
        'Review the assignment and replace it with explicit least-privilege policies.',
      );
    if (snapshot.policiesComplete)
      for (const name of assigned) {
        if (!policies.has(name))
          add(
            'assignment.missing-policy',
            'Assigned policy is missing',
            `Policy ${name} was not found in the complete policy inventory.`,
            'Correct the policy name or restore the intended policy.',
            'medium',
          );
      }
    if (
      r.data.auth_type === 'approle' &&
      r.data.bind_secret_id === false &&
      strings(r.data.secret_id_bound_cidrs).length === 0 &&
      strings(r.data.token_bound_cidrs).length === 0
    ) {
      add(
        'approle.unbound-login',
        'AppRole login is not bound to a SecretID or CIDR',
        'bind_secret_id=false; no SecretID or token CIDR restrictions.',
        'Require SecretID authentication or define reviewed network restrictions.',
      );
    }
    if (
      r.data.auth_type === 'kubernetes' &&
      strings(r.data.bound_service_account_names).includes('*') &&
      strings(r.data.bound_service_account_namespaces).includes('*')
    ) {
      add(
        'kubernetes.unbounded-subject',
        'Kubernetes role accepts all service accounts and namespaces',
        'Both service-account and namespace bindings contain *.',
        'Bind this role to the service accounts and namespaces that need its policies.',
      );
    }
  }
  return findings.sort(
    (a, b) => a.path.localeCompare(b.path) || a.ruleId.localeCompare(b.ruleId),
  );
}
