import { AUTH_DETECTORS, evaluateAuth } from './authDetectors.js';
import {
  catalog,
  parseConfig,
  settingsFingerprint,
  SUPPORTED_DETECTORS,
} from './catalog.js';
import type {
  RuleSettings,
  RunConfiguration,
} from '../../shared/auditRules.js';
import type {
  AuditSnapshot,
  AuditFinding,
} from '../../shared/securityAudit.js';
export const ENGINE_VERSION = '3';
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

// Run through a versioned catalog; unknown implementation coverage is explicit.
export function execute(
  snapshot: AuditSnapshot,
  settings: RuleSettings,
): { findings: AuditFinding[]; configuration: RunConfiguration } {
  const pinned = (settings as RunConfiguration).catalog;
  const definitions = (pinned ?? catalog(settings)).map((rule) => ({
    ...rule,
    supported: SUPPORTED_DETECTORS.includes(rule.detector),
  }));
  const config = parseConfig(
    settings.configYaml,
    new Set(definitions.map((r) => r.id)),
  );
  const legacy = analyze(snapshot);
  const resourcesByPath = new Map(snapshot.resources.map((r) => [r.path, r]));
  const bindings: Record<string, string> = {
    native_root_assignment: 'assignment.root',
    native_unbound_approle: 'approle.unbound-login',
    missing_policy_reference: 'assignment.missing-policy',
    kubernetes_double_wildcard: 'kubernetes.unbounded-subject',
  };
  const findings: AuditFinding[] = [];
  const issues: { path: string; reason: string }[] = [];
  for (const rule of definitions.filter((r) => r.active)) {
    if (!rule.supported) {
      issues.push({
        path: `rules/${rule.id}`,
        reason: `Detector ${rule.detector} has not been ported yet`,
      });
      continue;
    }
    let candidates: AuditFinding[] = [];
    if (AUTH_DETECTORS.includes(rule.detector)) {
      for (const resource of snapshot.resources)
        candidates.push(
          ...evaluateAuth(rule, resource, { config: config.raw }),
        );
    } else if (rule.detector === 'field_compare') {
      const { field, operator, value } = rule.parameters;
      for (const resource of snapshot.resources) {
        const type =
          resource.kind === 'role'
            ? (
                {
                  approle: 'approle',
                  kubernetes: 'kubernetes_role',
                  jwt: 'jwt_role',
                  oidc: 'jwt_role',
                  token: 'token_role',
                } as Record<string, string>
              )[String(resource.data.auth_type)]
            : resource.kind === 'policy'
              ? 'acl_policy'
              : resource.kind;
        if (
          !rule.object_types.includes(type) &&
          !rule.object_types.includes(resource.kind)
        )
          continue;
        const actual = resource.data[String(field)];
        const matched =
          operator === 'missing'
            ? actual === undefined || actual === null
            : operator === 'equals'
              ? actual === value
              : operator === 'contains'
                ? Array.isArray(actual) && actual.includes(value)
                : typeof actual === 'number' && actual > Number(value);
        if (matched)
          candidates.push({
            ruleId: rule.id,
            path: resource.path,
            severity: rule.effectiveSeverity,
            title: rule.title,
            evidence: JSON.stringify({
              field,
              operator,
              expected: value,
              actual: actual ?? null,
            }),
            recommendation: rule.remediation,
          });
      }
    } else
      candidates = legacy.filter((f) => f.ruleId === bindings[rule.detector]);
    findings.push(
      ...candidates
        .filter((f) => {
          const resource = resourcesByPath.get(f.path);
          if (!resource) return false;
          const type =
            resource.kind === 'role'
              ? (
                  {
                    approle: 'approle',
                    kubernetes: 'kubernetes_role',
                    jwt: 'jwt_role',
                    oidc: 'jwt_role',
                    token: 'token_role',
                  } as Record<string, string>
                )[String(resource.data.auth_type)]
              : resource.kind === 'policy'
                ? 'acl_policy'
                : resource.kind;
          return (
            rule.object_types.includes(type) ||
            rule.object_types.includes(resource.kind) ||
            (resource.kind === 'role' &&
              rule.object_types.includes('auth_role'))
          );
        })
        .map((f) => ({
          ...f,
          ruleId: rule.id,
          title: rule.title,
          recommendation: rule.remediation,
          severity: config.overrides[rule.id]?.severity ?? f.severity,
        })),
    );
  }
  if (definitions.some((r) => r.active && AUTH_DETECTORS.includes(r.detector)))
    issues.push({
      path: 'analysis/policy-privilege',
      reason:
        'Auth detectors currently resolve configured privileged policies; HCL-derived privilege signals are not implemented yet',
    });
  return {
    findings,
    configuration: {
      ...settings,
      engineVersion: ENGINE_VERSION,
      catalog: definitions,
      fingerprint: settingsFingerprint(settings, definitions),
      issues,
    },
  };
}
