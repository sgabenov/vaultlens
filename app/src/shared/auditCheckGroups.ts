import type { RuleView } from './auditRules.js';
export const CHECK_GROUPS = ['Policies', 'AppRole', 'Kubernetes', 'JWT / OIDC', 'Token', 'Identity', 'PKI', 'Transit', 'Assignments'] as const;
export type CheckGroup = typeof CHECK_GROUPS[number];
export function checkGroup(rule: Pick<RuleView, 'id' | 'object_types'>): CheckGroup {
  if (rule.id === 'REF-001' || rule.id === 'LOCAL-ROOT-001') return 'Assignments';
  if (['POL-005', 'POL-012'].includes(rule.id)) return 'Token';
  if (rule.id === 'POL-016') return 'Identity';
  if (rule.id === 'POL-017') return 'Transit';
  if (rule.id === 'POL-019') return 'PKI';
  if (rule.id.startsWith('POL-')) return 'Policies';
  if (rule.id.includes('APPROLE')) return 'AppRole';
  if (rule.id.startsWith('JWT-')) return 'JWT / OIDC';
  if (rule.id.startsWith('K8S-') || rule.id.startsWith('KUBE')) return 'Kubernetes';
  if (rule.object_types.includes('token_role')) return 'Token';
  if (rule.object_types.some(type => ['entity', 'group'].includes(type))) return 'Identity';
  if (rule.object_types.includes('kubernetes_role')) return 'Kubernetes';
  return 'Assignments';
}
