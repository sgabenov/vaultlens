import type { AuditResource } from '../../shared/securityAudit.js';

/** Correlate only RoleID hashes on the same observed auth mount accessor. */
export function roleEntityIds(resources: AuditResource[]): Map<string, Set<string>> {
  const mounts = new Map(resources.filter(r => r.kind === 'auth-mount' && r.data.type === 'approle')
    .filter(r => typeof r.data.accessor === 'string')
    .map(r => [r.data.accessor as string, r.path.replace(/\/$/, '')]));
  const roles = new Map(resources.filter(r => r.kind === 'role' && r.data.auth_type === 'approle')
    .filter(r => typeof r.data.role_id_sha256 === 'string')
    .map(r => [`${r.path.slice(0, r.path.lastIndexOf('/role/'))}:${r.data.role_id_sha256}`, r.path]));
  const result = new Map<string, Set<string>>();
  for (const alias of resources.filter(r => r.kind === 'alias')) {
    const mount = mounts.get(String(alias.data.mount_accessor ?? ''));
    const hash = alias.data.name_sha256;
    const entity = alias.data.canonical_id;
    if (!mount || typeof hash !== 'string' || typeof entity !== 'string' || !entity) continue;
    const role = roles.get(`${mount}:${hash}`);
    if (!role) continue;
    const ids = result.get(role) ?? new Set<string>();
    ids.add(entity);
    result.set(role, ids);
  }
  return result;
}
