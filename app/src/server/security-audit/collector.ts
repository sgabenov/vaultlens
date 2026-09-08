import { createHash } from 'node:crypto';
import { VaultClient, VaultError } from '../lib/vaultClient.js';
import type { AuditSnapshot } from '../../shared/securityAudit.js';
export const COLLECTED_FIELDS = [
  'name',
  'type',
  'policies',
  'token_policies',
  'allowed_policies',
  'allowed_policies_glob',
  'disallowed_policies',
  'disallowed_policies_glob',
  'orphan',
  'renewable',
  'path_suffix',
  'token_type',
  'bind_secret_id',
  'secret_id_bound_cidrs',
  'token_bound_cidrs',
  'bound_service_account_names',
  'bound_service_account_namespaces',
  'group_ids',
  'member_entity_ids',
  'member_group_ids',
  'disabled',
  'role_type',
  'bound_audiences',
  'bound_subject',
  'bound_claims',
  'bound_claims_type',
  'ttl',
  'max_ttl',
  'period',
  'token_no_default_policy',
  'token_ttl',
  'token_max_ttl',
  'token_explicit_max_ttl',
  'token_period',
  'token_num_uses',
  'secret_id_ttl',
  'secret_id_num_uses',
  'bound_service_account_namespace_selector',
];
export async function collect(
  target: string,
  token: string,
  skipTlsVerify = false,
): Promise<AuditSnapshot> {
  const client = new VaultClient(target, skipTlsVerify);
  const snapshot: AuditSnapshot = {
    version: 1,
    target,
    startedAt: new Date().toISOString(),
    finishedAt: '',
    resources: [],
    issues: [],
    policiesComplete: false,
  };
  async function read(
    path: string,
    list = false,
  ): Promise<Record<string, unknown> | null> {
    try {
      const response = list
        ? await client.list<{ data: Record<string, unknown> }>(path, token)
        : await client.get<{ data: Record<string, unknown> }>(path, token);
      return response.data ?? {};
    } catch (error) {
      // Vault LIST returns 404 for empty collections. Other failures remain explicit.
      if (list && error instanceof VaultError && error.statusCode === 404)
        return { keys: [] };
      snapshot.issues.push({
        path,
        reason:
          error instanceof VaultError
            ? `Vault HTTP ${error.statusCode}`
            : 'Request failed',
      });
      return null;
    }
  }
  const keys = (data: Record<string, unknown> | null): string[] =>
    Array.isArray(data?.keys)
      ? data.keys.filter((x): x is string => typeof x === 'string')
      : [];
  const select = (data: Record<string, unknown>) =>
    Object.fromEntries(
      COLLECTED_FIELDS.filter((k) => k in data).map((k) => [k, data[k]]),
    );
  // Deliberately serial in v1: bounded Vault load and deterministic evidence.
  const policyList = await read('sys/policies/acl', true);
  snapshot.policiesComplete = policyList !== null;
  for (const name of keys(policyList)) {
    if (name === 'root') continue;
    const path = `sys/policies/acl/${encodeURIComponent(name)}`;
    const data = await read(path);
    if (data)
      snapshot.resources.push({
        kind: 'policy',
        path,
        data: { name, hcl: data.policy ?? data.rules ?? '' },
      });
    else snapshot.policiesComplete = false;
  }
  for (const kind of ['entity', 'group']) {
    const base = `identity/${kind}/id`;
    for (const id of keys(await read(base, true))) {
      const path = `${base}/${encodeURIComponent(id)}`;
      const data = await read(path);
      if (data) snapshot.resources.push({ kind, path, data: select(data) });
    }
  }
  const aliasBase = 'identity/entity-alias/id';
  for (const id of keys(await read(aliasBase, true))) {
    const path = `${aliasBase}/${encodeURIComponent(id)}`;
    const data = await read(path);
    if (data) snapshot.resources.push({ kind: 'alias', path, data: {
      canonical_id: data.canonical_id, mount_accessor: data.mount_accessor,
      name_sha256: typeof data.name === 'string'
        ? createHash('sha256').update(data.name).digest('hex') : undefined,
    } });
  }
  const secretMounts = await read('sys/mounts');
  for (const [mount, value] of Object.entries(secretMounts ?? {}))
    snapshot.resources.push({
      kind: 'secret-mount',
      path: `sys/mounts/${mount}`,
      data: {
        mount_path: mount,
        type: (value as Record<string, unknown>).type,
      },
    });
  const auth = await read('sys/auth');
  const supported: Record<string, string> = {
    approle: 'role',
    kubernetes: 'role',
    jwt: 'role',
    oidc: 'role',
    token: 'roles',
  };
  for (const [mount, value] of Object.entries(auth ?? {})) {
    const type = String((value as Record<string, unknown>)?.type ?? '');
    snapshot.resources.push({
      kind: 'auth-mount',
      path: `auth/${mount}`,
      data: { type, accessor: (value as Record<string, unknown>).accessor },
    });
    if (!supported[type]) {
      snapshot.issues.push({
        path: `auth/${mount}`,
        reason: `Auth type ${type} is not collected by v1`,
      });
      continue;
    }
    const base = `auth/${mount}${supported[type]}`;
    for (const name of keys(await read(base, true))) {
      const path = `${base}/${encodeURIComponent(name)}`;
      const data = await read(path);
      if (data) {
        const selected = select(data);
        if (type === 'approle') {
          const roleId = await read(`${path}/role-id`);
          if (typeof roleId?.role_id === 'string')
            selected.role_id_sha256 = createHash('sha256').update(roleId.role_id).digest('hex');
          else if (roleId) snapshot.issues.push({ path: `${path}/role-id`, reason: 'RoleID response is missing role_id' });
        }
        snapshot.resources.push({
          kind: 'role',
          path,
          data: { ...selected, auth_type: type },
        });
      }
    }
  }
  snapshot.finishedAt = new Date().toISOString();
  return snapshot;
}
