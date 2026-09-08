import { sanitizeAlias } from './identity.js';
import { globMatch } from './authDetectors.js';
import { forEachConcurrent } from './concurrency.js';
import { createRequestPolicy, parseCollectionOptions, type CollectionOptions } from './requestPolicy.js';
import { createHash } from 'node:crypto';
import { VaultClient, VaultError } from '../lib/vaultClient.js';
import type { AuditSnapshot } from '../../shared/securityAudit.js';
export const COLLECTED_FIELDS = [
  'bound_cidrs',
  'num_uses',
  'local_secret_ids',
  'user_claim',
  'groups_claim',
  'alias_name_source',
  'allowed_entity_aliases',
  'name',
  'id',
  'parent_group_ids',
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
  requestOptions: Partial<CollectionOptions> = {},
): Promise<AuditSnapshot> {
  const policyOptions=parseCollectionOptions(requestOptions);
  const {workers,timeoutMs,maxDurationMs}=policyOptions;
  const matches=(value:string,patterns:string[])=>!patterns.length||patterns.some(pattern=>globMatch(pattern,value));
  const limitAbort=new AbortController();
  const signal=AbortSignal.any([AbortSignal.timeout(maxDurationMs),limitAbort.signal]);
  const policy=createRequestPolicy(policyOptions,undefined,signal);
  const client = new VaultClient(target, skipTlsVerify,{timeoutMs,signal,namespace:policyOptions.namespace});
  const snapshot: AuditSnapshot = {
    version: 1,
    analysisPerformed: false,
    namespaces:[policyOptions.namespace],
    target,
    startedAt: new Date().toISOString(),
    finishedAt: '',
    resources: [],
    issues: [],
    policiesComplete: false,
    collection: {workers,requestPolicy:policyOptions,metrics:policy.metrics,scope:{policyFilters:policyOptions.policyFilters,authMountFilters:policyOptions.authMountFilters,authTypeFilters:policyOptions.authTypeFilters,skipIdentity:policyOptions.skipIdentity}},
  };
  let aliasesComplete=false;
  let countedObjects=0;
  function addResource(resource: import('../../shared/securityAudit.js').AuditResource) {
    if(signal.aborted) return;
    const counted=!['auth-mount','secret-mount'].includes(resource.kind);
    if(counted && policyOptions.maxObjects && countedObjects>=policyOptions.maxObjects) {
      snapshot.policiesComplete=false;
      snapshot.issues.push({path:'collection/object-limit',reason:'Object limit reached; snapshot is incomplete'});
      limitAbort.abort();return;
    }
    if(counted) countedObjects++;
    snapshot.resources.push(policyOptions.namespace ? {...resource,namespace:policyOptions.namespace} : resource);
  }
  async function read(
    path: string,
    list = false,
  ): Promise<Record<string, unknown> | null> {
    try {
      const response = await policy.request(() => list
        ? client.list<{ data: Record<string, unknown> }>(path, token)
        : client.get<{ data: Record<string, unknown> }>(path, token));
      const data = response?.data;
      if (!data || typeof data !== 'object' || Array.isArray(data)) {
        snapshot.issues.push({path,reason:'Vault response is missing an object data field'});
        return null;
      }
      if (list && (!Array.isArray(data.keys) || data.keys.some(key => typeof key !== 'string' || !key))) {
        snapshot.issues.push({path,reason:'Vault LIST response contains an invalid keys field'});
        return null;
      }
      return data;
    } catch (error) {
      if(signal.aborted) {
        if(!limitAbort.signal.aborted && !snapshot.issues.some(issue=>issue.path==='collection/deadline'))
          snapshot.issues.push({path:'collection/deadline',reason:'Collection duration limit reached; snapshot is incomplete'});
        snapshot.policiesComplete=false;
        return null;
      }
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
  // Discovery stages are ordered; independent reads share one rate limiter.
  const policyList = await read('sys/policies/acl', true);
  snapshot.policiesComplete = policyList !== null && !policyOptions.policyFilters.length;
  await forEachConcurrent(keys(policyList).filter(name=>name!=='root' && matches(name,policyOptions.policyFilters)),workers,async name=>{
    const path = `sys/policies/acl/${encodeURIComponent(name)}`;
    const data = await read(path);
    if (data && typeof (data.policy ?? data.rules) !== 'string') {
      snapshot.issues.push({path,reason:'Policy response is missing its ACL source'});
      snapshot.policiesComplete = false;
    } else if (data)
      addResource({
        kind: 'policy',
        path,
        data: { name, hcl: data.policy ?? data.rules ?? '' },
      });
    else snapshot.policiesComplete = false;
  });
  if(!policyOptions.skipIdentity) {
  for (const kind of ['entity', 'group']) {
    const base = `identity/${kind}/id`;
    await forEachConcurrent(keys(await read(base,true)),workers,async id=>{
      const path = `${base}/${encodeURIComponent(id)}`;
      const data = await read(path);
      if (data) {
        const selected = select(data);
        if (kind === 'entity' && Array.isArray(data.aliases))
          selected.aliases = data.aliases.map(alias => alias && typeof alias === 'object' && !Array.isArray(alias)
            ? sanitizeAlias(alias as Record<string, unknown>) : null);
        addResource({ kind, path, data: selected });
      }
    });
  }
  const aliasBase = 'identity/entity-alias/id';
  const aliasList = await read(aliasBase,true);
  aliasesComplete = aliasList !== null;
  await forEachConcurrent(keys(aliasList),workers,async id=>{
    const path = `${aliasBase}/${encodeURIComponent(id)}`;
    const data = await read(path);
    if (data) addResource({ kind: 'alias', path, data: sanitizeAlias(data) });
    else aliasesComplete = false;
  });
  } else snapshot.issues.push({path:'identity',reason:'Identity collection was explicitly skipped'});
  const secretMounts = await read('sys/mounts');
  for (const [mount, value] of Object.entries(secretMounts ?? {}))
    addResource({
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
    aws: 'role',
    azure: 'role',
    alicloud: 'role',
    oci: 'role',
    gcp: 'roles',
  };
  for (const [mount, value] of Object.entries(auth ?? {})) {
    const type = String((value as Record<string, unknown>)?.type ?? '');
    addResource({
      kind: 'auth-mount',
      path: `auth/${mount}`,
      data: { type, accessor: (value as Record<string, unknown>).accessor },
    });
    if(!matches(mount.replace(/\/$/,''),policyOptions.authMountFilters)||!matches(type,policyOptions.authTypeFilters)) continue;
    if (!supported[type]) {
      snapshot.issues.push({
        path: `auth/${mount}`,
        reason: `Auth type ${type} is not collected by v1`,
      });
      continue;
    }
    const base = `auth/${mount}${supported[type]}`;
    await forEachConcurrent(keys(await read(base,true)),workers,async name=>{
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
        addResource({
          kind: 'role',
          path,
          data: { ...selected, auth_type: type },
        });
      }
    });
  }
  snapshot.resources.sort((a,b)=>a.path.localeCompare(b.path)||a.kind.localeCompare(b.kind));
  snapshot.issues.sort((a,b)=>a.path.localeCompare(b.path)||a.reason.localeCompare(b.reason));
  snapshot.namespaceAliasCompleteness={[policyOptions.namespace]:aliasesComplete && !signal.aborted};
  snapshot.namespacePolicyCompleteness={[policyOptions.namespace]:snapshot.policiesComplete};
  if(policyOptions.namespace) snapshot.issues=snapshot.issues.map(issue=>({...issue,namespace:policyOptions.namespace}));
  snapshot.finishedAt = new Date().toISOString();
  return snapshot;
}
