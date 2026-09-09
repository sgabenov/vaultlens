import { parseDocument } from 'yaml';
import { globMatch } from './authDetectors.js';
import type { AuditFinding } from '../../shared/securityAudit.js';
export type FindingException =
  import('../../shared/securityAudit.js').AuditException;
export function validDate(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value))
    return false;
  const date = new Date(value + 'T00:00:00Z');
  return (
    Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value
  );
}
export function parseExceptions(
  source: string,
  ruleIds: Set<string>,
): FindingException[] {
  if (Buffer.byteLength(source) > 256 * 1024)
    throw new Error('Exceptions exceed 256 KiB');
  const document = parseDocument(source, { uniqueKeys: true });
  if (document.errors.length) throw new Error('Invalid exceptions YAML');
  const raw = document.toJS({ maxAliasCount: 0 });
  if (
    !raw ||
    typeof raw !== 'object' ||
    Array.isArray(raw) ||
    raw.version !== 1 ||
    Object.keys(raw).some((k) => !['version', 'exceptions'].includes(k))
  )
    throw new Error('Expected version 1 exceptions');
  const entries = raw.exceptions ?? [];
  if (!Array.isArray(entries) || entries.length > 1000)
    throw new Error('Expected at most 1000 exceptions');
  const seen = new Set<string>();
  return entries.map((entry, index) => {
    if (
      !entry ||
      typeof entry !== 'object' ||
      Array.isArray(entry) ||
      Object.keys(entry).some(
        (k) =>
          ![
            'id',
            'rule_id',
            'namespace',
            'object_path',
            'policy_path',
            'owner',
            'reason',
            'expires',
            'match',
          ].includes(k),
      )
    )
      throw new Error(`Invalid exception ${index}`);
    if (entry.match !== undefined && !['exact', 'glob'].includes(entry.match))
      throw new Error('Invalid exception match mode');
    for (const field of [
      'id',
      'rule_id',
      'namespace',
      'object_path',
      'owner',
      'reason',
    ]) {
      if (
        field === 'namespace' &&
        entry.match === 'exact' &&
        entry[field] === ''
      )
        continue;
      if (typeof entry[field] !== 'string' || !entry[field].trim())
        throw new Error(`Exception ${index} requires ${field}`);
      entry[field] = entry[field].trim();
    }
    if (seen.has(entry.id))
      throw new Error(`Duplicate exception id: ${entry.id}`);
    seen.add(entry.id);
    if (!ruleIds.has(entry.rule_id))
      throw new Error(`Unknown exception rule: ${entry.rule_id}`);
    if (!validDate(entry.expires))
      throw new Error('Exception expires must be YYYY-MM-DD');
    if (entry.policy_path !== undefined && entry.policy_path !== null) {
      if (typeof entry.policy_path !== 'string' || !entry.policy_path.trim())
        throw new Error('Invalid exception policy_path');
      entry.policy_path = entry.policy_path.trim();
    } else delete entry.policy_path;
    return entry as FindingException;
  });
}
export function exceptionMatches(
  entry: FindingException,
  finding: AuditFinding,
): boolean {
  if (entry.match === 'exact')
    return (
      entry.rule_id === finding.ruleId &&
      entry.namespace === (finding.namespace ?? '') &&
      entry.object_path === finding.path &&
      (entry.policy_path === undefined ||
        entry.policy_path === finding.policyPath)
    );
  return (
    entry.rule_id === finding.ruleId &&
    globMatch(entry.namespace, finding.namespace || 'root') &&
    globMatch(entry.object_path, finding.path) &&
    (entry.policy_path === undefined ||
      (finding.policyPath !== undefined &&
        globMatch(entry.policy_path, finding.policyPath)))
  );
}
