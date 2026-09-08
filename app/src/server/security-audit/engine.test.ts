import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditStore } from './store.js';
import { analyze } from './engine.js';
import type { AuditSnapshot } from '../../shared/securityAudit.js';
const snapshot = (): AuditSnapshot => ({
  version: 1,
  target: 'http://example.invalid',
  startedAt: new Date().toISOString(),
  finishedAt: new Date().toISOString(),
  issues: [],
  policiesComplete: true,
  resources: [
    {
      kind: 'policy',
      path: 'sys/policies/acl/team%20read',
      data: { name: 'team read', hcl: '# not evaluated' },
    },
    {
      kind: 'role',
      path: 'auth/kubernetes/role/demo',
      data: {
        auth_type: 'kubernetes',
        token_policies: ['team read', 'missing'],
        bound_service_account_names: ['*'],
        bound_service_account_namespaces: ['*'],
      },
    },
  ],
});
test('missing policy and unbounded Kubernetes role, without parsing HCL', () => {
  const findings = analyze(snapshot());
  assert.deepEqual(
    findings.map((f) => f.ruleId),
    ['assignment.missing-policy', 'kubernetes.unbounded-subject'],
  );
  assert.match(findings[0].evidence, /missing/);
});
test('incomplete collection cannot establish a missing policy', () => {
  const s = snapshot();
  s.policiesComplete = false;
  assert.deepEqual(
    analyze(s).map((f) => f.ruleId),
    ['kubernetes.unbounded-subject'],
  );
});
test('AppRole bound and unbound controls', () => {
  const s = snapshot();
  s.resources = [
    {
      kind: 'role',
      path: 'auth/approle/role/demo',
      data: { auth_type: 'approle', bind_secret_id: false },
    },
  ];
  assert.equal(analyze(s)[0]?.ruleId, 'approle.unbound-login');
  s.resources[0].data.token_bound_cidrs = ['127.0.0.1/32'];
  assert.equal(analyze(s).length, 0);
  s.resources[0].data.token_bound_cidrs = [];
  s.resources[0].data.bind_secret_id = true;
  assert.equal(analyze(s).length, 0);
});
test('durable snapshot, target isolation, one running job and crash recovery', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lens-audit-test-'));
  const db = join(dir, 'audit.sqlite');
  let store = new AuditStore(db);
  try {
    const s = snapshot();
    const id = store.create(s.target);
    assert.throws(() => store.create(s.target));
    store.finish(id, s, analyze(s));
    store.fail(id);
    assert.equal(store.get(id, s.target)?.run.status, 'completed');
    assert.equal(store.get(id, 'http://another.invalid'), null);
    const interrupted = store.create(s.target);
    store.close();
    store = new AuditStore(db);
    store.recover();
    assert.equal(store.get(interrupted, s.target)?.run.status, 'interrupted');
    assert.equal(store.get(id, s.target)?.findings.length, 2);
    assert.equal(
      readFileSync(db).subarray(0, 15).toString(),
      'SQLite format 3',
    );
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
