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

import { catalog, DEFAULT_SETTINGS, parseRule } from './catalog.js';
import { execute } from './engine.js';
const customRule = `version: 1
rule:
  id: CUSTOM-TTL
  status: stable
  severity: low
  finding_kind: risky_configuration
  title: Team TTL limit
  description: Team roles should use short-lived tokens.
  remediation: Reduce token_ttl.
  object_types: [kubernetes_role]
  detector: field_compare
  parameters: {field: token_ttl, operator: greater_than, value: 3600}
`;
test('catalog validates YAML, profiles, overrides and duplicate IDs without executing expressions', () => {
  const definitions = catalog(DEFAULT_SETTINGS);
  assert.equal(
    definitions.filter(
      (r) => r.source === 'builtin' && !r.id.startsWith('LOCAL-'),
    ).length,
    35,
  );
  assert.equal(definitions.find((r) => r.id === 'POL-008')?.active, false);
  const extended = catalog({
    ...DEFAULT_SETTINGS,
    configYaml:
      'version: 1\nprofile: extended\nrules:\n  POL-008: {severity: low}\n',
  });
  assert.equal(
    extended.find((r) => r.id === 'POL-008')?.effectiveSeverity,
    'low',
  );
  assert.equal(extended.find((r) => r.id === 'POL-008')?.active, true);
  assert.throws(
    () => parseRule(customRule.replace('field_compare', 'eval')),
    /Unregistered/,
  );
  assert.throws(() =>
    parseRule(customRule.replace('value: 3600', 'value: 3600, value: 10')),
  );
  assert.throws(
    () =>
      catalog({
        ...DEFAULT_SETTINGS,
        customRulesYaml: customRule + '\n---\n' + customRule,
      }),
    /Duplicate/,
  );
  assert.throws(
    () =>
      catalog({
        ...DEFAULT_SETTINGS,
        configYaml: 'version: 1\nrules: {TYPO: {enabled: true}}',
      }),
    /Unknown/,
  );
});
test('custom rule runs with scoped object types and severity overrides; unported checks are explicit', () => {
  const s = snapshot();
  s.resources[1].data.token_ttl = 7200;
  const settings = {
    ...DEFAULT_SETTINGS,
    customRulesYaml: customRule,
    configYaml: 'version: 1\nrules:\n  CUSTOM-TTL: {severity: critical}\n',
  };
  const result = execute(s, settings);
  assert.equal(
    result.findings.find((f) => f.ruleId === 'CUSTOM-TTL')?.severity,
    'critical',
  );
  assert.ok(
    result.configuration.issues.some((i) => i.path === 'rules/POL-001'),
  );
  assert.equal(result.configuration.fingerprint.length, 64);
  s.resources[1].data.auth_type = 'approle';
  assert.equal(
    execute(s, settings).findings.some((f) => f.ruleId === 'CUSTOM-TTL'),
    false,
  );
});
test('settings revisions reject lost updates and historical runs retain their own configuration', () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-settings-'));
  const store = new AuditStore(join(dir, 'db.sqlite'));
  try {
    const current = store.settings();
    const saved = store.saveSettings({
      ...current,
      customRulesYaml: customRule,
    });
    assert.equal(saved.revision, 1);
    assert.throws(() => store.saveSettings(current), /Settings changed/);
    const s = snapshot();
    const result = execute(s, saved);
    const id = store.create(s.target);
    store.finish(id, s, result.findings, result.configuration);
    store.saveSettings({ ...saved, customRulesYaml: '' });
    assert.equal(store.get(id, s.target)?.configuration?.revision, 1);
    assert.equal(
      store.get(id, s.target)?.configuration?.customRulesYaml,
      customRule,
    );
    assert.equal(store.get(id, s.target)?.run.status, 'partial');
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
