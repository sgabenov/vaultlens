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
    configYaml:
      'version: 1\nprofile: extended\nrules:\n  CUSTOM-TTL: {severity: critical}\n',
  };
  const result = execute(s, settings);
  assert.equal(
    result.findings.find((f) => f.ruleId === 'CUSTOM-TTL')?.severity,
    'critical',
  );
  assert.ok(
    result.configuration.issues.some((i) => i.path === 'rules/POL-010'),
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
    assert.equal(store.get(id, s.target)?.run.status, 'completed');
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

import authFixtures from './fixtures/auth-parity.json' with { type: 'json' };
import { AUTH_DETECTORS, evaluateAuth } from './authDetectors.js';
test('auth detectors match Python evidence and severity across synthetic controls and thresholds', () => {
  const definitions = catalog({
    ...DEFAULT_SETTINGS,
    configYaml: 'version: 1\nprofile: extended\n',
  }).filter((r) => AUTH_DETECTORS.includes(r.detector));
  const mismatches: unknown[] = [];
  for (const fixture of authFixtures) {
    const actual = definitions
      .flatMap((rule) =>
        evaluateAuth(rule, fixture.resource, { config: fixture.config }),
      )
      .map((f) => ({
        ruleId: f.ruleId,
        severity: f.severity,
        evidence: JSON.parse(f.evidence),
      }))
      .sort((a, b) => a.ruleId.localeCompare(b.ruleId));
    try {
      assert.deepEqual(actual, fixture.expected);
    } catch {
      mismatches.push({
        name: fixture.name,
        actual,
        expected: fixture.expected,
      });
    }
  }
  assert.deepEqual(mismatches, []);
});
test('runtime severity is preserved unless an explicit configuration override changes it', () => {
  const s = snapshot();
  s.resources = [
    {
      kind: 'role',
      path: 'auth/approle/role/test',
      data: {
        auth_type: 'approle',
        bind_secret_id: false,
        secret_id_bound_cidrs: ['127.0.0.1/32'],
      },
    },
  ];
  const settings = {
    ...DEFAULT_SETTINGS,
    configYaml: 'version: 1\nrules:\n  APPROLE-004: {enabled: true}\n',
  };
  assert.equal(
    execute(s, settings).findings.find((f) => f.ruleId === 'APPROLE-004')
      ?.severity,
    'info',
  );
  settings.configYaml =
    'version: 1\nrules:\n  APPROLE-004: {enabled: true, severity: high}\n';
  assert.equal(
    execute(s, settings).findings.find((f) => f.ruleId === 'APPROLE-004')
      ?.severity,
    'high',
  );
});

import policyFixtures from './fixtures/policy-parity.json' with { type: 'json' };
import { parsePolicy, PolicyParseError } from './policyParser.js';
import {
  POLICY_DETECTORS,
  evaluatePolicy,
  vaultPatternMatches,
} from './policyDetectors.js';
test('policy detectors and lexical source information match the Python corpus', () => {
  const definitions = catalog({
    ...DEFAULT_SETTINGS,
    configYaml: 'version: 1\nprofile: extended\n',
  }).filter((r) => POLICY_DETECTORS.includes(r.detector));
  const mounts = [
    ['secret/', 'kv'],
    ['secret/nested/', 'kv'],
    ['cubbyhole/', 'cubbyhole'],
  ].map(([mount, type]) => ({
    kind: 'secret-mount',
    path: `sys/mounts/${mount}`,
    data: { mount_path: mount, type },
  }));
  const mismatches: unknown[] = [];
  for (const fixture of policyFixtures) {
    try {
      const blocks = parsePolicy(fixture.source);
      assert.deepEqual(
        JSON.parse(JSON.stringify(blocks.map(({ column, ...b }) => b))),
        fixture.blocks,
      );
      const resource = {
        kind: 'policy',
        path: 'sys/policies/acl/demo',
        data: { name: 'demo', hcl: fixture.source },
      };
      const actual = definitions
        .flatMap((rule) => evaluatePolicy(rule, resource, blocks, mounts))
        .map((f) => ({
          ruleId: f.ruleId,
          severity: f.severity,
          evidence: JSON.parse(f.evidence),
          line: f.line,
          matchedBlock: f.matchedBlock,
        }))
        .sort((a, b) => a.ruleId.localeCompare(b.ruleId));
      assert.deepEqual(actual, fixture.expected);
    } catch (error) {
      mismatches.push({ name: fixture.name, error: String(error) });
    }
  }
  assert.deepEqual(mismatches, []);
});
test('malformed or unsupported policy syntax produces diagnostics instead of invented grants', () => {
  for (const source of [
    'path "*" {capabilities=["read"]',
    '/* never closed',
    'path "*" { capabilities=var.caps }',
    'path "*" { capabilities=["read"] capabilities=["sudo"] }',
    'path "*" {capabilities=["read",42]}',
  ])
    assert.throws(() => parsePolicy(source), PolicyParseError);
  assert.equal(parsePolicy('# path "*" {capabilities=["sudo"]}').length, 0);
  assert.equal(
    vaultPatternMatches('secret/+/data/*', 'secret/team/data/item'),
    true,
  );
  assert.equal(
    vaultPatternMatches('secret/+/data/*', 'secret/team/extra/data/item'),
    false,
  );
});
test('disabled policy findings still supply privilege signals to role checks', () => {
  const s = snapshot();
  s.resources = [
    {
      kind: 'policy',
      path: 'sys/policies/acl/danger',
      data: { name: 'danger', hcl: 'path "*" {capabilities=["update"]}' },
    },
    {
      kind: 'role',
      path: 'auth/approle/role/demo',
      data: {
        auth_type: 'approle',
        token_policies: ['danger'],
        bind_secret_id: false,
      },
    },
  ];
  const result = execute(s, {
    ...DEFAULT_SETTINGS,
    configYaml: 'version: 1\nrules:\n  POL-001: {enabled: false}\n',
  });
  assert.equal(
    result.findings.some((f) => f.ruleId === 'POL-001'),
    false,
  );
  const role = result.findings.find((f) => f.ruleId === 'APPROLE-008');
  assert.equal(role?.severity, 'critical');
  assert.deepEqual(JSON.parse(role!.evidence).privileged_policies, {
    danger: ['POL-001'],
  });
  assert.equal(result.configuration.issues.length, 0);
  s.resources[0].data.hcl = 'path "*" {capabilities = var.caps}';
  assert.ok(
    execute(s, DEFAULT_SETTINGS).configuration.issues.some(
      (i) => i.path === 'sys/policies/acl/danger',
    ),
  );
});
