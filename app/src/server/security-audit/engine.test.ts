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
test('custom rule runs with scoped object types and severity overrides', () => {
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
    !result.configuration.issues.some((i) => i.path.startsWith('rules/')),
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

test('relationship chains combine assigned policies and honor implicit default', () => {
  const s = snapshot();
  s.resources = [
    { kind: 'policy', path: 'sys/policies/acl/role-admin', data: { name: 'role-admin',
      hcl: 'path "auth/approle/role/demo" { capabilities = ["update"] }' } },
    { kind: 'policy', path: 'sys/policies/acl/default', data: { name: 'default',
      hcl: 'path "sys/policies/acl/*" { capabilities = ["update"] }' } },
    { kind: 'role', path: 'auth/approle/role/demo', data: {
      auth_type: 'approle', token_policies: ['role-admin'] } },
  ];
  const settings = { ...DEFAULT_SETTINGS, configYaml: 'version: 1\nprofile: extended\n' };
  const selected = () => execute(s, settings).findings.filter(f =>
    ['POL-010', 'POL-011', 'POL-015'].includes(f.ruleId));
  assert.deepEqual(selected().map(f => f.ruleId).sort(), ['POL-010', 'POL-011', 'POL-015']);
  const chain = selected().find(f => f.ruleId === 'POL-015')!;
  assert.deepEqual(chain.relatedObjects?.map(o => o.name), ['default', 'role-admin']);
  assert.equal(JSON.parse(chain.evidence).role_administration_grants[0].policy, 'role-admin');
  s.resources[2].data.token_no_default_policy = true;
  assert.deepEqual(selected().map(f => f.ruleId), ['POL-010']);
  s.resources[0].data.hcl = 'path "auth/approle/role/demo" { capabilities = ["deny", "update"] }';
  assert.equal(selected().length, 0);
  s.resources[0].data.hcl = 'path "auth/approle/role/other" { capabilities = ["update"] }';
  assert.equal(selected().length, 0);
});

test('auth bootstrap requires both configuration and mount administration grants', () => {
  const s = snapshot();
  s.resources = [
    { kind: 'policy', path: 'sys/policies/acl/bootstrap', data: { name: 'bootstrap',
      hcl: 'path "sys/auth/*" { capabilities = ["update"] }\npath "auth/+/config" { capabilities = ["update"] }' } },
    { kind: 'role', path: 'auth/kubernetes/role/demo', data: {
      auth_type: 'kubernetes', token_policies: ['bootstrap'] } },
  ];
  const settings = { ...DEFAULT_SETTINGS, configYaml: 'version: 1\nprofile: extended\n' };
  const findings = () => execute(s, settings).findings.filter(f => f.ruleId === 'POL-014');
  assert.equal(findings().length, 1);
  assert.equal(JSON.parse(findings()[0].evidence).confidence, 'proven_capabilities_inferred_configuration');
  s.resources[0].data.hcl = 'path "sys/auth/*" { capabilities = ["update"] }';
  assert.equal(findings().length, 0);
  s.resources[0].data.hcl = 'path "sys/auth/*" { capabilities = ["read"] }\npath "auth/+/config" { capabilities = ["update"] }';
  assert.equal(findings().length, 0);
});

import relationshipFixtures from './fixtures/relationship-parity.json' with { type: 'json' };
test('six relationship detectors match Python evidence and severity', () => {
  const settings = { ...DEFAULT_SETTINGS, configYaml: 'version: 1\nprofile: extended\n' };
  for (const fixture of relationshipFixtures) {
    const s = snapshot();
    s.resources = fixture.resources;
    const actual = execute(s, settings).findings.filter(f => f.path === fixture.path &&
      ['POL-010', 'POL-011', 'POL-012', 'POL-013', 'POL-014', 'POL-015'].includes(f.ruleId))
      .map(f => ({ruleId:f.ruleId, severity:f.severity, evidence:JSON.parse(f.evidence)}))
      .sort((a,b) => a.ruleId.localeCompare(b.ruleId));
    assert.deepEqual(actual, fixture.expected, fixture.name);
  }
});

import { roleEntityIds } from './identity.js';
test('identity correlation requires the same AppRole accessor and RoleID hash', () => {
  const fixture = relationshipFixtures.find(f => f.name === 'cross-role-True-True-True')!;
  const resources: AuditSnapshot['resources'] = structuredClone(fixture.resources);
  assert.deepEqual([...roleEntityIds(resources).get('auth/approle/role/source')!], ['entity-a']);
  const alias = resources.find(r => r.path === 'identity/entity-alias/id/source')!;
  alias.data = {...alias.data, mount_accessor: 'different-mount'};
  assert.equal(roleEntityIds(resources).has('auth/approle/role/source'), false);
  alias.data = {...alias.data, mount_accessor:'test-accessor', name_sha256:'different-role'};
  assert.equal(roleEntityIds(resources).has('auth/approle/role/source'), false);
});

import referenceFixtures from './fixtures/reference-parity.json' with {type:'json'};
import { evaluateReference } from './referenceDetector.js';
test('missing policy references match Python, with explicit incomplete-inventory suppression', () => {
  const rule = catalog(DEFAULT_SETTINGS).find(r => r.id === 'REF-001')!;
  for (const fixture of referenceFixtures) {
    const result = evaluateReference(rule, fixture.resource, new Set(fixture.known), true, {config:{}});
    assert.deepEqual(result.map(f => ({severity:f.severity,evidence:JSON.parse(f.evidence)})), fixture.expected, fixture.name);
    assert.equal(evaluateReference(rule, fixture.resource, new Set(), false, {config:{}}).length, 0);
  }
  const s = snapshot();
  s.resources[1].data.token_policies = ['team-admin'];
  s.resources[1].data.token_no_default_policy = true;
  const result = execute(s, {...DEFAULT_SETTINGS, configYaml:
    'version: 1\nprivileged_policies:\n  exact: []\n  patterns: ["team-*"]\n'});
  const missing = result.findings.find(f => f.ruleId === 'REF-001')!;
  assert.equal(missing.severity, 'high');
  assert.deepEqual(JSON.parse(missing.evidence).configured_privileged_names, ['team-admin']);
});

test('implicit default policy participates in auth privilege checks', () => {
  const s = snapshot();
  s.resources = [
    {kind:'policy',path:'sys/policies/acl/default',data:{name:'default',hcl:'path "*" { capabilities = ["update"] }'}},
    {kind:'role',path:'auth/approle/role/demo',data:{auth_type:'approle',token_policies:[]}},
  ];
  assert.ok(execute(s, DEFAULT_SETTINGS).findings.some(f => f.ruleId === 'APPROLE-001'));
  s.resources[1].data.token_no_default_policy = true;
  assert.ok(!execute(s, DEFAULT_SETTINGS).findings.some(f => f.ruleId === 'APPROLE-001'));
});

import { analyzeIdentity } from './identity.js';
test('nested Identity groups retain provenance without duplicate diamond assignments', () => {
  const s = snapshot();
  s.resources = [
    {kind:'group',path:'identity/group/id/top',data:{policies:['admin'],member_group_ids:['left','right']}},
    {kind:'group',path:'identity/group/id/left',data:{policies:['left'],member_group_ids:['leaf']}},
    {kind:'group',path:'identity/group/id/right',data:{policies:[],member_group_ids:['leaf']}},
    {kind:'group',path:'identity/group/id/leaf',data:{policies:['read'],member_entity_ids:['person']}},
    {kind:'entity',path:'identity/entity/id/person',data:{policies:['own']}},
  ];
  const before=structuredClone(s.resources);
  const result=analyzeIdentity(s.resources);
  assert.equal(result.issues.length,0);
  const effective=result.assignments.filter(a => a.subjectKind==='entity');
  assert.deepEqual(effective.map(a=>a.policy), ['admin','left','own','read']);
  assert.equal(effective.find(a=>a.policy==='admin')?.sourcePath,'identity/group/id/top');
  assert.deepEqual(s.resources,before);
  s.resources[0].data.parent_group_ids=['leaf','missing'];
  s.resources[3].data.member_entity_ids=['absent'];
  const broken=execute(s,DEFAULT_SETTINGS);
  assert.ok(broken.configuration.issues.some(i=>i.reason.includes('cycle')));
  assert.ok(broken.configuration.issues.some(i=>i.path==='identity/group/id/missing'));
  assert.ok(broken.configuration.issues.some(i=>i.path==='identity/entity/id/absent'));
  assert.ok(!broken.identity.assignments.some(a=>a.relationship==='inherited' && a.subjectPath===a.sourcePath));
});

import identityFixtures from './fixtures/identity-parity.json' with {type:'json'};
test('Identity inheritance matches Python for parent/child edges and diamond provenance', () => {
  const sorted = (items: unknown[]) => items.map(item => JSON.stringify(item)).sort();
  for (const fixture of identityFixtures) {
    const result=analyzeIdentity(fixture.resources);
    assert.deepEqual(sorted(result.assignments), sorted(fixture.expected), fixture.name);
    assert.equal(result.issues.length > 0, fixture.partial, fixture.name);
  }
});

import { compareRuns } from './diff.js';
test('offline diff preserves duplicate finding identities, severity changes and coverage gaps', () => {
  const s=snapshot(), result=execute(s,DEFAULT_SETTINGS);
  const old: import('../../shared/securityAudit.js').AuditDetail={
    run:{id:'old',target:s.target,startedAt:s.startedAt,finishedAt:s.finishedAt,status:'completed',resourceCount:s.resources.length,issueCount:0,findingCount:2},
    snapshot:s,configuration:result.configuration,findings:[
      {ruleId:'demo',path:'auth/demo',severity:'medium',title:'Demo',recommendation:'Review',evidence:'{"a":1,"b":2}'},
      {ruleId:'demo',path:'auth/demo',severity:'high',title:'Demo',recommendation:'Review',evidence:'{"a":2}'},
    ],
  };
  const next=structuredClone(old);next.run.id='new';
  next.findings[0].evidence='{"b":2,"a":1}';
  next.findings[1].severity='critical';
  next.snapshot!.resources[1].data.token_ttl=3600;
  let diff=compareRuns(old,next);
  assert.equal(diff.statistics.findings.unchanged,1);
  assert.equal(diff.statistics.findings.changed,1);
  assert.equal(diff.statistics.resources.changed,1);
  assert.deepEqual(diff.warnings,[]);
  next.findings=[];next.snapshot!.issues.push({path:'auth/demo',reason:'Vault HTTP 403'});
  diff=compareRuns(old,next);
  assert.equal(diff.statistics.findings.removed,2);
  assert.equal(diff.warnings.length,1);
  next.configuration!.engineVersion='different';
  assert.throws(()=>compareRuns(old,next),/incomparable/);
  next.configuration=old.configuration;next.snapshot!.target='http://other.invalid';
  assert.throws(()=>compareRuns(old,next),/incomparable/);
});

import { createBaseline, parseBaseline, applyBaseline, findingFingerprint } from './baseline.js';
test('baseline preserves findings and gates only new identities under the same configuration', () => {
  const s=snapshot(),result=execute(s,DEFAULT_SETTINGS);
  const detail: import('../../shared/securityAudit.js').AuditDetail={snapshot:s,configuration:result.configuration,findings:result.findings,
    run:{id:'base',target:s.target,startedAt:s.startedAt,finishedAt:s.finishedAt,status:'completed',resourceCount:2,issueCount:0,findingCount:result.findings.length}};
  const baseline=parseBaseline(JSON.stringify(createBaseline(detail)));
  const original=structuredClone(result.findings);
  const controls=applyBaseline(result.findings,result.configuration,s.target,baseline);
  assert.ok(controls.states.every(state=>!state.gate));
  assert.deepEqual(result.findings,original);
  const changed=structuredClone(result.findings);changed[0].evidence='new evidence';
  assert.ok(applyBaseline(changed,result.configuration,s.target,baseline).states[0].gate);
  assert.throws(()=>applyBaseline(changed,result.configuration,'http://other',baseline),/incompatible/);
  assert.throws(()=>applyBaseline(changed,{...result.configuration,engineVersion:'other'},s.target,baseline),/incompatible/);
  assert.throws(()=>parseBaseline('version: 1\ntool: vaultlens\nfingerprints: [nope]'),/requires|Invalid/);
  const a={...original[0],evidence:'{"a":1,"b":2}'};
  assert.equal(findingFingerprint(a),findingFingerprint({...a,evidence:'{"b":2,"a":1}'}));
});

import { parseExceptions } from './exceptions.js';
test('expiring exceptions preserve findings, scope policy paths and report unused entries', () => {
  const s=snapshot(),configuration=execute(s,DEFAULT_SETTINGS).configuration;
  const finding={ruleId:'POL-001',path:'sys/policies/acl/demo',policyPath:'secret/team/*',severity:'high' as const,title:'Demo',recommendation:'Review',evidence:'{}'};
  const entry={id:'approved',rule_id:'POL-001',namespace:'root',object_path:'sys/policies/acl/demo',policy_path:'secret/team/*',owner:'security',reason:'Migration deadline',expires:'2026-09-08'};
  const load=(entries:unknown[])=>parseExceptions(JSON.stringify({version:1,exceptions:entries}),new Set(['POL-001']));
  const entries=load([entry,{...entry,id:'unused',object_path:'other'},{...entry,id:'expired',expires:'2026-09-07'}]);
  let controls=applyBaseline([finding],configuration,s.target,undefined,entries,'2026-09-08');
  assert.equal(controls.states[0].gate,false);
  assert.equal(controls.states[0].exception?.owner,'security');
  assert.deepEqual(controls.exceptions.unused.map(e=>e.id),['unused']);
  assert.deepEqual(controls.exceptions.expired.map(e=>e.id),['expired']);
  controls=applyBaseline([finding],configuration,s.target,undefined,entries,'2026-09-09');
  assert.equal(controls.states[0].gate,true);
  assert.equal(applyBaseline([{...finding,policyPath:'other'}],configuration,s.target,undefined,entries,'2026-09-08').states[0].gate,true);
  assert.throws(()=>load([entry,entry]),/Duplicate/);
  assert.throws(()=>load([{...entry,expires:'2026-02-30'}]),/expires/);
  assert.throws(()=>load([{...entry,owner:''}]),/requires owner/);
  assert.throws(()=>load([{...entry,rule_id:'unknown'}]),/Unknown/);
});

import { parseAuditArguments, auditExitCode } from './cliOptions.js';
test('CI arguments reject ignored flags and gate severity independently of completeness', () => {
  assert.throws(()=>parseAuditArguments(['scan','--fial-on','none']),/Unsupported/);
  assert.throws(()=>parseAuditArguments(['diff','old','new','--baseline','file']),/Unsupported/);
  assert.throws(()=>parseAuditArguments(['scan','--fail-on']),/requires/);
  assert.throws(()=>parseAuditArguments(['scan','--fail-on','high','--fail-on','none']),/Duplicate/);
  assert.throws(()=>parseAuditArguments(['scan','--require-complete','--allow-incomplete']),/Conflicting/);
  assert.throws(()=>parseAuditArguments(['analyze']),/positional/);
  const options=parseAuditArguments(['analyze','--fail-on','medium','run-id','--exceptions','team.yml']);
  assert.equal(options.positionals[0],'run-id');assert.equal(options.exceptions,'team.yml');
  assert.equal(auditExitCode(['medium'],false,options),1);
  assert.equal(auditExitCode(['low'],false,options),0);
  assert.equal(auditExitCode([],true,options),2);
  assert.equal(auditExitCode(['critical'],false,{...options,failOn:'none'}),0);
  assert.equal(auditExitCode([],true,parseAuditArguments(['scan','--allow-incomplete'])),0);
});

import { exportAudit } from './exporter.js';
test('offline exports preserve evidence and protect CSV cells from formula execution', () => {
  const s=snapshot(),result=execute(s,DEFAULT_SETTINGS);
  const detail: import('../../shared/securityAudit.js').AuditDetail={snapshot:s,configuration:result.configuration,findings:[{
    ruleId:'DEMO',path:'=HYPERLINK("external")',severity:'high',title:'A, "quote"',evidence:'first\nsecond',recommendation:'Review'}],
    run:{id:'demo',target:s.target,startedAt:s.startedAt,finishedAt:s.finishedAt,status:'completed',resourceCount:2,issueCount:0,findingCount:1}};
  assert.deepEqual(JSON.parse(exportAudit(detail,'json')),detail);
  const lines=exportAudit(detail,'jsonl').trim().split('\n').map(line=>JSON.parse(line));
  assert.equal(lines.filter(r=>r.type==='finding')[0].finding.evidence,'first\nsecond');
  assert.equal(lines.filter(r=>r.type==='resource').length,s.resources.length);
  const csv=exportAudit(detail,'csv');
  assert.ok(csv.includes('"\'=HYPERLINK(""external"")"'));
  assert.ok(csv.includes('"A, ""quote"""'));
  assert.ok(exportAudit(detail,'yaml').includes('ruleId: DEMO'));
  assert.equal(parseAuditArguments(['export','run','file','--format','jsonl']).format,'jsonl');
  assert.throws(()=>parseAuditArguments(['export','run','file','--format','unknown']),/format/);
});

import { createRequestPolicy } from './requestPolicy.js';
import { VaultError } from '../lib/vaultClient.js';
test('collector request policy retries transient failures, spaces requests and rejects access failures', async () => {
  let time=0;
  const policy=createRequestPolicy({retries:2,requestsPerSecond:2,retryBackoffMs:100},{now:()=>time,sleep:async ms=>{time+=ms;}});
  let calls=0;
  assert.equal(await policy.request(async()=>{if(++calls<3) throw new VaultError('unavailable',503);return 'ok';}),'ok');
  assert.equal(calls,3);assert.equal(time,1000);assert.equal(policy.metrics.retries,2);
  let denied=0;
  await assert.rejects(()=>policy.request(async()=>{denied++;throw new VaultError('denied',403);}),/denied/);
  assert.equal(denied,1);
  const limited=createRequestPolicy({retries:1,requestsPerSecond:100,retryBackoffMs:0},{now:()=>time,sleep:async ms=>{time+=ms;}});
  let attempts=0;
  await assert.rejects(()=>limited.request(async()=>{attempts++;throw new VaultError('limited',429);}),/limited/);
  assert.equal(attempts,2);
  assert.throws(()=>parseAuditArguments(['scan','--retries','NaN']),/retries/);
  assert.equal(parseAuditArguments(['scan','--retries','0']).requestPolicy.retries,0);
});

import { forEachConcurrent } from './concurrency.js';
test('collector pool bounds concurrency and drains active work after an error', async () => {
  let active=0,peak=0,finished=0;
  await forEachConcurrent(Array.from({length:12},(_,i)=>i),3,async()=>{
    active++;peak=Math.max(peak,active);
    await new Promise(resolve=>setTimeout(resolve,1));
    active--;finished++;
  });
  assert.equal(peak,3);assert.equal(finished,12);
  active=0;
  await assert.rejects(()=>forEachConcurrent([0,1,2,3],2,async i=>{
    active++;await new Promise(resolve=>setTimeout(resolve,1));active--;
    if(i===0) throw new Error('stop');
  }),/stop/);
  assert.equal(active,0);
  assert.equal(parseAuditArguments(['scan','--workers','4']).requestPolicy.workers,4);
  assert.throws(()=>parseAuditArguments(['scan','--workers','0']),/workers/);
});

import { parseCollectionOptions } from './requestPolicy.js';
test('web collection options validate types and reject unsupported settings before starting', () => {
  assert.equal(parseCollectionOptions(undefined).workers,10);
  assert.deepEqual(parseCollectionOptions({workers:2,retries:0}),{workers:2,retries:0,requestsPerSecond:10,retryBackoffMs:500,timeoutMs:30000,maxDurationMs:7200000,maxObjects:0,policyFilters:[],authMountFilters:[],authTypeFilters:[],skipIdentity:false,namespace:''});
  assert.throws(()=>parseCollectionOptions({workers:'2'}),/numeric/);
  assert.throws(()=>parseCollectionOptions({workers:33}),/workers/);
  assert.throws(()=>parseCollectionOptions({requestsPerSecond:0}),/requestsPerSecond/);
  assert.throws(()=>parseCollectionOptions({unexpected:1}),/Unknown/);
});

test('collection deadline cancels queued rate waits without starting more operations', async () => {
  const abort=new AbortController();
  const policy=createRequestPolicy({retries:3,requestsPerSecond:0.01,retryBackoffMs:500},undefined,abort.signal);
  let calls=0;
  await policy.request(async()=>{calls++;});
  const pending=policy.request(async()=>{calls++;});
  abort.abort();
  await assert.rejects(()=>pending);
  assert.equal(calls,1);
  assert.equal(parseAuditArguments(['scan','--timeout-ms','100','--max-duration-ms','200']).requestPolicy.maxDurationMs,200);
  assert.throws(()=>parseCollectionOptions({timeoutMs:0}),/timeoutMs/);
});

test('saved controls retain their application date and exception metadata across SQLite reads', () => {
  const directory=mkdtempSync(join(tmpdir(),'audit-controls-'));
  const store=new AuditStore(join(directory,'audit.sqlite'));
  try {
    const s=snapshot(),result=execute(s,DEFAULT_SETTINGS);
    const exception={id:'temporary',rule_id:result.findings[0].ruleId,namespace:'root',object_path:result.findings[0].path,owner:'reviewer',reason:'Migration',expires:'2026-09-08'};
    s.controls=applyBaseline(result.findings,result.configuration,s.target,undefined,[exception],'2026-09-08');
    const id=store.create(s.target);store.finish(id,s,result.findings,result.configuration);
    exception.owner='changed later';
    const saved=store.get(id,s.target)!;
    assert.equal(saved.snapshot?.controls?.appliedOn,'2026-09-08');
    assert.equal(saved.snapshot?.controls?.exceptionDefinitions[0].owner,'reviewer');
    assert.equal(saved.snapshot?.controls?.states[0].suppressed,true);
    assert.ok(exportAudit(saved,'csv').includes('"temporary"'));
    assert.ok(exportAudit(saved,'jsonl').includes('"appliedOn":"2026-09-08"'));
  } finally {store.close();rmSync(directory,{recursive:true,force:true});}
});

test('multiple CLI scope patterns are retained and normalized without allowing duplicate scalar options', () => {
  const options=parseAuditArguments(['collect','--policy-filter','team-*','--policy-filter','default','--policy-filter','team-*','--auth-type-filter','jwt','--auth-type-filter','approle','--skip-identity']);
  assert.deepEqual(options.requestPolicy.policyFilters,['default','team-*']);
  assert.deepEqual(options.requestPolicy.authTypeFilters,['approle','jwt']);
  assert.equal(options.requestPolicy.skipIdentity,true);
  assert.throws(()=>parseAuditArguments(['analyze','run','--policy-filter','*']),/Unsupported/);
  assert.throws(()=>parseAuditArguments(['scan','--workers','1','--workers','2']),/Duplicate/);
  assert.throws(()=>parseAuditArguments(['collect','--policy-filter']),/requires/);
});

test('namespace partitions isolate policy references, privilege signals and exceptions', () => {
  const s=snapshot();s.namespaces=['team-a','team-b'];s.resources=[
    {namespace:'team-a',kind:'policy',path:'sys/policies/acl/admin',data:{name:'admin',hcl:'path "*" {capabilities=["update"]}'}},
    ...['team-a','team-b'].map(namespace=>({namespace,kind:'role',path:'auth/approle/role/demo',data:{auth_type:'approle',token_policies:['admin'],token_no_default_policy:true}})),
  ];
  const result=execute(s,DEFAULT_SETTINGS);
  assert.ok(result.findings.some(f=>f.namespace==='team-a'&&f.ruleId==='APPROLE-001'));
  assert.ok(!result.findings.some(f=>f.namespace==='team-b'&&f.ruleId==='APPROLE-001'));
  assert.ok(result.findings.some(f=>f.namespace==='team-b'&&f.ruleId==='REF-001'));
  assert.ok(!result.findings.some(f=>f.namespace==='team-a'&&f.ruleId==='REF-001'));
  const finding=result.findings.find(f=>f.ruleId==='REF-001')!;
  const exception={id:'scope',rule_id:'REF-001',namespace:'team-a',object_path:'*',owner:'security',reason:'Review',expires:'2099-01-01'};
  assert.equal(applyBaseline([finding],result.configuration,s.target,undefined,[exception]).states[0].gate,true);
  assert.equal(applyBaseline([finding],result.configuration,s.target,undefined,[{...exception,namespace:'team-b'}]).states[0].gate,false);
  assert.notEqual(findingFingerprint({...finding,namespace:'team-a'}),findingFingerprint(finding));
});

test('namespace selection normalizes boundaries and rejects invalid header/path input', () => {
  assert.equal(parseCollectionOptions({namespace:'/team/child/'}).namespace,'team/child');
  assert.equal(parseAuditArguments(['collect','--namespace','team/child']).requestPolicy.namespace,'team/child');
  assert.throws(()=>parseCollectionOptions({namespace:'team\r\nHeader: value'}),/namespace/);
  assert.throws(()=>parseCollectionOptions({namespace:'team/../other'}),/namespace/);
  assert.throws(()=>parseCollectionOptions({namespace:'team//child'}),/namespace/);
});


test('alias reference gaps stay within their namespace and preserve raw inventory', () => {
  const s = snapshot();
  s.namespaces = ['team-a', 'team-b'];
  s.resources = [
    {namespace:'team-a',kind:'alias',path:'identity/entity-alias/id/demo',data:{canonical_id:'person',mount_accessor:'shared'}},
    {namespace:'team-b',kind:'entity',path:'identity/entity/id/person',data:{policies:[]}},
    {namespace:'team-b',kind:'auth-mount',path:'auth/approle/',data:{type:'approle',accessor:'shared'}},
  ];
  const before = structuredClone(s.resources);
  const result = execute(s, DEFAULT_SETTINGS);
  assert.equal(result.identity.issues.length, 2);
  assert.ok(result.identity.issues.every(issue => issue.namespace === 'team-a'));
  assert.deepEqual(s.resources, before);
  const resolved = s.resources.map(resource => ({...resource,namespace:'team-a'}));
  assert.deepEqual(analyzeIdentity(resolved).issues, []);
  resolved[0] = {...resolved[0], data:{canonical_id:'',mount_accessor:''}};
  assert.deepEqual(analyzeIdentity(resolved).issues.map(issue => issue.reason), [
    'Alias is missing its canonical entity ID',
    'Alias is missing its auth mount accessor',
  ]);
});

import { sanitizeAlias } from './identity.js';
test('embedded alias reconciliation respects catalog coverage and retains no raw name', () => {
  const alias = sanitizeAlias({id:'alias-a',canonical_id:'person',mount_accessor:'accessor',name:'sensitive-role-id',metadata:{secret:'discard'}});
  assert.equal(alias.name, undefined);
  assert.equal(alias.metadata, undefined);
  assert.equal(typeof alias.name_sha256, 'string');
  const resources: AuditSnapshot['resources'] = [
    {kind:'entity',path:'identity/entity/id/person',data:{aliases:[alias]}},
    {kind:'auth-mount',path:'auth/approle/',data:{accessor:'accessor'}},
  ];
  assert.deepEqual(analyzeIdentity(resources, false).issues, []);
  assert.match(analyzeIdentity(resources, true).issues[0].reason, /absent from.*catalog/);
  resources.push({kind:'alias',path:'identity/entity-alias/id/alias-a',data:alias});
  assert.deepEqual(analyzeIdentity(resources, true).issues, []);
  resources[2].data = {...alias,name_sha256:'changed'};
  assert.match(analyzeIdentity(resources, true).issues[0].reason, /differs.*not atomic/);
  resources[2].data = {...alias,id:'another-id'};
  resources[2].path = 'identity/entity-alias/id/another-id';
  assert.deepEqual(analyzeIdentity(resources, true).issues, []);
  const s = snapshot();
  s.namespaces = ['team-a','team-b'];
  s.namespaceAliasCompleteness = {'team-a':true,'team-b':false};
  s.resources = ['team-a','team-b'].flatMap(namespace => resources.slice(0,2).map(resource => ({...resource,namespace})));
  const issues = execute(s, DEFAULT_SETTINGS).identity.issues;
  assert.equal(issues.length, 1);
  assert.equal(issues[0].namespace, 'team-a');
});

import { createServer as createRawServer } from 'node:net';
import { collect } from './collector.js';
test('collector rejects malformed catalogs and missing ACL source instead of proving absence', async () => {
  let mode: 'malformed'|'source'|'empty' = 'malformed';
  const server = createRawServer(socket => {
    let request = '';
    socket.on('data', chunk => {
      request += chunk.toString();
      if (!request.includes('\r\n\r\n')) return;
      const [method,path] = request.split('\r\n')[0].split(' ');
      let status = 200;
      let body: unknown = {data:{}};
      if (method === 'LIST') {
        body = {data:{keys:[]}};
        if (path === '/v1/sys/policies/acl') {
          if (mode === 'malformed') body = {data:{keys:['default',123]}};
          if (mode === 'source') body = {data:{keys:['default']}};
          if (mode === 'empty') {status = 404; body = {errors:[]};}
        }
        if (path === '/v1/identity/entity-alias/id' && mode === 'malformed') body = {data:{}};
      }
      const payload = JSON.stringify(body);
      socket.end(`HTTP/1.1 ${status} ${status === 200 ? 'OK' : 'Not Found'}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(payload)}\r\n\r\n${payload}`);
    });
  });
  await new Promise<void>(resolve => server.listen(0,'127.0.0.1',resolve));
  try {
    const address = server.address() as import('node:net').AddressInfo;
    const target = `http://127.0.0.1:${address.port}`;
    const options = {retries:0,requestsPerSecond:1000,maxDurationMs:5000};
    const malformed = await collect(target,'fixture-token',false,options);
    assert.equal(malformed.policiesComplete,false);
    assert.equal(malformed.namespaceAliasCompleteness?.[''],false);
    assert.equal(malformed.issues.filter(issue => issue.reason.includes('invalid keys')).length,2);
    mode = 'source';
    const missingSource = await collect(target,'fixture-token',false,options);
    assert.equal(missingSource.policiesComplete,false);
    assert.equal(missingSource.resources.some(resource => resource.kind === 'policy'),false);
    assert.match(missingSource.issues[0].reason,/missing its ACL source/);
    mode = 'empty';
    const empty = await collect(target,'fixture-token',false,options);
    assert.equal(empty.policiesComplete,true);
    assert.equal(empty.namespaceAliasCompleteness?.[''],true);
    assert.deepEqual(empty.issues,[]);
  } finally {
    await new Promise<void>((resolve,reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

test('collector inventories Python-supported cloud auth roles with allowlisted token settings', async () => {
  const types = ['aws','azure','alicloud','oci','gcp'];
  const requests: string[] = [];
  const server = createRawServer(socket => {
    let request = '';
    socket.on('data', chunk => {
      request += chunk.toString();
      if (!request.includes('\r\n\r\n')) return;
      const [method,path] = request.split('\r\n')[0].split(' ');
      requests.push(`${method} ${path}`);
      let data: Record<string,unknown> = method === 'LIST' ? {keys:[]} : {};
      if (path === '/v1/sys/auth') data = Object.fromEntries(types.map(type => [`${type}/`,{type,accessor:`${type}-accessor`}]));
      if (method === 'LIST' && path.startsWith('/v1/auth/')) data = {keys:['workload']};
      if (path.endsWith('/workload')) data = {
        token_policies:['cloud-read'],token_ttl:600,token_bound_cidrs:['192.0.2.0/24'],
        secret_access_key:'must-not-persist',client_secret:'must-not-persist',private_key:'must-not-persist',
      };
      const payload = JSON.stringify({data});
      socket.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(payload)}\r\n\r\n${payload}`);
    });
  });
  await new Promise<void>(resolve => server.listen(0,'127.0.0.1',resolve));
  try {
    const address = server.address() as import('node:net').AddressInfo;
    const result = await collect(`http://127.0.0.1:${address.port}`,'fixture-token',false,{retries:0,requestsPerSecond:1000,maxDurationMs:5000});
    assert.deepEqual(result.issues,[]);
    const roles = result.resources.filter(resource => resource.kind === 'role');
    assert.equal(roles.length,5);
    assert.deepEqual(roles.map(role => role.data.auth_type).sort(),[...types].sort());
    assert.ok(roles.every(role => role.data.token_ttl === 600));
    assert.ok(!JSON.stringify(result).includes('must-not-persist'));
    assert.ok(requests.includes('LIST /v1/auth/gcp/roles'));
    assert.ok(requests.includes('GET /v1/auth/aws/role/workload'));
    assert.ok(requests.every(request => !request.endsWith('/config')));
  } finally {
    await new Promise<void>((resolve,reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

import { policyUsage } from '../../shared/policyUsage.js';
test('policy usage separates namespace, inheritance and token issuance permissions', () => {
  const s = snapshot();
  s.resources = [
    {namespace:'a',kind:'policy',path:'sys/policies/acl/read',data:{name:'read'}},
    {namespace:'b',kind:'policy',path:'sys/policies/acl/read',data:{name:'read'}},
    {namespace:'a',kind:'role',path:'auth/token/roles/demo',data:{auth_type:'token',token_policies:['read','read'],allowed_policies:['admin'],allowed_policies_glob:['team-*']}},
  ];
  s.identity = {groupCount:1,entityCount:1,issues:[],assignments:[
    {namespace:'a',subjectKind:'entity',subjectPath:'identity/entity/id/person',policy:'read',relationship:'inherited',sourcePath:'identity/group/id/team'},
  ]};
  const before = structuredClone(s);
  const result = policyUsage(s);
  assert.equal(result.find(row => row.namespace === 'b')?.references.length,0);
  assert.equal(result.find(row => row.name === 'read' && row.namespace === 'a')?.references.length,2);
  assert.equal(result.find(row => row.name === 'admin')?.references[0].relationship,'allowed');
  assert.equal(result.find(row => row.name === 'default')?.collected,false);
  assert.ok(!result.some(row => row.name === 'team-*'));
  assert.deepEqual(s,before);
});
