import { parseExceptions } from './exceptions.js';
import { createBaseline, parseBaseline, applyBaseline } from './baseline.js';
import { compareRuns } from './diff.js';
import { readFileSync, writeFileSync } from 'node:fs';
import { catalog } from './catalog.js';
import { AuditStore } from './store.js';
import { collect } from './collector.js';
import { execute } from './engine.js';
const [command, argument] = process.argv.slice(2);
const target = process.env['VAULT_ADDR'] || 'http://127.0.0.1:8200';
const store = new AuditStore(
  process.env['VAULTLENS_AUDIT_DB'] || 'data/security-audit.sqlite',
);
const baselineFlag = process.argv.indexOf('--baseline');
try {
  if(baselineFlag >= 0 && !process.argv[baselineFlag+1]) throw new Error('--baseline requires a file');
  const baseline = baselineFlag < 0 ? undefined : parseBaseline(readFileSync(process.argv[baselineFlag+1], 'utf8'));
  const exceptionsFlag=process.argv.indexOf('--exceptions');
  if(exceptionsFlag>=0 && !process.argv[exceptionsFlag+1]) throw new Error('--exceptions requires a file');
  const exceptions=exceptionsFlag<0 ? [] : parseExceptions(readFileSync(process.argv[exceptionsFlag+1],'utf8'),new Set(catalog(store.settings()).map(r=>r.id)));
  if (command === 'baseline-create' && argument && process.argv[4]) {
    const detail=store.get(argument,target);
    if(!detail) throw new Error('Snapshot not found for VAULT_ADDR');
    writeFileSync(process.argv[4], JSON.stringify(createBaseline(detail),null,2)+'\n', {mode:0o600,flag:'wx'});
    console.log(JSON.stringify({baseline:process.argv[4],sourceRunId:argument}));
  } else if (command === 'scan') {
    if (!process.env['VAULT_TOKEN']) throw new Error('VAULT_TOKEN is required');
    const id = store.create(target);
    try {
      const snapshot = await collect(target, process.env['VAULT_TOKEN']);
      const { findings, configuration, identity } = execute(snapshot, store.settings());
      const controls=applyBaseline(findings,configuration,target,baseline,exceptions);
      snapshot.identity = identity;
      store.finish(id, snapshot, findings, configuration);
      console.log(
        JSON.stringify({ id, snapshot, findings, configuration, controls }, null, 2),
      );
      process.exitCode =
        snapshot.issues.length || configuration.issues.length
          ? 2
          : findings.some((f,i) => controls.states[i].gate && ['critical', 'high'].includes(f.severity))
            ? 1
            : 0;
    } catch {
      store.fail(id);
      throw new Error('Collection failed');
    }
  } else if (command === 'diff' && argument && process.argv[4]) {
    const old = store.get(argument, target), next = store.get(process.argv[4], target);
    if (!old || !next) throw new Error('Both runs must exist for VAULT_ADDR');
    const result = compareRuns(old, next);
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.warnings.length ? 2 : result.changes.findings.some(change =>
      ['added', 'changed'].includes(change.change) && change.new &&
      ['high', 'critical'].includes(change.new.severity)) ? 1 : 0;
  } else if (command === 'analyze' && argument) {
    const detail = store.get(argument, target);
    if (!detail?.snapshot) throw new Error('Snapshot not found for VAULT_ADDR');
    const { findings, configuration, identity } = execute(
      detail.snapshot,
      detail.configuration ?? store.settings(),
    );
    const controls=applyBaseline(findings,configuration,target,baseline,exceptions);
    console.log(
      JSON.stringify(
        {
          id: argument,
          controls,
          identity,
          findings,
          issues: detail.snapshot.issues,
          configuration,
        },
        null,
        2,
      ),
    );
    process.exitCode =
      detail.snapshot.issues.length || configuration.issues.length
        ? 2
        : findings.some((f,i) => controls.states[i].gate && ['critical', 'high'].includes(f.severity))
          ? 1
          : 0;
  } else if (command === 'rules')
    console.log(JSON.stringify(catalog(store.settings()), null, 2));
  else if (command === 'configure' && argument) {
    const current = store.settings();
    const next = store.saveSettings({
      ...current,
      configYaml: readFileSync(argument, 'utf8'),
      customRulesYaml: process.argv[4]
        ? readFileSync(process.argv[4], 'utf8')
        : current.customRulesYaml,
    });
    console.log(JSON.stringify(next, null, 2));
  } else if (command === 'list')
    console.log(JSON.stringify(store.list(target), null, 2));
  else
    throw new Error(
      'Usage: audit scan [--baseline FILE] [--exceptions FILE] | list | analyze RUN_ID [--baseline FILE] [--exceptions FILE] | baseline-create RUN_ID FILE | diff OLD_RUN_ID NEW_RUN_ID | rules | configure CONFIG_YAML [CUSTOM_RULES_YAML]',
    );
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Audit failed');
  process.exitCode = 2;
} finally {
  store.close();
}
