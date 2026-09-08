import { readFileSync } from 'node:fs';
import { catalog } from './catalog.js';
import { AuditStore } from './store.js';
import { collect } from './collector.js';
import { execute } from './engine.js';
const [command, argument] = process.argv.slice(2);
const target = process.env['VAULT_ADDR'] || 'http://127.0.0.1:8200';
const store = new AuditStore(
  process.env['VAULTLENS_AUDIT_DB'] || 'data/security-audit.sqlite',
);
try {
  if (command === 'scan') {
    if (!process.env['VAULT_TOKEN']) throw new Error('VAULT_TOKEN is required');
    const id = store.create(target);
    try {
      const snapshot = await collect(target, process.env['VAULT_TOKEN']);
      const { findings, configuration, identity } = execute(snapshot, store.settings());
      snapshot.identity = identity;
      store.finish(id, snapshot, findings, configuration);
      console.log(
        JSON.stringify({ id, snapshot, findings, configuration }, null, 2),
      );
      process.exitCode =
        snapshot.issues.length || configuration.issues.length
          ? 2
          : findings.some((f) => ['critical', 'high'].includes(f.severity))
            ? 1
            : 0;
    } catch {
      store.fail(id);
      throw new Error('Collection failed');
    }
  } else if (command === 'analyze' && argument) {
    const detail = store.get(argument, target);
    if (!detail?.snapshot) throw new Error('Snapshot not found for VAULT_ADDR');
    const { findings, configuration, identity } = execute(
      detail.snapshot,
      detail.configuration ?? store.settings(),
    );
    console.log(
      JSON.stringify(
        {
          id: argument,
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
        : findings.some((f) => ['critical', 'high'].includes(f.severity))
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
      'Usage: audit scan | list | analyze RUN_ID | rules | configure CONFIG_YAML [CUSTOM_RULES_YAML]',
    );
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Audit failed');
  process.exitCode = 2;
} finally {
  store.close();
}
