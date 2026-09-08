import { AuditStore } from './store.js';
import { collect } from './collector.js';
import { analyze } from './engine.js';
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
      const findings = analyze(snapshot);
      store.finish(id, snapshot, findings);
      console.log(JSON.stringify({ id, snapshot, findings }, null, 2));
      process.exitCode = snapshot.issues.length
        ? 2
        : findings.some((f) => f.severity === 'high')
          ? 1
          : 0;
    } catch {
      store.fail(id);
      throw new Error('Collection failed');
    }
  } else if (command === 'analyze' && argument) {
    const detail = store.get(argument, target);
    if (!detail?.snapshot) throw new Error('Snapshot not found for VAULT_ADDR');
    const findings = analyze(detail.snapshot);
    console.log(
      JSON.stringify(
        { id: argument, findings, issues: detail.snapshot.issues },
        null,
        2,
      ),
    );
    process.exitCode = detail.snapshot.issues.length
      ? 2
      : findings.some((f) => f.severity === 'high')
        ? 1
        : 0;
  } else if (command === 'list')
    console.log(JSON.stringify(store.list(target), null, 2));
  else throw new Error('Usage: audit scan | list | analyze RUN_ID');
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Audit failed');
  process.exitCode = 2;
} finally {
  store.close();
}
