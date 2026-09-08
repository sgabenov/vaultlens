import { DEFAULT_SETTINGS, catalog } from './catalog.js';
import type {
  RuleSettings,
  RunConfiguration,
} from '../../shared/auditRules.js';
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import type {
  AuditRun,
  AuditSnapshot,
  AuditFinding,
  AuditDetail,
} from '../../shared/securityAudit.js';
export class AuditStore {
  private db: DatabaseSync;
  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    chmodSync(path, 0o600);
    this.db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS audit_runs (id TEXT PRIMARY KEY, target TEXT NOT NULL, startedAt TEXT NOT NULL, finishedAt TEXT,
      status TEXT NOT NULL, resourceCount INTEGER NOT NULL DEFAULT 0, issueCount INTEGER NOT NULL DEFAULT 0,
      findingCount INTEGER NOT NULL DEFAULT 0, snapshot TEXT, findings TEXT NOT NULL DEFAULT '[]');
      CREATE UNIQUE INDEX IF NOT EXISTS audit_single_running ON audit_runs(status) WHERE status='running';`);
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS audit_settings (revision INTEGER PRIMARY KEY, configYaml TEXT NOT NULL, customRulesYaml TEXT NOT NULL)',
    );
    const columns = this.db.prepare('PRAGMA table_info(audit_runs)').all();
    if (!columns.some((c) => c.name === 'configuration'))
      this.db.exec('ALTER TABLE audit_runs ADD COLUMN configuration TEXT');
  }
  settings(): RuleSettings {
    const row = this.db
      .prepare(
        'SELECT revision,configYaml,customRulesYaml FROM audit_settings ORDER BY revision DESC LIMIT 1',
      )
      .get() as unknown as RuleSettings | undefined;
    return row ?? { ...DEFAULT_SETTINGS };
  }
  saveSettings(next: RuleSettings): RuleSettings {
    catalog(next);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (this.settings().revision !== next.revision)
        throw new Error('Settings changed; reload before saving');
      const saved = { ...next, revision: next.revision + 1 };
      this.db
        .prepare(
          'INSERT INTO audit_settings(revision,configYaml,customRulesYaml) VALUES (?,?,?)',
        )
        .run(saved.revision, saved.configYaml, saved.customRulesYaml);
      this.db.exec('COMMIT');
      return saved;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  list(target: string): AuditRun[] {
    return this.db
      .prepare(
        'SELECT id,target,startedAt,finishedAt,status,resourceCount,issueCount,findingCount FROM audit_runs WHERE target=? ORDER BY startedAt DESC LIMIT 100',
      )
      .all(target) as unknown as AuditRun[];
  }
  get(id: string, target: string): AuditDetail | null {
    const row = this.db
      .prepare('SELECT * FROM audit_runs WHERE id=? AND target=?')
      .get(id, target) as unknown as
      | (AuditRun & {
          snapshot: string | null;
          findings: string;
          configuration: string | null;
        })
      | undefined;
    if (!row) return null;
    const { snapshot, findings, configuration, ...run } = row;
    return {
      run,
      snapshot: snapshot ? JSON.parse(snapshot) : null,
      findings: JSON.parse(findings),
      configuration: configuration ? JSON.parse(configuration) : null,
    };
  }
  create(target: string): string {
    const id = randomUUID();
    this.db
      .prepare(
        "INSERT INTO audit_runs(id,target,startedAt,status) VALUES (?,?,?,'running')",
      )
      .run(id, target, new Date().toISOString());
    return id;
  }
  finish(
    id: string,
    snapshot: AuditSnapshot,
    findings: AuditFinding[],
    configuration?: RunConfiguration,
  ) {
    this.db
      .prepare(
        "UPDATE audit_runs SET status=?,finishedAt=?,resourceCount=?,issueCount=?,findingCount=?,snapshot=?,findings=?,configuration=? WHERE id=? AND status='running'",
      )
      .run(
        snapshot.issues.length || configuration?.issues.length
          ? 'partial'
          : 'completed',
        snapshot.finishedAt,
        snapshot.resources.length,
        snapshot.issues.length + (configuration?.issues.length ?? 0),
        findings.length,
        JSON.stringify(snapshot),
        JSON.stringify(findings),
        configuration ? JSON.stringify(configuration) : null,
        id,
      );
  }
  fail(id: string) {
    this.db
      .prepare(
        "UPDATE audit_runs SET status='failed',finishedAt=? WHERE id=? AND status='running'",
      )
      .run(new Date().toISOString(), id);
  }
  recover() {
    this.db
      .prepare(
        "UPDATE audit_runs SET status='interrupted',finishedAt=? WHERE status='running'",
      )
      .run(new Date().toISOString());
  }
  close() {
    this.db.close();
  }
}
