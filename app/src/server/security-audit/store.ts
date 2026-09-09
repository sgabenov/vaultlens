import { withoutPolicySource } from './sourceRedaction.js';
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
  AuditException,
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
    this.db.exec('CREATE TABLE IF NOT EXISTS audit_object_exceptions (target TEXT NOT NULL, id TEXT NOT NULL, scope TEXT NOT NULL, entry TEXT NOT NULL, PRIMARY KEY(target,id), UNIQUE(target,scope))');
    const columns = this.db.prepare('PRAGMA table_info(audit_runs)').all();
    if (!columns.some((c) => c.name === 'configuration'))
      this.db.exec('ALTER TABLE audit_runs ADD COLUMN configuration TEXT');
    if (!columns.some(c => c.name === 'failureReason'))
      this.db.exec('ALTER TABLE audit_runs ADD COLUMN failureReason TEXT');
    if (!columns.some(c => c.name === 'progress'))
      this.db.exec('ALTER TABLE audit_runs ADD COLUMN progress TEXT');
  }
  exceptions(target:string):AuditException[] {
    return this.db.prepare('SELECT entry FROM audit_object_exceptions WHERE target=? ORDER BY id').all(target).map(row=>JSON.parse(String(row.entry)));
  }
  addException(target:string,entry:AuditException):void {
    const scope=JSON.stringify([entry.rule_id,entry.namespace,entry.object_path,entry.policy_path??null]);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if(this.exceptions(target).length>=1000)throw new Error('At most 1000 object exceptions are supported');
      if(this.db.prepare('SELECT id FROM audit_object_exceptions WHERE target=? AND scope=?').get(target,scope))throw new Error('An exception already exists for this check and object');
      this.db.prepare('INSERT INTO audit_object_exceptions(target,id,scope,entry) VALUES(?,?,?,?)').run(target,entry.id,scope,JSON.stringify(entry));
      this.db.exec('COMMIT');
    } catch(error) {this.db.exec('ROLLBACK');throw error;}
  }
  updateException(target:string,entry:AuditException):boolean {
    const scope=JSON.stringify([entry.rule_id,entry.namespace,entry.object_path,entry.policy_path??null]);
    return this.db.prepare('UPDATE audit_object_exceptions SET scope=?,entry=? WHERE target=? AND id=?').run(scope,JSON.stringify(entry),target,entry.id).changes>0;
  }
  removeException(target:string,id:string):boolean {
    return this.db.prepare('DELETE FROM audit_object_exceptions WHERE target=? AND id=?').run(target,id).changes>0;
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
        'SELECT id,target,startedAt,finishedAt,status,resourceCount,issueCount,findingCount,failureReason FROM audit_runs WHERE target=? ORDER BY startedAt DESC LIMIT 100',
      )
      .all(target) as unknown as AuditRun[];
  }
  deleteRuns(target:string,ids:string[]):number {
    if(!ids.length||ids.length>100||new Set(ids).size!==ids.length)throw new Error('Select between 1 and 100 distinct runs');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if(this.db.prepare("SELECT id FROM audit_runs WHERE target=? AND status='running'").get(target))throw new Error('Wait for the active audit to finish before deleting runs');
      const lookup=this.db.prepare('SELECT id FROM audit_runs WHERE target=? AND id=?');
      for(const id of ids)if(!lookup.get(target,id))throw new Error('A selected run is unavailable. Refresh the list and try again');
      const remove=this.db.prepare('DELETE FROM audit_runs WHERE target=? AND id=?');
      for(const id of ids)remove.run(target,id);
      this.db.exec('COMMIT');return ids.length;
    } catch(error){this.db.exec('ROLLBACK');throw error;}
  }
  get(id: string, target: string): AuditDetail | null {
    const row = this.db
      .prepare('SELECT * FROM audit_runs WHERE id=? AND target=?')
      .get(id, target) as unknown as
      | (Omit<AuditRun,'progress'> & {
          progress: string|null;
          snapshot: string | null;
          findings: string;
          configuration: string | null;
        })
      | undefined;
    if (!row) return null;
    const { snapshot, findings, configuration, progress, ...run } = row;
    return {
      run:{...run,progress:progress?JSON.parse(progress):null},
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
        snapshot.analysisPerformed === false ? 'collected' : snapshot.issues.length || configuration?.issues.length
          ? 'partial'
          : 'completed',
        snapshot.sourceRunId ? new Date().toISOString() : snapshot.finishedAt,
        snapshot.resources.length,
        snapshot.issues.length + (configuration?.issues.length ?? 0),
        findings.length,
        JSON.stringify(snapshot.collection?.requestPolicy.redactPolicySource ? withoutPolicySource(snapshot) : snapshot),
        JSON.stringify(findings),
        configuration ? JSON.stringify(configuration) : null,
        id,
      );
  }
  saveCheckpoint(id:string,snapshot:AuditSnapshot) {
    const saved=snapshot.collection?.requestPolicy.redactPolicySource ? withoutPolicySource(snapshot) : snapshot;
    this.db.prepare("UPDATE audit_runs SET snapshot=?,resourceCount=? WHERE id=? AND status='running'")
      .run(JSON.stringify({...saved,analysisPerformed:false,finishedAt:'',policiesComplete:false}),snapshot.resources.length,id);
  }
  updateProgress(id:string,progress:import('../../shared/securityAudit.js').AuditProgress) {
    this.db.prepare("UPDATE audit_runs SET progress=?,resourceCount=? WHERE id=? AND status='running'").run(JSON.stringify(progress),progress.resources,id);
  }
  fail(id: string, reason='The background audit stopped before completion.') {
    this.db
      .prepare(
        "UPDATE audit_runs SET status='failed',finishedAt=?,failureReason=? WHERE id=? AND status='running'",
      )
      .run(new Date().toISOString(), reason, id);
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
