# Native Security Audit

Upstream proposal: https://github.com/Jasonrve/vaultlens/issues/17

The `/security-audit` page adds configuration assessment separately from Vault request audit logs. The TypeScript collector, rule engine and CLI live in `app/src/server/security-audit`; shared response types live in `app/src/shared/securityAudit.ts`.

## Included

- Read-only API collection of ACL policy source, entities, groups and roles for AppRole, Kubernetes, JWT/OIDC and token auth mounts.
- Four checks: root policy assignments, missing assigned policies, AppRole without SecretID/CIDR bindings, and Kubernetes roles wildcarding both service accounts and namespaces.
- A SQLite snapshot and findings per run, history, severity filtering, collection gap details, and a background worker.
- An offline CLI using the same engine. No Python, Redis or external database is required.
- Missing policy checks are suppressed when the policy inventory is incomplete. Unsupported auth types and failed reads make a run partial.

This remains a partial port of the Python audit tool. See [the parity tracker](audit-parity.md) for the full completion checklist. No effective HCL authorization evaluation, policy-manifest planning, aliases, secret-engine configuration, enterprise namespaces, snapshot diff, exceptions, remediation or cancellation is implemented yet. Rule definitions and configuration are now editable/importable YAML through the Rules and configuration page; execution remains limited to registered native detectors. A completed run means the implemented collection finished; it does not certify the cluster as secure.

## Run

Requires Node.js 22.13 or newer (uses built-in `node:sqlite`). Tested locally with Node 26.0.0 and Vault 1.21.4.

```sh
cd app
npm ci
npm run build
HOST=127.0.0.1 VAULT_ADDR=https://vault.example.com npm start
```

Open `http://127.0.0.1:3001/security-audit` and sign in. This route bypasses the background-service setup wizard, but still requires authentication and server-side administrator authorization (`root` or `vaultlens-admin`, consistent with the existing admin middleware). Direct login from the audit page returns to it.

The audit worker uses the initiating user's token in memory. It does not use the system token, persist login tokens, or collect secret values. Stored resource fields are allowlisted; arbitrary auth configuration and identity metadata are not copied. Policy source is preserved as configuration evidence, so the database is still sensitive.

For a read-only evaluation, leave `VAULT_SYSTEM_TOKEN` and other background-service credentials unset. Existing VaultLens startup behavior with configured service credentials is unchanged and can write service policies or start other background services. Do not interpret this module's read-only collector as making the entire application read-only.

Use `VAULTLENS_AUDIT_DB=/path/to/security-audit.sqlite` to set the database path (default: `app/data/security-audit.sqlite` when started from `app`). The file is created with mode 0600, uses WAL and needs a writable persistent directory. The standard `app/data` directory is ignored by Git.

The initial deployment contract is one application instance and one active audit job. Do not share its database with another server or concurrently running CLI. At first authenticated access after a server restart, stale running jobs are marked interrupted; no credentials are retained to resume them. Completed snapshots remain available. There is no automated retention policy yet; use a separate CLI database for experiments.

All current VaultLens administrators can read snapshots for the configured Vault address. This is not per-user snapshot isolation. Collection privileges can differ from snapshot-viewing privileges; deploy only where this administrator trust boundary is appropriate. Namespace support and finer audit-specific RBAC need a separate change.

Collection is serial in v1 to limit load, and records start/end times rather than claiming atomic consistency. SQLite stores one JSON snapshot per run; large-inventory pagination and storage optimization have not been implemented or load-tested.

## CLI and CI

The CLI reads `VAULT_ADDR` and `VAULT_TOKEN` from the environment. It does not read or write `~/.vault-token`.

```sh
# From app/, after npm run build. Supply VAULT_TOKEN through your normal secret mechanism.
VAULTLENS_AUDIT_DB=/tmp/audit-ci.sqlite npm run audit -- scan
VAULTLENS_AUDIT_DB=/tmp/audit-ci.sqlite npm run audit -- list
VAULTLENS_AUDIT_DB=/tmp/audit-ci.sqlite npm run audit -- analyze RUN_ID
```

Keep the same `VAULT_ADDR` for offline lookup. `analyze` requires no token or network connection and does not overwrite the original findings. To capture clean JSON, invoke `node dist/server/security-audit/cli.js ...` directly; npm prints its own script banner.

Exit codes: 0 = no high findings within implemented checks and complete collection; 1 = high findings; 2 = incomplete collection, failed execution or invalid command. Partial coverage takes precedence over findings. Medium findings remain in the report but do not fail CI in v1.

API endpoints, all protected by authentication and administrator checks:

- `GET /api/security-audit/rules`
- `GET /api/security-audit/runs`
- `POST /api/security-audit/runs` (CSRF protection applies; returns 202 and run ID)
- `GET /api/security-audit/runs/:id`

## Validation

```sh
cd app
npm run test:security-audit
npm run build
```

The initial focused tests cover policy-name handling, suppression under incomplete coverage, AppRole restriction controls, SQLite persistence, target isolation, the single-running-job constraint and interrupted-run recovery.

The initial four-rule live synthetic Vault checks confirmed:

- CLI and UI find the missing policy and unbounded Kubernetes subject in a seeded role.
- CLI exits 1 for that high finding.
- An unauthenticated API request gets 401; a default-policy user gets 403.
- An administrator token without collection privileges produces a partial run with four collection gaps and no fabricated missing-policy finding.
- Browser login, background execution and rendered findings work without a system token.
- Both production and development worker entry points complete against the disposable Vault.
- The new page passes targeted ESLint. Full client typechecking reports the same existing errors as unmodified upstream; the production build and server typecheck pass.

Disposable Vault command (never omit the no-store flag):

```sh
vault server -dev -dev-no-store-token -dev-root-token-id=native-audit-demo -dev-listen-address=127.0.0.1:18200
```

Use only synthetic data and a separate application configuration/database directory for this setup.


## Rule catalog and configuration revisions

`/security-audit/rules` shows the 35 Python rule definitions plus two temporary native configuration checks. This is a catalog migration, not a claim that all detectors have been ported. Pending detectors remain visible; enabling one produces an analysis coverage gap and exit code 2. Collection gaps and analysis gaps are stored separately and displayed together in the report.

Built-in definitions are immutable package defaults. The environment YAML uses the Python vocabulary: profiles, thresholds, AppRole/JWT/Kubernetes settings, privileged policy names/patterns, and per-rule enabled/severity overrides. Not every setting has a consuming native detector yet; pending rules make that limitation explicit.

Custom rules are YAML documents (`version: 1`, `rule: ...`), separated with `---`. Paste text, import a local YAML file, or append the example in the UI. Import replaces the editor contents; it does not save automatically. Save validates all documents and the configuration together. Duplicate IDs, unknown detectors, invalid overrides, YAML aliases and unknown fields are rejected. Custom YAML is limited to 256 KB and 100 definitions.

The `field_compare` detector supports `equals`, `contains`, `missing` and numeric `greater_than` against direct allowlisted snapshot fields. Rules select object types and carry title, remediation, severity and status. This is a declarative extension mechanism, not JavaScript evaluation. New kinds of analysis still require registered native detector implementations.

SQLite retains configuration revisions. Saves use optimistic concurrency: a stale editor receives HTTP 409 instead of overwriting another save. Each run stores its initiating revision, configuration YAML, custom YAML, resolved rule definitions, engine version, fingerprint and analysis gaps. Previous runs are not changed by later saves. This pins configuration, but native detector code still belongs to the installed engine version; full historical engine replay is not claimed.

The CLI shares the same settings and catalog:

```sh
node dist/server/security-audit/cli.js rules
node dist/server/security-audit/cli.js configure audit-config.yml custom-rules.yml
```

The custom file is optional; omitting it preserves the saved custom rules. `analyze` uses the run's saved configuration where available, with saved rule definitions when present and the currently installed engine. Use separate databases for concurrent CLI/server deployments.

Seven focused tests now include catalog parsing, profile/severity overrides, executable-expression rejection, duplicate IDs, custom detector execution, explicit unported coverage, conflicting updates and historical configuration retention. Browser verification covered appending a YAML rule, saving revision 1, and launching a scan with that rule against the synthetic Kubernetes role.


## Authentication detector port

All 19 AppRole, JWT/OIDC and Kubernetes detector implementations are registered natively. Configuration now drives TTL and SecretID thresholds, configured privileged-policy names/patterns, required JWT claims, broad-claim exceptions and approved wildcard namespaces. Kubernetes namespace selectors suppress an otherwise unbounded namespace classification, as in the Python reference. Dynamic detector severity is preserved; an explicit environment severity override takes precedence.

This does not complete privilege analysis: configured privileged policies work, but HCL-derived privilege signals remain pending. Runs with auth detectors explicitly record that dependency as an analysis coverage gap, even when policy findings are disabled. The initial temporary native checks remain separate from the Python rules.

The checked-in synthetic corpus `app/src/server/security-audit/fixtures/auth-parity.json` was generated from Python reference commit `2692356e6d793fe40ed00639ee4551758dc797f9`. It contains 128 cases and 284 expected findings, covering all 19 auth rule IDs. Tests compare rule IDs, severity and structured evidence, including negative boundaries, selectors, glob exceptions, custom thresholds and normalized mount configuration. They do not claim coverage of HCL-derived privilege or end-to-end identity relationships.

Regenerate with a Python 3.11+ environment containing the reference dependencies:

```sh
PYTHONPATH=/path/to/vault-security-audit/src python scripts/generate-auth-parity.py app/src/server/security-audit/fixtures/auth-parity.json
```

The generator is a development-only oracle; the shipped application and CLI remain TypeScript/Node-only. Nine native tests and the production build pass after this increment.


## Policy parser and policy detectors

Nine policy detectors (`POL-001` through `POL-009`) are now native. They preserve the matched policy path, source block, line and attributes. Secret-engine mounts are collected from `sys/mounts` for mount-aware broad-path checks. The UI exposes matched source blocks in findings.

The lexical parser handles quoted strings, literal lists/maps, comments, heredocs and multiple path blocks without interpreting commented-out grants. It retains wrapping/parameter restrictions as structured attributes. Bare expressions outside quoted strings are explicitly unsupported and produce an analysis gap; this is a literal Vault ACL parser, not a general Terraform expression evaluator. Parsing restrictions does not yet implement full request-authorization evaluation.

The policy corpus contains 186 Python-derived cases and 102 expected findings. Source locations, comments and matched blocks are compared alongside rule IDs, severity and evidence. Python-hcl2 8.x keeps quoted attribute lexemes; the generator explicitly decodes these literals for semantic comparison and preserves raw Python attributes separately. A disposable Vault confirmed that decoded allowed/required parameter names accept the allowed value and deny invalid/missing values.

High/critical policy signals now feed auth checks independently of the profile and disabled policy findings. A dedicated integration test confirms a disabled `POL-001` finding still identifies a privileged AppRole through its assigned policy. Parse errors and incomplete policy inventories remain explicit gaps. The previous blanket HCL-privilege implementation gap is removed; six relationship detectors remain pending.

Twelve native tests pass, including the 128 auth cases and 186 policy cases. The default profile can now finish without implementation gaps; that does not imply the extended profile or the overall Python parity checklist is complete.

### Complete report archives

Select **ZIP · complete report** in the audit report format selector to download
one archive containing summaries, coverage, policy usage and risk indexes,
per-resource YAML, the snapshot and JSONL reports. The source-omission checkbox
also applies to ZIP; matched finding evidence remains in the report.

For offline export, run from `app` with the audit database and `VAULT_ADDR`
configured:

```sh
npm run audit -- export-archive RUN_ID report.zip --redact-policy-source
```

The CLI creates a new file with mode 0600 and refuses to overwrite an existing
file. ZIP exports allow up to 5,000 resources and 64 MiB of entry content; use
`export-directory RUN_ID DIRECTORY` for larger reports (up to 50,000 resources).
ZIP entries are stored without compression to limit server CPU work. The bundled
JavaScript dependency `fflate` provides ZIP support; no system archive command or
additional service is required. Report schemas are native VaultLens schemas.

Python SQLite import accepts schemas 2 and 3. Legacy schema-2 snapshots may omit
collection and lifecycle metadata; imported configuration can still be analyzed,
but snapshot comparison requires known collection scope. The source schema is
retained in import provenance. Historical Python findings and baseline controls
are not imported; analysis creates native findings from the observed resources.
