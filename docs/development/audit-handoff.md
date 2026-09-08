# Security audit handoff — 2026-09-08

## Resume intent

The user requested saving the current state and continuing later. Stop implementation after this handoff. The overall objective remains unfinished: native TypeScript security audit with functionality comparable to the Python utility, including viewing, configuring and extending audit rules through the UI. Do not claim parity based on rule counts or passing tests alone.

## Checkout and reference

- Checkout: `/Users/gabenov.s/git/github/sgabenov/vaultlens`
- Branch: `feature/native-security-audit`
- Last implementation commit: `3513cc9`
- Origin: `sgabenov/vaultlens`; upstream: `Jasonrve/vaultlens`.
- Python reference: `/Users/gabenov.s/git/wb/vault/vault-security-audit`.
- Upstream feature request: https://github.com/Jasonrve/vaultlens/issues/17
- Changes are committed locally. No push or implementation PR has been performed in this work sequence. Ask before pushing unless the user gives fresh authorization.
- Repository material is English; conversation is Russian. Prefer substantive checks over trivial tests. No delegated agents unless requested.

## Implemented

- Shared native TypeScript engine for Web UI and CLI; 35 Python builtin rules plus two native rules. Current engine version 12.
- YAML rule catalog/configuration, custom field-comparison rules, validated changes, immutable revisions and pinned configuration for historical runs. UI catalog browse/edit/import and custom-rule save/reanalysis were exercised.
- Collection of ACL policies, auth mounts/roles, secret mount metadata, Identity entities/groups/aliases, policy assignments and inheritance. Secret values and SecretIDs are not collected; RoleID/alias associations use hashes.
- Scoped and recursive namespace collection; filters, concurrency, shared rate limits, retries, deadlines and object budgets.
- SQLite run history without PostgreSQL/Redis, worker progress, checkpoints, resume and selective refresh into separate snapshots; retained-resource timestamps.
- Offline analysis and diff, native baselines, expiring exceptions and configurable CI gates.
- Python SQLite schemas 2 and 3 import for native reanalysis, including web upload. Original Python findings and controls are not migrated.
- JSON/JSONL/YAML/findings CSV, linked directory reports and ZIP export; optional omission of full policy source. Native report formats are not guaranteed Python machine-schema compatible.
- CLI help: `npm --prefix app run audit -- --help`. Help and invalid arguments do not create a database.

## Latest verification

- 54/54 native tests and server TypeScript compilation passed; log `/tmp/vaultlens-import-coverage-tests.log`.
- Last full production build passed at the ZIP implementation stage: `/tmp/vaultlens-archive-build.log`. Subsequent changes are primarily server/CLI/shared type changes; do not imply a newer full build was run.
- Full frontend tsc has known upstream errors; production Vite build passing is not equivalent to a clean frontend type check.
- ZIP verified with independent Python zipfile reader, including integrity and HCL omission. Browser-managed ZIP download is still unverified.
- Python detector oracle fixtures: auth 128 cases, policy 186 cases, relationships 40 cases, missing references 16 cases, acyclic Identity 8 cases. These demonstrate fixture agreement, not complete authorization semantics.
- Browser previously exercised policy usage, scoped scan, custom rule edit/save/reanalysis and diff. Several newer controls were verified through APIs rather than browser interaction.
- Latest import fix preserves contradictory coverage metadata but marks native coverage incomplete: count mismatches and duplicate namespace/source records cannot establish absence of policies or aliases.

## Local demo (revalidate before use)

- User-visible UI: http://127.0.0.1:18302/security-audit
- Dev Vault: http://127.0.0.1:18200
- At handoff, listeners verified: UI Node PID 63069; Vault PID 38139.
- UI database: `/tmp/vaultlens-diff-ui.sqlite`.
- UI backend process predates several recent changes. Current static build and running backend can differ. Rebuild/restart deliberately before acceptance testing; check listener ownership before terminating anything.
- Dev login token was supplied in the conversation; do not add credentials to the repository. Namespace is empty. This demo is not production Vault.
- Other development instances may exist on 18301/18303/18304; rediscover them, do not assume their handles remain live.
- Main Dashboard requires upstream system-token/AppRole setup. Security Audit intentionally uses the logged-in user's token without that setup; backend validates lookup-self and requires root or vaultlens-admin.
- Lens Audits is VaultLens's own activity log; Audit Log displays Vault audit-device requests; Security Audit is this configuration-analysis module. No label rename was requested or implemented.

## Next work, in priority order

1. Consolidate a stable demo and run a complete browser acceptance scenario against the latest backend: collection, rules/config import and edit, reanalysis, findings/coverage/usage, Python upload, diff, baseline/exceptions, resume, refresh and downloads. Preserve original snapshots and active rule settings during tests.
2. Reconcile the Python feature checklist with current code and actual reference behavior. `audit-parity.md` is an accumulated evidence log with stale earlier pending statements; rewrite its top-level status matrix before using it as the completion checklist.
3. Investigate effective ACL precedence, deny, parameter constraints and sudo in relationship findings. Current relationship checks model declarations; they do not prove an executable escalation. Validate disputed cases against Vault rather than blindly matching Python.
4. Complete refresh/merge edge cases: partial read failures, removal evidence, obsolete retained gaps, namespace discovery changes and Python differential fixtures. Broaden interruption/resume failure injection beyond normal process exit.
5. Verify Enterprise namespace/scoped-auth behavior when a suitable environment exists. Local fake HTTP tests are not Enterprise acceptance evidence.
6. Check import/export fidelity and decide remaining Python machine-format compatibility work from the reference requirements. Historical findings/control migration and Python baseline compatibility remain absent.
7. Validate rule profile/threshold/severity configuration equivalence more broadly; finish reusable controls configuration UX where required by reference scope.
8. Review runtime robustness (including extremely low request-rate timer overflow), large-data behavior and remaining browser-only gaps. Finish coherent user docs and prepare a reviewable PR only after authorization to publish.

Batch remediation and arbitrary Vault writes are not implemented. Do not quietly expand read-only audit into automatic changes. Determine whether remediation is required for Python parity or remains the user's earlier future direction.

## Useful commands

From the checkout:

```sh
npm --prefix app run test:security-audit
npm --prefix app run build
npm --prefix app run audit -- --help
git status --short
```

Use a separate SQLite database for CLI writes when the web server is running. Tokens are required only for live collection/resume/refresh; offline commands still select their target through VAULT_ADDR. Read `docs/development/security-audit.md` for usage and `docs/development/audit-parity.md` for detailed evidence and limitations.
