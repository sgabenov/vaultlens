# Security Audit

Security Audit reviews Vault configuration snapshots for risky policies, role
settings and Identity assignments. It is separate from request audit logs and
from the Permission Tester. A finding is a configuration assessment, not proof
that a particular person can authenticate or exploit the permission.

![Security Audit findings](/screenshots/security-audit-findings.png)

## Start an audit

1. Sign in to VaultLens with a token carrying `root` or `vaultlens-admin`, as
   required by the existing administrator middleware.
2. Open **Security Audit → Findings → Run audit**.
3. Select the namespace and optional filters, concurrency and collection limits.
4. Start the run. Collection and analysis continue in a background worker; you
   can leave the page and return through **Runs**.
5. Review coverage gaps before interpreting the findings. A completed run is not
   a certificate that Vault is secure.

The collector uses the initiating user's token. It does not require the
VaultLens system token or the background-service setup wizard. Administrator
access to the UI does not imply permission to read every Vault configuration
endpoint: denied reads are recorded as coverage gaps.

The collector uses GET/LIST requests for policy source, auth role configuration,
Identity entities/groups/aliases, mounts, PKI roles/public issuer expiry, and
Transit key metadata. It does not read secret values, issue tokens or SecretIDs,
export private keys, or change Vault configuration. Ordinary VaultLens background
services retain their existing behavior if you configure their credentials.

## Workspace tabs

| Tab | Workflow |
| --- | --- |
| Findings | Choose a Run, search/filter findings and group by check or object. Check groups split by actual severity and sort critical first. Expand a finding for its reason, matched HCL block, policy assignments, technical evidence and recommendation. |
| Runs | Select runs, compare two compatible results, or delete selected finished runs. Info shows collection parameters, coverage, metrics and saved configuration. Reanalyze snapshot creates a new run using current saved checks and exceptions without fetching Vault data. |
| Reports | Select a saved run and download JSON, JSONL, YAML, CSV or a complete ZIP report. |
| Checks | Enable built-in checks, change severity, and edit supported parameters. Default severity remains visible. Save the draft before collecting or reanalyzing. |
| Exceptions | Add, edit, search or remove exact check/namespace/object exceptions with owner, reason and expiry. A finding also offers Exclude this object. |
| Sources | Refresh selected sources from an existing native snapshot, or import a compatible Python SQLite snapshot. |

Only the latest 100 runs appear in the run list. Findings and assignments have
client-side pagination; a run's detail is still loaded as one snapshot. Object
links open the current VaultLens object in a new tab, not its historical state.
Cross-namespace object links are omitted because existing object pages do not
accept the snapshot namespace.

![Security Audit checks](/screenshots/security-audit-checks.png)

## Checks and severity

The catalog covers Policies, AppRole, Kubernetes, JWT/OIDC, Token, Identity, PKI,
Transit and Assignments. Specialized checks include secrets-engine management,
token issuance/lifetime, inherited Identity privileges, certificate name/lifetime
restrictions, CA expiry, key exportability/deletion and rotation age.

The default profile enables stable rules. Review and experimental checks need an
explicit enable override or the extended profile. Enable them deliberately for
your environment; broad domain permissions or periodic tokens may be justified.
Some detectors select severity from the evidence. A saved severity override
replaces that selection. Temporal checks use the snapshot's collection end time.

Built-in rule definitions are package defaults. The UI saves environment
configuration revisions rather than modifying the definitions. Advanced custom
YAML is supported through the API/CLI for registered declarative detectors; the
current Checks UI focuses on built-in checks. Uploading executable plugins or
JavaScript is not supported.

## Exceptions and history

Exceptions match a check, namespace and exact Vault API object path. Wildcards in
that path are literal for UI-created exceptions. `root` and `default` policies
are not automatically excluded. Exceptions apply to future analysis: editing an
exception does not rewrite a historical report. Expired exceptions remain visible
for review. Reanalyze to evaluate the current saved exception set.

Reanalysis preserves collection timestamps and records a source run. Native
engine code comes from the installed application; pinning the configuration does
not retain executable copies of older engines. Run comparison requires matching
configuration/engine fingerprints and compatible collection coverage. A removed
finding means it was not observed in the comparison; it does not prove remediation.

## Deployment and storage

Requires Node.js 22.13 or newer. The existing Node 22 Docker image is supported.
There is no PostgreSQL, Redis, Python runtime or external queue requirement.

```sh
cd app
npm ci
npm run build
HOST=127.0.0.1 VAULT_ADDR=https://vault.example.com \
  VAULTLENS_AUDIT_DB=/var/lib/vaultlens/security-audit.sqlite npm start
```

Provision the writable database directory first. Without `VAULTLENS_AUDIT_DB`,
the path is `data/security-audit.sqlite` relative to the application working
directory. SQLite uses WAL; persist the directory, not just the main file. The
file is created with mode 0600. Back up with the process stopped or a SQLite-aware
backup, including WAL state. There is no automatic retention or encryption at
rest. Reports and policy source should be treated as sensitive configuration.

Use one application instance per database. All VaultLens administrators can read
snapshots for the configured Vault address, even if their own collection token
has fewer permissions. This is an administrator trust boundary, not per-user or
per-namespace report isolation. Do not run a writing CLI against the live web
server's database. After a restart, stale running jobs become interrupted; no
credentials are retained. Resume requires a valid initiating token again.

## Coverage limits

- Collection is not atomic; resources may change while they are read.
- Literal ACL parsing and observed assignments do not reproduce all Vault ACL
  precedence, parameter constraints, templating or effective token permissions.
- Missing data and unsupported syntax are coverage gaps. Incomplete inventories
  suppress absence-based findings where completeness is required.
- Refresh retains previously observed resources when selected collection fails;
  retained data is not evidence of current existence or deletion.
- PKI/Transit checks require a fresh snapshot with engine configuration metadata.
  Reanalyzing an older snapshot reports the missing coverage.
- Large-cluster performance, multiple web instances and automated remediation are
  outside this first implementation. No remediation buttons write to Vault.

See [architecture](../architecture/security-audit.md) for extension points,
[CLI and development](../development/security-audit.md) for commands, and
[local lab](../development/audit-lab.md) for disposable test data.
