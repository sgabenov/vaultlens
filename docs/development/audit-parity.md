# Python audit parity tracker

Reference: local vault-security-audit Python implementation, inspected 2026-09-08. This is the completion checklist, not a description of already implemented behavior.

| Requirement | Evidence needed | State |
| --- | --- | --- |
| All 35 rules: POL-001..015, APPROLE-001..008, JWT-001/002/003/005/006, K8S-001..006, REF-001 | Equivalent findings on shared fixtures, negative cases and Vault-confirmed disputed semantics | Pending |
| HCL parsing with source locations, attributes and parse diagnostics | Comment, wildcard, template and restriction fixtures | Pending |
| Policy privilege signals and escalation relationships | Cross-policy, role, entity and group fixtures | Pending |
| Collection: policies, mounts, auth config/roles, identity and aliases | Supported-source coverage and redaction checks | Partial: initial selected sources |
| Namespace recursion/filtering, policy/auth filters, limits, skip identity, source redaction | Collector integration fixtures | Pending |
| Bounded workers, rate limit, timeout, retries, max duration, progress | Fault-injection tests | Partial: serial reads and request timeout |
| Checkpoint/resume with max age and partial failures | Interrupted collection recovery test | Pending |
| Collect, scan, analyze, selective refresh into a new snapshot | CLI and UI workflows | Partial: scan/analyze |
| SQLite import/compatibility with existing Python snapshots | Real schema fixture, counts, normalized findings | Pending |
| Offline snapshot diff | Added/removed/changed object and finding fixtures | Pending |
| Baseline create/apply and expiring exceptions | Suppression/fingerprint/expiry tests | Pending |
| Profiles, thresholds, privileged-policy settings, severity/enabled overrides | Configuration validation and equivalent configured results | In progress |
| Rule catalog browse, YAML import, extension and configuration through UI | Browser create/edit/save/run workflow and immutable run revision | Implemented initial YAML catalog/editor/import, custom field detector, revisions; full detector parity pending |
| JSON and other Python export formats, fail-on and require-complete controls | CLI export/exit-code fixtures | Partial: JSON, fixed high threshold |
| Persistent run history, filtering and access control | Browser/API tests | Initial implementation |
| Production build, native-only runtime, documentation and commits | Clean build, runtime demo, parity evidence | Initial implementation |

The Python implementation is a behavioral reference, not an infallible authorization oracle. Corrected semantics must be recorded and verified against Vault rather than preserving known false positives or false negatives. Existing request-audit logs and live management views remain separate.
