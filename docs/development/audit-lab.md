# Local audit lab

`scripts/seed-audit-lab.mjs` populates the loopback development Vault at
`http://127.0.0.1:18200`. It requires Node.js and a privileged `VAULT_TOKEN` from
the environment. It refuses other addresses and non-root namespaces.

```sh
VAULT_ADDR=http://127.0.0.1:18200 node scripts/seed-audit-lab.mjs
```

The fixtures deliberately grant dangerous capabilities. All created names or
auth mount paths use `audit-lab-`; the script does not issue login tokens or
SecretIDs, alter existing audit devices, or change VaultLens settings. Re-running
resets the lab definitions. The development Vault is ephemeral; rerun after it
restarts. Do not use these fixtures in production.

## Imported policies

Source: [hashicorp-vault-policy-auditor/test_policies](https://github.com/manjula-aw/hashicorp-vault-policy-auditor/tree/43163570bc8e23cfe3986b1369dbfc59a08be6bf/test_policies).
The script downloads 17 HCL files at this pinned commit, with an ownership comment.
It does not execute upstream scripts or vendor upstream source into this repository.

Vault 1.21.4 rejects `capabilities = ["*"]` in `lazy_admin_wildcard.hcl` and
`mixed_capability_star.hcl`. These become explicitly named `-expanded` variants
with create, read, update, delete, list, sudo and patch capabilities. These are
adapted fixtures, not exact imports. Rejections and the file-to-policy mapping
are saved to `/tmp/vaultlens-audit-lab-manifest.json`.

## Scenarios

| Objects | Purpose |
| --- | --- |
| AppRole: weak-admin, cidr-only-admin | Privileged policies, unlimited SecretID reuse/lifetime, missing SecretID binding with a loopback CIDR, long token lifetime |
| AppRole: bounded-reader | Short-lived, single-use SecretID and limited policy comparison |
| AppRole: missing-policy | Reference to an intentionally absent policy |
| Kubernetes: wildcard-admin, bounded-reader | Wildcard subjects versus one service account and namespace |
| JWT: broad-admin, bounded-reader | Broad claim glob and no audience versus restricted claims and audience |
| Token: audit-lab-issuer, audit-lab-bounded-issuer | Allowed policy issuance, orphan/periodic versus bounded lifetime |
| Entities: operator, reader, inherited-admin, disabled-operator, dangling-reference | Direct, inherited, disabled and missing-policy assignments |
| Groups: team, platform-admins | Parent group privileges inherited through a child group by its entities |
| Groups: key-operators, policy-catalog, external-team | Additional direct assignments, all imported policies, external group alias |
| JWT entity/group aliases | Links from identities to the dedicated JWT mount |

Entity and group names above have the `audit-lab-` prefix. AppRole, Kubernetes and
JWT roles live under `auth/audit-lab-<type>/`; the two token roles use the existing
token mount. Kubernetes is configured for role inspection only, without a real
cluster connection. JWT has a synthetic issuer and a public verification key;
the signing key is not retained. These are configuration-audit fixtures, not
end-to-end authentication fixtures.

## Verified collection on 2026-09-09

Run `596175fb-7a25-465e-8e92-6d1a522bb9a0` completed against the existing local
instance with **53 resources, 27 findings and 0 coverage gaps**. Counts include
pre-existing VaultLens objects. Identity collection recorded **29 direct and 16
inherited assignments**.

The saved settings had **13 of 37 checks active**; seeding did not change them.
The run produced APPROLE-001, APPROLE-008, JWT-006, K8S-004, POL-001 through
POL-005, and REF-001 findings. A fixture without a finding is not evidence that
all possible checks passed. Use Checks to enable additional rules, then
Runs → Info → Reanalyze snapshot to evaluate them on the collected data.

## Management checks added on 2026-09-10

POL-016 through POL-020 review Identity administration, Transit key management,
Database role/configuration changes, PKI administration/signing, and KV v2
metadata deletion/version destruction. They are review rules, enabled explicitly
on this local instance alongside POL-008/009. Existing settings are preserved.
Engine version is 13; historical runs retain their original configuration.

The lab now also creates four `audit-lab-` secret mounts and an
`audit-lab-engine-management` policy assigned to the operator entity. They hold
no real keys, database connections, certificates or secret values.

The detectors use observed mount types and namespaces, not conventional mount
names. Read-only access, deny blocks, ordinary Transit encryption, Identity
lookup and KV metadata update alone are not flagged by these new rules. Global
wildcards remain covered by POL-001. Findings indicate sensitive permissions to
review, not proven exploitable escalation. Missing mount inventory cannot prove
absence of management permissions. PKI signing is intentionally a review rule;
role constraints still need human inspection. New rules were independently
implemented from the reviewed concepts, without copying upstream Python code.
