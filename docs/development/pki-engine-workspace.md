# PKI engine workspace

The Secrets Engines list opens PKI mounts in `/secrets/pki/<mount>` with Overview,
Issuers, Roles and Certificates tabs. Other engine routing remains unchanged.
Nested mount paths are supported. Object selection, serial and source identity
are URL parameters so reloads and browser navigation retain the selected object.

`GET /api/pki-engine?mount=...&section=...` is a bounded read-only adapter. It uses
the current user token and configured Vault namespace. It never substitutes the
background system token. Role/issuer reads are independent of certificate LIST
permission. Each Vault endpoint enforces its own access; known object names can be
opened even when listing is denied. Mount identity is checked before and after the
read. The API rejects unsupported sections and path traversal in references.

Lists return 50 references per page. Vault's LIST endpoint still returns the full
list to the backend; frontend paging is not Vault-side pagination, and concurrent
changes may affect page boundaries. For large inventories use the durable catalog
and indexed search in Certificates. Certificate detail reads are bounded to 1 MiB.

The monitoring table and certificate detail have links to the exact engine,
normalized serial and retained record ID. The engine reads the current certificate
from Vault and displays its current validity, revocation observation, PEM and
verified signing issuer where available. The retained monitoring observation is
shown separately; a failed live read does not erase it or masquerade as fresh data.
Different fingerprints are an explicit conflict and are not written back over the
catalog. Cached observations are subject to the existing catalog authorization and
must match the current source and serial before being displayed.

Roles link to their configured `issuer_ref`; certificates link to a signing issuer
only after signature verification. Current role settings do not establish the
historical issuing role. Role attribution remains unknown without issuance evidence.
This follows the separate role, issuer and certificate resources of the
[Vault PKI API](https://developer.hashicorp.com/vault/api-docs/secret/pki).

No issue, sign, revoke, role update, issuer update or tidy operation is introduced.
The PKI engine shares existing runtime configuration and requires no new database
migration or setup wizard. Development remains on `feature/vault-certificate-viewer`,
with local integration in `develop` and publication to origin only.

Verification: the PKI engine API fixture checks role reads without certificate LIST,
issuer reads, direct normalized serial reads, permission denial, replacement mounts,
invalid paths and nested mount links. Existing catalog tests cover observation
retention, export authorization and conflicts. Live UI acceptance is recorded after
integration in the migration plan.
