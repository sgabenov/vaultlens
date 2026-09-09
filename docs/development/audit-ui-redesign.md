# Web audit redesign

The agreed scope is a web-only workflow inside the existing VaultLens shell:
Findings, Runs, Checks and Sources use internal navigation. Checks are built into
code, grouped by Policies, AppRole, Kubernetes, JWT/OIDC, Token, Identity and
assignments. Users can enable checks/categories, change severity and supported
parameters. One settings set applies to the current Vault; each run pins its
revision. Findings need grouping (check first, object optional), filters, search
and pagination for large results. Object exceptions require a reason and expiry;
root/default policies are not silently excluded. CLI/CI, plugins and automatic
remediation are outside this stage. Keep collection/analysis reusable without
adding architecture solely for optional future integrations.

## Implemented first slice

Shared audit navigation and dedicated Runs/Sources pages now use nested routes.
Findings accepts a run query parameter. Tab links carry the explicitly selected
run, and Runs links directly to a stored result. The original rules URL redirects
to Checks. Sources contains Python snapshot upload and routes successful imports
to their own run. Existing analysis/collection operations remain available.

Production build passed. Browser checks opened Runs, selected a historical run
with three findings and switched to Sources with its run ID retained. No new
collection was launched during this verification.

## Remaining UI work

Replace the old YAML/custom-rule Checks editor with the agreed built-in controls;
add grouped/paginated findings and object-exception forms; move collection setup
and start actions into a coherent run dialog; add run pagination and preserve
unsaved input when navigating. The first slice does not claim mockup parity.
The mockup remains a design reference with synthetic data, not engine evidence.

## Built-in Checks editor

The YAML/custom-rule editor has been replaced by built-in categories, category
and individual enable controls, severity overrides, AppRole parameters and shared
token lifetime thresholds. Existing configuration fields are retained through
YAML document edits and the existing revision-checked API. If legacy custom rules
exist, the UI explains that saving disables them for future analyses while
retaining their definitions for compatibility. No custom rule creation/import UI
remains. Categories without dedicated checks show an explicit empty state.

Production build passed. Browser inspection verified the catalog and AppRole
category toggle (3/9 to 9/9 with an unsaved-change indicator); the test draft was
closed without changing the user's saved settings. A configuration round-trip
against the native catalog verified category enablement, severity and duration
changes while preserving unrelated policy checks. Saving through this new form
still requires end-to-end acceptance. JWT/Kubernetes list settings, privileged
policy selectors, object exceptions and unsaved-navigation handling remain to be
completed. This supersedes the earlier note that the old Checks editor remains.

## Findings grouping

Findings now default to groups by check, with object grouping and an ungrouped
mode. Search covers check title/ID, object path and namespace; filters cover
severity, namespace and category from the run's pinned catalog. Both groups and
objects inside an expanded group are paginated (10/25/50). Group severity is the
highest matching finding severity. Object grouping includes namespace in its key.
Evidence, matched ACL blocks, recommendations and related objects remain available
through disclosure panels. Filtering resets page/expanded group state.

Production build passed. A 1,200-finding fixture verified group counts, highest
severity ordering, namespace isolation and input immutability. Browser acceptance
of pagination is pending. Pagination bounds rendering, not network payloads:
the current run detail API still returns the full snapshot/findings. Historical
catalogs missing rule metadata cannot support category classification. Exception
status filtering and creation are still pending; existing historical controls
remain accessible outside the findings panel.

## Historical exception visibility

Run detail responses now include finding controls matched by fingerprint, rather
than assuming the stored control and finding arrays share an order. Conflicting
states for the same fingerprint yield an unknown status. Findings adds
Open/Excluded/Unknown filtering, per-object status, exception reason/owner/expiry
and the historical evaluation date. Missing controls in a run that declares
controls are shown as unknown, not silently open or excluded. Old runs without
controls remain open. No exception is inferred from the policy name.

Production build and focused checks passed for reordered findings, namespace
isolation, retained historical expiry and ambiguous states. The running backend
must be restarted to serve the new derived field; until then affected historical
runs show Unknown. This does not yet provide exception creation or persistence
through a form.

## Persistent object exceptions

An individual finding now offers an owner/reason/expiry form. The backend derives
rule/namespace/object from a target-scoped finished run, validates it against the
built-in catalog and stores an exact-match exception in SQLite for that Vault.
Literal wildcard characters do not broaden its scope; root namespace and a
namespace named root remain distinct. New web analyses merge saved exceptions
with any legacy explicitly supplied controls. Historical results stay immutable.
Checks includes a searchable, paginated list with expiry and removal actions.
There is no implicit exception for root/default policies.

All 55 native tests passed, including persisted exact scope, duplicate rejection,
target isolation, reopening the store and scoped removal. Production build and
subsequent client/server builds passed. The demo backend was restarted after
verifying no active runs. API create/list/delete was exercised on a temporary
exception derived from a stored finding, then the original exception list was
restored. Derived historical controls now reach the running API. Full browser
form submission/reanalysis and editable existing exceptions remain pending.

## Collection dialog

Findings, Runs and Sources now open a shared collection dialog. Namespace and
recursive collection are primary controls; scope filters and resource limits are
under Advanced collection settings. Starting successfully closes the dialog and
selects the new run. Failed run-list requests are shown inside the dialog, and
invalid advanced inputs expand their section so browser validation is visible.
Millisecond fields accept integer values, including the default request timeout
and collection duration (their previous step bases rejected these defaults).

Production and client builds passed. Browser acceptance started collection with
unchanged defaults against the local development Vault and navigated to the new
result. API readback confirmed run 0c72eaca-53f6-4468-b6ec-028551f0ed78 completed
with 12 resources, 5 findings and no collection issues. No external Vault was used.

## Remaining built-in list parameters

Checks now exposes JWT broad claim values, review-only glob claim names, required
bound claims per exact auth mount, Kubernetes namespaces permitting wildcard
service accounts, and shared privileged-policy exact names/patterns. Lists use
one value per line; blank lines and duplicates are normalized without disrupting
text entry. Required-claim mount entries can be added and removed. Auth prefixes
and trailing slashes are normalized for new entries to match the detector's
mount lookup. Privileged selectors classify policy assignments; they are not
exceptions. Existing unsupported custom/plugin creation remains out of scope.

Production and final client builds passed. Browser form acceptance saved two
required claims under a temporary mount in revision 3; API readback confirmed
both values. Reanalysis cfc95d38-8bc9-4f6e-826b-25a102ac45b8 completed with that
revision pinned. The temporary mount was removed through the UI and saved in
revision 4; API verification confirmed cleanup and the unchanged revision 3
historical run. No actual Vault configuration was modified.

## Drafts across audit navigation

The audit workspace now owns the Checks draft, selected category and selected
check. Internal tab navigation preserves these values without writing them to
server storage. Discard changes restores saved settings, including list editor
contents. A newer server revision is reported as a conflict; the existing
revision-checked save endpoint remains authoritative. Save-in-progress state is
shared so returning to Checks cannot edit or discard an in-flight save.
Drafts last while the Security Audit workspace remains mounted; the UI explicitly
asks users to save before leaving the workspace or reloading.

Production build passed. Browser verification disabled POL-001 in a draft,
switched to Runs, returned to Checks and confirmed the disabled check and unsaved
indicator were retained. Discard restored 13 enabled checks and revision 4
without saving a new configuration revision.

## Object exception browser acceptance

The complete exception workflow was verified against the local development run:
open POL-003, expand its policy finding, enter owner/reason/expiry and save the
exact object exception. The UI confirmed that the historical result was unchanged.
Reanalysis started from the UI completed as 2e0fe1b8-78ba-4dc6-8812-10f5dbcf98af.
The Excluded filter displayed exactly one of five findings, and its object row
showed Excluded. API readback independently confirmed one suppressed finding and
zero suppressed findings in the source run.

The saved entry was then removed through Checks. A new API-triggered reanalysis
9149261c-3ca0-4445-95ab-758b57326c39 completed with no excluded findings. The prior
analysis still retained its one historical exclusion, and the saved exception
list was restored to empty. This verifies create, apply, filter and remove; it
does not claim editing an existing exception or browser acceptance of large-list
pagination. No Vault configuration was changed.
