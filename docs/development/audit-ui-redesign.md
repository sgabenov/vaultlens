# Web audit workspace

## Scope

Security Audit uses the existing VaultLens shell with five internal routes:
Findings, Runs, Checks, Exceptions and Sources. This stage manages built-in checks through the
web interface. CLI/CI integrations, plugin authoring and automatic remediation
are outside the agreed scope. Collection and analysis remain shared native
TypeScript services. SQLite and a local worker thread require no PostgreSQL or
Redis service.

## Implemented behavior

- Findings groups results by check by default, with object and ungrouped modes.
  Search, severity, namespace, category and exception-status filters combine.
  Groups and their object rows use 10/25/50-row pagination. Evidence, matching
  policy blocks, recommendations and related objects expand on demand.
- Runs links to immutable saved results and paginates the most recent 100 runs.
  The selected run is retained in navigation links between audit tabs.
- Checks lists built-in rules under Policies, AppRole, Kubernetes, JWT/OIDC,
  Token, Identity and Assignments. Individual and category toggles, severity
  overrides and supported parameters apply to new analyses. Categories without
  dedicated checks say so explicitly; collection is not a passing check.
- One saved configuration serves the current VaultLens Vault connection. Each
  analysis pins its configuration revision and catalog. Revision-checked saves
  prevent overwriting newer settings. The UI has no plugin/custom-rule creation;
  saving legacy configurations disables their custom definitions for future
  analysis while preserving historical definitions.
- Checks exposes AppRole limits, shared token TTL thresholds, JWT claim lists,
  required bound claims per exact auth mount, allowed Kubernetes namespaces and
  privileged-policy exact names/patterns. Privileged selectors classify policies;
  they do not exclude them. New JWT mount entries normalize auth/ and slashes.
- Checks drafts, selected categories and selected checks survive internal tab
  navigation. Discard restores saved settings. Drafts are held only while the
  workspace is open; the UI states that reload/leaving requires saving first.
- Findings, Runs and Sources open the collection dialog using the current Vault
  session. Namespace/recursive collection are primary options; resource limits,
  scope filters and redaction are under Advanced collection settings. Browser
  validation expands invalid advanced fields. Successful start selects its run.
- Collection runs in a worker, stores snapshots and reports progress and coverage
  gaps. Missing data never establishes absence. Secret values are not collected.
  Sources also exposes the existing Python snapshot import workflow.
- Exact object exceptions are created from a finding with owner, reason and
  expiry. Scope is derived server-side from the selected stored finding. Literal
  wildcards stay literal, and the empty root namespace differs from a namespace
  named root. No root/default-policy exception is added implicitly. Exceptions creates, edits, lists, searches and removes saved exceptions. New analyses apply the current list;
  historical exception states remain unchanged and can be filtered as Excluded.

## Acceptance evidence

Production build passed after the final UI edits. All 55 native audit tests passed
with no skips or failures. The suite covers catalog/override validation, detector
behavior, collection coverage, snapshot reuse, imports and exact exception
persistence. The full client TypeScript check still has pre-existing upstream
errors; the Vite client build and server TypeScript build pass.

Browser/API checks used only the local development Vault at 127.0.0.1:18200 and
VaultLens at 127.0.0.1:18302. No production Vault configuration was changed.

| Requirement | Verified evidence |
| --- | --- |
| Four internal tabs and selected-run navigation | Browser Runs selection opened Findings and carried the run query into Sources; Checks/Runs round trip retained the draft. |
| Collect using the current session | Browser default collection completed as 0c72eaca-53f6-4468-b6ec-028551f0ed78: 12 resources, 5 findings, no collection issues. |
| Editable lists and immutable revision | Browser saved two required claims in revision 3. Reanalysis cfc95d38-8bc9-4f6e-826b-25a102ac45b8 pinned revision 3. Removing the temporary mount saved revision 4 without changing that run. |
| Toggle and severity affect analysis | Browser disabled POL-003 and set POL-002 to low in revision 5. Run f3627d33-aeac-48ac-a1d5-adaa3540ebf9 had no POL-003 finding and two low POL-002 findings. The source retained POL-003 and high POL-002. Original configuration was restored at revision 6. |
| Drafts survive tab navigation | Browser disabled POL-001 without saving, switched Checks → Runs → Checks, and found the draft intact. Discard restored 13 enabled checks without a save. |
| Exceptions end to end | Browser created an exact POL-003 exception and reanalyzed. Run 2e0fe1b8-78ba-4dc6-8812-10f5dbcf98af had one excluded finding of five, visible through the Excluded filter. Source remained unexcluded. |
| Exception removal preserves history | Browser removed the exception in Checks. Run 9149261c-3ca0-4445-95ab-758b57326c39 had no excluded findings; the preceding run retained its exclusion. The saved list was restored to empty. |
| Large results | A temporary 1,200-finding fixture displayed four check groups (240/480/240/240). Browser Next showed rows 11–20 of 240; object grouping showed 1,200 groups. Search found the final object and reset pagination. Namespace plus critical severity returned the expected 120 findings. The fixture was removed after testing. |

## Practical limits

Pagination limits rendered rows; the run-detail API still transfers the full
report. Browser acceptance establishes usability at 1,200 findings, not arbitrary
scale. Runs currently lists the most recent 100 entries; older IDs remain
addressable. Historical catalogs without rule metadata cannot classify categories.
Token and Identity currently have no dedicated checks; assignment checks still
use collected relationship data. Adding new detector logic requires code changes.
Exceptions supports in-place editing of exact scope, owner, reason and expiry. Drafts do not survive reload or leaving Security Audit. Enterprise
namespace behavior and production-scale collection require environment-specific
validation beyond the local development Vault used here.

## Dedicated Exceptions tab

Exceptions now has its own navigation entry, with direct creation, editing, search,
Active/Expired filters and pagination. Creation from Findings still prefills scope.
The technical Baseline and exceptions panel was removed from Findings; applied
exception reasons remain in individual finding evidence. Updates preserve the
entry ID and use an atomic target-scoped SQLite update with unique scope checks.

Production build passed. Browser create/edit/delete and API duplicate rejection,
invalid-edit preservation and stable IDs were verified on temporary exact objects.
The persistence test additionally covers target isolation and conflicting updates.

## Refresh placement

Selective refresh now lives in Sources, beside collection and import. The panel
uses the selected run query (or latest run when none is selected), shows its date
and links to run history for choosing another snapshot. Ineligible snapshots and
loading/error states are explicit. Successful refresh opens the newly created
result in Findings. The former Findings refresh panel has been removed.

Client build passed. Browser refresh from Sources requested only policies for
run 0c72eaca-53f6-4468-b6ec-028551f0ed78. API readback confirmed new run
0024bdbb-a296-43a5-b5f0-d84206d04ba8 completed with four requests, nine retained
resources, twelve total resources, five findings and zero coverage issues.

## Comparison placement

Run comparison now lives in Runs. Select two completed/partial runs in the table
and press Compare; the older run is Before and the newer run is After. Selection
persists across list pages, caps at two, and can be cleared. Changing selection
clears the previous comparison. Findings no longer embeds comparison controls.
Backend compatibility checks remain enforced, with their explanatory errors shown
instead of a generic HTTP status. Removed findings do not imply remediation.

Client build passed. Browser comparison of runs 9149261c and 0024bdbb displayed
12 unchanged resources and five unchanged findings. Comparing different rule
configurations was rejected by the existing backend compatibility check.
