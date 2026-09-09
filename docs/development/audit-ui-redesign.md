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
