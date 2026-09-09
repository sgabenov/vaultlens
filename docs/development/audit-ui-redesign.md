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
