# Engineering evidence — v0.16

The security release workspace now tracks findings across line-only source edits, presents prioritized remediation work, and exports schema-validated SARIF 2.1.0 reports.

## Finding identity and baseline compatibility

New reports assign an issue ID from the relative path, enclosing Python class/function scope, rule, title and occurrence number. Comments/imports inserted above a finding no longer make it appear new. Baseline comparison has an explicit location_changed state. Legacy reports without IDs still compare exact path/line/rule/title locations.

Names and occurrence order are heuristic identity anchors, not semantic proofs. File/function renames, reordered duplicate issues and changed scope boundaries can require manual review. Reports with matching IDs can still represent changed implementation. Not seen remains distinct from independently verified remediation; excluded files remain outside current scope. Source is parsed, never executed or altered.

## Remediation and SARIF exports

Each finding produces a suggested P0/P1/P2 task, source location, remediation and verification step. Missing/reported-disabled controls add evidence-gathering tasks. Owner assignment remains unset; generated tasks are suggestions. Existing session triage and release gates remain separate, so review notes cannot silently remove findings.

Export SARIF from the current audit, or export the remediation plan separately. Exports are disabled when inputs change until a successful rescan. SARIF contains relative URI-encoded paths, line locations, rule IDs, severity levels and partial fingerprints. It omits raw source, snippets, patches, detected secret literals and executable fix actions. The source snapshot and bounded-analysis limitations are retained. Importing SARIF into another tool does not grant deployment authority.

Tests validate populated and empty exports against the bundled official [OASIS SARIF 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json), including path escaping, locations and metadata. Regression tests also cover shifted lines, duplicate IDs, distinct scopes, legacy baseline compatibility, prioritized tasks and redaction/non-execution.

Validation: 129 tests pass; 95.30% statement and 86.01% branch coverage. All 166 inventoried function bodies and 59 endpoints were exercised. Browser verification inserted a comment above the demonstration function and reported three location changes, four unchanged findings and zero new findings; SARIF export stayed disabled while inputs were stale and enabled after rescan.
