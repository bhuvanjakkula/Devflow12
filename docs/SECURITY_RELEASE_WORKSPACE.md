# Security release workspace — v0.15

Open `/protection` through the local owner launcher. The workspace now guides source import, production-control declarations, baseline comparison, finding triage and CI run metadata verification. The read-only source audit continues to avoid source execution, project modification, network requests and source persistence.

## Guided audit and baselines

Choose a source folder to preserve relative paths, or explicitly select files. Common caches, dependencies, environment and private-key files are excluded, with the existing bounded snapshot limits enforced. Advanced JSON remains available for precise snapshots. Controls use explicit Unassessed, Reported enabled and Reported disabled choices.

Export an audit baseline or a review bundle. Import either as the next baseline, then run the current audit. Comparison reports new, unchanged, severity-changed, not-seen and outside-scope findings. Matching uses path, line, rule and title; moved code can appear new. A finding missing from a later report is not proven fixed, and omitted files are explicitly outside scope. User-supplied baseline authenticity is not verified.

Triage notes and states live only in the browser session and can be exported. Accepted risk needs a note; needs retest is distinct from proof of remediation. Triage never suppresses detector findings or clears gates. Notes record their source snapshot. Changing inputs marks the report stale and disables export until a new successful scan.

## CI verification

`GET /api/ci-evidence/status` exposes only configuration metadata, never credentials. `POST /api/ci-evidence/verify` accepts only a numeric workflow run ID and expected 40-character commit SHA. Repository, trusted workflow and branch are server-configured. The service performs a GET to GitHub's fixed HTTPS API with redirects and environment proxies disabled. It checks repository, ID, commit, workflow, branch, allowed push/workflow_dispatch event, successful completion and seven-day freshness. Failed/mismatched metadata does not pass.

Use these server environment variables:

```text
DEVFLOW_CI_REPOSITORY=bhuvanjakkula/DevFlow
DEVFLOW_CI_WORKFLOW=.github/workflows/tests.yml
DEVFLOW_CI_BRANCH=main
DEVFLOW_CI_TOKEN=<configure locally; never enter in the browser or commit it>
```

Prefer a fine-grained token with Actions read access to only this repository. The optional connected launcher reuses the owner's already saved Git credential in process memory; that credential can have broader GitHub permissions even though this integration only reads metadata. No credential is written into reports or source releases.

The adapter verifies GitHub run metadata, not artifact contents, individual test claims, uploaded source-to-commit equivalence or production safety. Expected SHA is supplied by the reviewer. Release review still requires source findings, declarations and human verification. Metadata alone cannot authorize deployment.

Reference: [GitHub's workflow-run REST API](https://docs.github.com/en/rest/actions/workflow-runs). Mocked regression tests cover failures, stale dates, commits, repository scope, workflow/branch/event mismatches and credential redaction. Live verification depends on a connected repository and authenticated access.

## Release review

The board shows missing source scans, high-severity findings, incomplete analysis, undeclared/disabled controls and missing CI evidence as attention items. Even with supporting metadata present, the result is only Ready for human review. The separate Product quality board measures DevFlow's own tests; its coverage does not certify an audited customer's software.

Local validation: 121 tests passed, with 95.27% statement and 85.80% branch coverage; 161 inventoried function bodies and 59 endpoints exercised. Browser checks verified guided controls, severity filtering, risk-note requirements, preserved release attention status and baseline import/comparison with seven unchanged findings.

Live connection verified: private repository bhuvanjakkula/DevFlow, commit 0525ff811e130e99d17c4723dadfd32e62235e09, Actions run 38572682868. Both Python 3.10 and 3.12 jobs completed successfully. The local UI verified all eight run-metadata policy checks. Browser testing also confirmed input changes disable stale report exports, while triage and reported controls do not clear high-severity findings or deployment gates.
