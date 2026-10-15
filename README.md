# DevFlow 12 — Requirements → Evidence (working local repository)

**Version 0.19 OpenAI assistance:** `/ai` provides requirements analysis, debugging suggestions and explanations through the OpenAI Responses API. It sends only explicitly submitted text/context, uses server-side credentials, enforces tenant opt-in and a daily request quota, and never changes approvals or verified evidence. See [setup and privacy details](docs/OPENAI_ASSISTANCE.md). Disabled until the operator supplies an API key, a compatible model and explicit enablement. No live OpenAI call has been verified in this workspace.

**Version 0.18 enterprise API controls:** opt-in signed JWT access-token verification, operator-bound roles, a separate database per tenant, verified reviewer attribution and self-review prevention, transaction-bound audit chains, encrypted backup jobs and restore drills, authenticated operational APIs, and deployment templates. See [enterprise API setup](docs/ENTERPRISE_API.md) and [security assessment](docs/SECURITY_ASSESSMENT_V018.md). Deployment and external independent assessment require external services; their completion is not claimed by the local release. Earlier notes below describe historical releases and local mode.

**Version 0.17 operational controls:** request bodies are capped at 8 MiB before parsing, including chunked requests. `backup.py` creates consistent SQLite snapshots and restores to a new file with checksum and database integrity checks. See [operating instructions and remaining work](docs/OPERATIONAL_CONTROLS.md). This is a working local engineering application; enterprise production readiness remains incomplete.

**Version 0.16 engineering evidence:** location-tolerant finding IDs, prioritized remediation tasks and schema-validated SARIF 2.1.0 export. Baselines distinguish location changes from new findings, with compatibility for older reports. See [the evidence guide](docs/ENGINEERING_EVIDENCE.md). Source remains read-only and fixes are never applied to audited projects.

**Version 0.15 security release workspace:** `/protection` now provides guided imports, production-control declarations, baseline comparisons, session-only triage with exported review bundles and a read-only GitHub Actions metadata adapter. See [the workspace guide](docs/SECURITY_RELEASE_WORKSPACE.md). These checks preserve audited source and never authorize a deployment.

**Read-only protection audit:** `/protection` adds redacted static source/configuration findings, offline dependency declaration checks and explicit production-control gaps. Submitted projects are never executed, modified or stored. See [the preservation and audit guide](docs/READ_ONLY_PROTECTION.md). This is a bounded security-review tool, not production certification or a no-bugs guarantee.

**Version 0.13 quality verification:** open `/quality` for measured test outcomes, statement/branch coverage, module/function gaps, API response exercise and source freshness. Run `python quality_gate.py` after installing `requirements-quality.txt` (Node.js is required for browser-script syntax checks). The gate executes only this trusted checkout; customer-submitted source remains non-executing. See [the quality audit](docs/QUALITY_AUDIT.md) for scope, fixes and repeatable verification. GitHub Actions now uses the same gate.

**Version 0.12 systems engineering:** open `/systems` for a source-file import workflow, Python architecture fitness checks, circular dependencies, import hotspots, change-impact suggestions, event-based SLO error budgets, multiwindow burn alerts and a prioritized release-readiness queue. Reports are persisted and compared with the latest source snapshot. Read [the systems engineering guide](docs/SYSTEMS_ENGINEERING.md). Full suite: 84 passing tests, including optional PQC tests. Reliability counters are supplied by the user; no production telemetry connector or automatic deployment is claimed.

**Version 0.11 public owner access:** `python public_owner.py` creates a temporary HTTPS link protected by Cloudflare email PIN authentication for `bhuvanjakkula@gmail.com`. Local access remains available through `python run.py`. Read [the public owner guide](docs/PUBLIC_OWNER_ACCESS.md). 70 tests pass, including optional PQC tests. This completes the interrupted public access setup; permanent hosting and wider engineering roadmap features remain future work.

**Version 0.10 free local owner access:** run `python run.py` or `Start-DevFlow-Owner.cmd`, then open the one-use link printed in the terminal. Owner profile: `bhuvanjakkula@gmail.com`; no DevFlow password or subscription. Read [the owner access guide](docs/FREE_OWNER_ACCESS.md). This is local-machine access, not verified Gmail sign-in or public hosting.

**Version 0.9 PQC security foundation:** offline ML-KEM-768/AES-256-GCM encrypted exports with ML-DSA-65 signatures, encrypted private-key bundles, optional bearer API protection and origin checks. Read [the PQC security guide](docs/PQC_SECURITY.md). 64 tests pass with the optional PQC libraries. Database encryption and PQ-TLS remain future work.

**Version 0.8:** rechecked repair suggestions against fixed specification examples and bounded counterexample reduction. Read [the repair guide](docs/REPAIR_SUGGESTIONS.md). 55 tests pass.

**Version 0.7:** audit candidate code against saved specification examples, reject attempts to replace expectations, and see audit freshness/test gaps in the lifecycle report. Read [the saved-specification guide](docs/SAVED_SPECIFICATION_AUDITS.md). 52 tests pass.

**Version 0.6.1:** adds `POST /api/projects/{id}/engineering/bounded-check` to exhaustively compare candidate/reference numeric functions across declared finite input domains. Read [the bounded-check guide](docs/BOUNDED_CHECK.md). 51 tests pass.

**Version 0.6 audit tools:** seeded grammar-constrained numeric mutation, test-strength scoring, distinguishing-input suggestions and hash-bound verification replay. Read [the audit guide](docs/AUDIT_AND_REPLAY.md). All 47 tests pass. Older release notes below describe retained functionality.

**Version 0.5 assurance tools:** structured requirements with contradiction checks and executable pytest export, bounded independent numeric verification, and conservative data-flow security analysis across static helper calls. Reports are connected to the lifecycle dashboard. Read [the assurance guide](docs/ASSURANCE.md) for supported syntax, examples and limits. The release passes 41 tests.

**Version 0.4 integrated platform:** open `/engineering` for the lifecycle report joining requirements, linked source, regression targets, documentation freshness and evidence gaps across Planning, Development, Quality and Operations. Requirement revisions automatically record impact events. Repository analysis, static checks, traceback triage, contract/environment comparison, calibrated estimates and decisions remain available. Read [the architecture guide](docs/INTEGRATED_PLATFORM.md) and [engineering guide](docs/ENGINEERING_WORKBENCH.md). The version 0.2 workflow below remains available.

**Version 0.2 — an executable, local-first prototype.** Track a customer request through drafted and approved acceptance criteria, manually linked code changes, test reports, reviewer decisions, and a transparent verification report. The earlier 12-module overview, requirements analyzer, Python static scanner, and planning drafts remain available.

> **Verification is evidence-based, not absolute.** "Reviewed pass" means a person *reported* a passing test and another review action *accepted* that report for **every currently linked code change** at the current acceptance-criterion revision. The app does **not** execute tests, inspect your Git history, authenticate people, verify CI URLs, establish independent review, or prove correctness/security. Do not deploy publicly.

## Start quickly

Requires Python **3.10+**.

```bash
python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run.py
```

Visit **http://127.0.0.1:8000**.

- **Workflow page:** `http://127.0.0.1:8000/`
- **Original 12-module dashboard:** `http://127.0.0.1:8000/overview`
- **Interactive REST API documentation:** `http://127.0.0.1:8000/api/docs`

### Follow the five steps in the browser

1. Create or select a project.
2. Paste the customer's request and generate **draft** acceptance criteria. Edit them to specify concrete inputs and observable outcomes, then enter an approver name to approve each criterion.
3. Link a Git commit hash, pull request URL, or change identifier to each criterion. **Links are just references**; this MVP does not verify that they exist.
4. Enter a test name, outcome (`passed` / `failed` / `blocked`), which code link it exercises, observations, and reporter. Mark a reported result as accepted or rejected through the separate review action. Reporter and reviewer names are **unverified text fields**.
5. See the live traceability report. Download the **full report as JSON or Markdown**.

## What is in this repository?

```text
devflow12-mvp/
├── .github/workflows/tests.yml       # CI to run automated tests
├── app/
│   ├── analysis.py                   # deterministic requirements & Python AST checks
│   ├── main.py                       # original 12-module API + routing
│   ├── storage.py                    # SQLite schema and data access
│   └── workflow.py                   # feature, criterion, code link, test/review & report APIs
├── static/
│   ├── workflow.html                 # complete no-build traceability UI
│   └── index.html                    # original 12-module dashboard
├── tests/
│   ├── test_app.py                   # basic project and scanner tests
│   └── test_workflow.py              # end-to-end traceability and regression tests
├── docs/
│   ├── API_AND_WORKFLOW.md
│   └── SECURITY_AND_LIMITATIONS.md
├── .dockerignore
├── .gitignore
├── compose.yaml
├── Dockerfile
├── requirements.txt
├── requirements-dev.txt
└── run.py
```

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Automated tests cover creating projects/features, approvals, code links, evidence submission, human review, failed/blocked/rejected reports, multi-link support, criterion revisions that stale prior results, cross-project ID checks, input validation, and non-executing Python static scans.

### Run with Docker (optional)

```bash
docker compose up --build
```

Then open `http://127.0.0.1:8000`. The Compose service publishes only on the **localhost interface**. The named volume persists SQLite data. The container listens on `0.0.0.0` internally for Docker forwarding and is **not suitable to expose on public networks**.

## Data and export

By default, SQLite is created at `data/devflow.sqlite3`. Set `DEVFLOW_DB` to use another path (for example, a temporary test database). Project data, customer text, linked references, test reports and reviewer names are stored locally in SQLite. Core static analysis remains local. Optional AI assistance sends explicitly submitted text/context to OpenAI; configured CI/public-owner integrations also contact their providers. Deleting the database while the server is stopped resets its records. JSON / Markdown report exports are generated in your browser.

## Status logic

The server uses these conservative rules for each acceptance criterion:

| Status | Meaning |
|---|---|
| `draft` | Criterion needs an explicit approval action. |
| `unlinked` | Approved but no code change has been linked. |
| `missing_evidence` | At least one code link has no report for the current revision. |
| `stale_evidence` | Only older criterion revisions have test reports for one or more links. |
| `awaiting_review` | Most recent report is pending review. |
| `failed` or `blocked` | Most recent accepted report for a link says failed or blocked. |
| `rejected_evidence` | A recent reported result was rejected by a reviewer. |
| `reviewed_pass` | Each current code link has a latest, current-revision, accepted `passed` report. |

**Safety of this logic:** a newly linked change needs its own evidence. Editing a criterion increases its revision, sets it to draft, and makes older evidence ineligible for `reviewed_pass`. New reports for a link supersede previous reports in status evaluation; historical reports remain stored. "Reviewed pass" still relies entirely on self-reported information.

## Current boundaries and roadmap

All 12 areas have implemented local workflows or bounded prototypes described in the release notes above, including source/import analysis, traceback triage, declared contracts, environment comparison, decisions, specifications, numeric verification, mutation/repair experiments, SRE calculations and evidence review. The quality gate verifies DevFlow itself. Production telemetry adapters, verified Git/CI identities, sandboxed customer test execution and automated deployment remain future integrations.

Before selling or deploying the app, prioritize real authentication/authorization, proper role separation, permission-scoped GitHub integration, CI run validation, tamper-resistant audit trails, schema migrations, backups, retention controls, sandboxed test runners, rate limiting, and a security audit. See [Security and limitations](docs/SECURITY_AND_LIMITATIONS.md).

## Repository note

This release download is a clean source archive. It excludes Git metadata, local databases, dependency bundles and secret files. Initialize a Git repository after extracting it if desired. Publishing or deploying it requires your chosen remote or hosting service.
