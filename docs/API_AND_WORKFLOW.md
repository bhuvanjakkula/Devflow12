# Traceability workflow and API

All routes are served locally at `http://127.0.0.1:8000`. Prefix for workflow endpoints:

```
/api/projects/{project_id}/workflow
```

## Example lifecycle

1. `POST /api/projects` `{"name":"Invoice Portal","description":"Invoice tracking"}` → project ID.
2. `POST /api/projects/{id}/workflow/features` `{"customer_text":"Customers must upload an invoice and see an accurate total."}` → feature ID and drafted criteria.
3. `PATCH /api/projects/{id}/workflow/criteria/{criterion_id}` `{"statement":"Given invoice lines 10 and 20, when the total is calculated, then the display shows 30."}` → increments revision if modified, resets approval.
4. `POST /api/projects/{id}/workflow/criteria/{criterion_id}/approve` `{"reviewer":"Customer representative"}` → approved criterion.
5. `POST /api/projects/{id}/workflow/criteria/{criterion_id}/code-links` `{"reference":"abc123def","file_path":"src/invoices.py","notes":"Invoice arithmetic"}` → code link ID.
6. `POST /api/projects/{id}/workflow/criteria/{criterion_id}/evidence`:
   ```json
   {
     "code_link_id": 1,
     "test_name": "invoice_total_handles_two_lines",
     "outcome": "passed",
     "method": "manual",
     "run_reference": "local-test-001",
     "details": "Input 10 + 20; observed output 30",
     "reported_by": "QA engineer"
   }
   → evidence ID in pending-review state. A `ci_reported` entry requires a nonempty `run_reference`, but URLs are **not fetched or trusted**.
7. `POST /api/projects/{id}/workflow/evidence/{evidence_id}/review` `{"decision":"accepted","reviewer":"Release reviewer","note":"Evidence reviewed"}` → accepted result. You can also reject it. A finished review cannot be overwritten; submit another evidence entry instead.
8. `GET /api/projects/{id}/workflow/report` → all features, criteria, code links, latest status, full historical evidence and unresolved issues.

Other endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/projects` | List projects |
| GET | `/api/projects/{id}` | Existing project's latest heuristic analyses |
| POST | `/api/projects/{id}/requirements/analyze` | Legacy heuristic requirement analysis |
| POST | `/api/projects/{id}/code/analyze` | Non-executing Python AST scanner |
| GET | `/api/projects/{id}/report` | Original 12-module status report |
| GET | `/api/projects/{id}/workflow/features` | Full feature list including traceability |
| GET | `/api/projects/{id}/workflow/features/{feature_id}` | One feature's criteria and evidence |
| GET | `/api/projects/{id}/workflow/events` | Local event history (last 300) |

Open `/api/docs` for complete machine-generated OpenAPI schemas.

## Rules

- **No implicit approval.** Generated criteria start as `draft`. Stakeholder approval is an explicit action.
- **Revision invalidation.** An edit increments `revision`, returns the criterion to draft and excludes old evidence from current verification.
- **All linked changes matter.** If an additional code link is added, the criterion needs an accepted pass for it as well before showing `reviewed_pass`.
- **Latest evidence supersedes earlier evidence per link.** A new pending, rejected, failed, or blocked report prevents a `reviewed_pass` for that link even when older reports passed.
- **Human review is a state transition, not identity assurance.** This prototype does not check credentials, enforce separation of reporter and reviewer, or independently validate evidence.
- **All code references are opaque text.** No cloning, GitHub queries, PR validation, source execution or CI API integration is performed.
- **Project scope is enforced in each nested URL.** This prevents accidentally using an item ID from a different project, but **is not authorization**. Anyone who can reach this local web service can access all projects.

## Data model

`projects` → `feature_requirements` → `acceptance_criteria` → `code_links` → `test_evidence`.

A test report stores its criterion's revision at submission. Review decisions are attached to each report. `workflow_events` stores an append-only *within normal application paths* record of state-changing workflow actions; SQLite file owners can modify the database, so it is **not tamper-proof**.
