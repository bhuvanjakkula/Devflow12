# DevFlow 12 Engineering Workbench — version 0.3

This release extends the supplied complete repository. The original MVP is preserved separately in the workspace. It provides working local analysis for all twelve pain points, at different depths. These are deterministic tools, not an LLM or autonomous software engineer.

## Start

From this project directory:

```powershell
python -m pip install -r requirements.txt
python run.py
```

Open http://127.0.0.1:8000/engineering for the new workbench. The original traceability workflow remains at `/`, and interactive API documentation is at `/api/docs`.

Create a project, select an analysis, replace the sample JSON with your input, and run it. Download a report using the JSON export button. Repository reports and decisions are retained in SQLite; repository source text is not retained by the new report endpoints. Findings contain source paths, symbol names and locations. Existing requirement/workflow endpoints retain their input text as before.

## What addresses each pain point

| Pain point | Working capability | Practical limit |
|---|---|---|
| Requirements | Ambiguity, missing-context and exact positive/negative contradiction detection; draft criteria and existing approval workflow | Does not infer arbitrary business rules or semantic contradictions |
| Debugging | Python traceback frame mapping, exception-specific hypotheses, reproduction steps | Does not reproduce failures or verify root causes |
| Testing | Function-specific negative/boundary/failure test plans plus existing revision-aware reviewed evidence | Suggested cases are not executable assertions or passing tests |
| AI code quality | AST findings, mutable-default detection, async blocking detection, branch-count metrics | Python only; no formal correctness proof |
| Legacy code | Function signatures and locations, static imports and module dependency graph | Dynamic imports, polymorphism and runtime behavior unresolved |
| Documentation | Source-derived Markdown reference with snapshot fingerprint | Refresh by rescanning; no background synchronization |
| Security | Alias-aware subprocess, deserialization, unsafe YAML, TLS-disabled and SQL-interpolation checks alongside the original scanner | Heuristics with false positives/negatives; not a comprehensive audit |
| Integration | Provider/consumer route and response-field type comparison | Simplified declared contracts; no OpenAPI parsing, request validation or retries |
| Deployment | Supplied environment metadata comparison; findings and missing-execution release status | No production probing or deployment orchestration |
| Maintenance | Baseline/current source comparison, deleted files and transitive importer impact; impacted test targets | Run the entire suite too; import graph is incomplete |
| Estimation | Branch-count points, user-calibrated hours/rate and scenario ranges | Default values are illustrative; not empirical predictions |
| Coordination | Persisted append-only decision records and existing requirement/evidence event history | Owner/reviewer identities are unverified |

## Analyze a repository from the terminal

```powershell
python analyze_repo.py . --changed app/intelligence.py --output engineering-report.json
python analyze_repo.py C:\repo\current --baseline C:\repo\previous --hours-per-point 3 --hourly-rate 75
```

The CLI reads UTF-8 Python source, skips Git/dependency/cache directories and symlinks, and never imports supplied modules. Limits: 100 files, 500 KB per snapshot, 60,000 characters per source file. The API accepts snapshots directly using forward-slash relative paths, without reading server filesystem paths.

New API prefix: `/api/projects/{id}/engineering`. POST endpoints: `requirements`, `repository`, `debug`, `contracts`, `environment`, `decisions`. GET endpoints: `reports`, `decisions`. Create the project first with `POST /api/projects`.

## Validation and development

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Windows machines with an inaccessible default pytest temporary directory can use a new project-local path with `--basetemp=.test-run-local`.

The release has 19 passing tests: existing workflow/revision/isolation cases plus alias checks, safe-call controls, transitive impact (including deleted dependencies), source fingerprints, contradictions, traceback mapping, contract/environment drift, non-execution, persistence, input rejection and CLI source loading.

## Engineering boundaries and next development

Run locally: authentication and multi-user authorization are not implemented. Reports are advisory and must not authorize deployment automatically. Do not enter secrets in source, tracebacks, requirements or environment metadata. Scanning does not remediate exposed credentials. Repository findings redact operation text, but paths, symbol names and the original scanner's named findings remain in reports.

For a production edition, implement authenticated identities and tenant permissions; verify CI evidence against trusted signed artifacts; add isolated test runners with resource/network limits; use established language/security analyzers; support real OpenAPI schemas; benchmark estimates against historical delivery data; and evaluate requirement extraction against stakeholder-approved examples. These are future work, not capabilities claimed by this release.

The percentages copied into the request are not used as product evidence: this implementation does not validate those survey claims.
