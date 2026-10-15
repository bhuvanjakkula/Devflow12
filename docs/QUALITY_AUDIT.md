# DevFlow quality audit — v0.13

This release follows published Google engineering review principles: inspect design and behavior, think through edge cases, test changes, check user interfaces and keep documentation current. Reference: [Google's code review checklist](https://google.github.io/eng-practices/review/reviewer/looking-for.html). It does not reproduce Google's proprietary internal tooling or claim Google certification.

## Repeatable quality gate

```powershell
python -m pip install -r requirements-quality.txt
python quality_gate.py
```

Node.js must be available on PATH. The runner verifies this fixed, trusted checkout. It never runs source uploaded through the website and accepts no arbitrary execution command or repository path. Tests use a temporary database and do not inherit owner/tunnel/API-token settings. Tests, coverage, lint and JavaScript checks have timeouts; failed subprocesses fail the gate.

The gate enforces:

1. Passing unit, integration, security, lifecycle and CLI regression tests.
2. At least 90% statement coverage and 80% branch coverage.
3. Exercise of every inventoried function body in app/ plus analyze_repo.py, pqc_cli.py and public_owner.py.
4. Successful-response exercise for every OpenAPI endpoint and the generated API documentation routes.
5. Ruff static correctness rules E9/F821/F822/F823.
6. Node syntax checks for every static JavaScript file and inline HTML script.
7. Optional cryptographic tests actually run rather than being skipped.
8. Source files remain stable throughout verification.

`data/quality/latest.json` records the checks, exact environment/package versions, relative module paths, function statement coverage, missing lines, route response statuses and a source hash. Coverage JSON, JUnit XML and a local test log are retained alongside it. These runtime artifacts and dependency caches are excluded from source releases. The release includes a copied audit snapshot under docs/ for review.

Open http://127.0.0.1:8000/quality in the authenticated owner browser to inspect results. Refresh detects source/test/config changes and marks old results stale. Module details expose partial function coverage and missing statements. Evidence is local and unsigned; a modified local report is not independently authenticated.

GitHub Actions installs the quality dependencies and runs the same gate on the configured Python 3.10 and 3.12 matrix, retaining artifacts. Those remote CI jobs have not been run from this workspace; local results identify their actual Python/platform environment.

## Fixed defects and gaps

- Invalid Unicode in a JSON body could make FastAPI's validation error serializer crash. A safe 422 handler now omits raw input and exception contexts, also preventing request-value reflection.
- Unknown snapshot/SLO options, including misspelled configuration keys, were silently ignored. Those schemas now reject extra fields.
- Repository CLI scans included installed analyzer/crypto dependency caches. Those directories are now excluded.
- The public launcher stopped consuming its internal log queue after startup, allowing unlimited accumulation. The queue is bounded while its reader keeps draining the process.
- Finite-domain comparison had a backend endpoint but no browser workbench entry. It now has a criterion-linked input/control.
- Dynamically generated traceability fields had visible labels without programmatic associations. Unique field IDs now associate every generated label with its control.
- Local HTML/JavaScript responses could show cached pre-upgrade interfaces. They now receive no-store headers.
- Requirement role detection recognized singular names but missed Users/Admins. Plural actor labels now count.
- Overview badges labeled existing prototypes as Planned. They now show Prototype explicitly.

## Browser verification

A clearly labeled local **Quality browser audit** project was used to create a requirement, approve a criterion, link a reference, submit synthetic blocked evidence and accept it. The report correctly remained blocked rather than showing reviewed pass. No customer test result was fabricated.

All 15 workbench modes were exercised through their controls: lifecycle, finite-domain comparison, repair proposals, saved-specification audit, mutation audit, replay, structured specifications, numeric verification, security flow, repository analysis, requirements, traceback triage, contracts, environment comparison and decisions. Numeric verification detected the deliberate demo defect, repair generated a rechecked proposal, and replay reproduced the recorded result.

Overview requirement analysis, Python scanning and report generation were checked in the browser, as were the quality board, filtering and systems report display. The systems demo from v0.12 remains explicitly demonstration data. The finite-domain and model checks do not execute full Python programs.

## Interpretation

Coverage proves that tests visited code; it does not establish correctness for every input, concurrency schedule or environment. Successful route responses do not establish exhaustive API contract testing. Some failure branches remain untested and are visible in the report. Browser verification is recorded separately from automated Python coverage. Public email-PIN completion requires the owner; it is not simulated as a verified human login.

No production load benchmark, penetration test, independent security review or Google-internal equivalence is claimed. Customer code is never automatically repaired or deployed. Human design/security review remains a separate release decision.

## Recorded local results

Final gate: 95 passed, 0 failed, 0 skipped; 95.10% statement coverage, 85.07% branch coverage; 147 function bodies and 53 endpoint responses exercised. See quality-verification-v0.13.json for source hashes, environment versions and remaining statement gaps.

## Follow-up header audit

Fixed crashes on malformed Origin and Host headers and made tunnel host comparison handle non-ASCII input safely. The follow-up gate passes 97 tests with 95.02% statement and 85.11% branch coverage; all 147 inventoried functions and 53 endpoints remain exercised.
