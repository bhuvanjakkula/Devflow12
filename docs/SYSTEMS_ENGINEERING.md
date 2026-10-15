# Systems engineering — v0.12

Start with `python run.py`, open the printed one-use owner link, then choose **Systems board** in the workbench, or visit http://127.0.0.1:8000/systems in the same browser. This remains a local-first Python/SQLite application.

## Source and architecture

Create or select a project, then choose a repository folder or individual source files. The importer uses relative paths, omits common caches/dependencies/runtime directories, environment files and known private PQC bundles, and enforces 100 files, 500 KB total, and 60,000 characters per file. Inspect the JSON before submitting; only include files appropriate for analysis. Source is processed locally without execution; the stored reports contain findings, hashes, dependency metadata and telemetry, not raw source.

Python static imports build a directed graph. Tarjan's strongly connected components identify circular dependencies. Dependency hotspots rank modules by incoming imports. Explicit boundary rules flag edges whose source and target start with the configured relative prefixes. Use a trailing slash for directory boundaries, such as `app/storage/`. Baseline snapshots and changed_files propagate through reverse dependencies to suggest regression targets. Dynamic imports, external dependencies and runtime dispatch are not resolved; run the full regression suite.

An example boundary:

```json
{"name":"Storage must not import API", "source_prefix":"app/storage/", "forbidden_prefix":"app/api/"}
```

## Reliability arithmetic

The optional `slo` input declares a service name, target fraction (0.999 means 99.9%), a 7–90 day window, an explicit timezone-aware `measured_at`, full-window event counters and recent 5m, 30m, 1h and 6h counters. Define the same good/bad event SLI for every window. All windows must end at the measurement time and contain their shorter windows, including good-event counts. Invalid counters, nonfinite targets and future timestamps are rejected.

- Allowed bad events = full-window total × (1 − target).
- Budget used = observed bad events ÷ allowed bad events.
- Burn rate = window bad-event ratio ÷ (1 − target).
- Fast burn requires both 1h and 5m rates at or above 14.4× for a 30-day window.
- Slow burn requires both 6h and 30m rates at or above 6× for a 30-day window.
- Thresholds scale by configured window_days / 30, preserving the example policy's period-relative spend.

Zero traffic is unmeasured, not success. Missing/zero-traffic recent windows leave the corresponding alert unassessed. Measurements older than 24 hours require refresh, and freshness is recomputed on report retrieval. Budget exhaustion or a firing fast-burn alert recommends focusing on reliability before feature releases. These are advisory policies; no alert is sent and no deployment is blocked automatically.

The calculations draw on Google's [SLO alerting chapter](https://sre.google/workbook/alerting-on-slos/) and [error-budget policy example](https://sre.google/workbook/error-budget-policy/). Counters are user-supplied, not verified production measurements. This implementation is not affiliated with Google.

## Evidence and release review

`POST /api/projects/{id}/engineering/systems` accepts the source snapshot, optional boundaries and SLO. It saves a repository analysis and a systems report. `GET` returns the latest systems report with fresh lifecycle checks and measurement age. Records are scoped to the project; existing databases gain an additive systems_reports table on startup.

The action queue combines requirement/evidence gaps, stale bounded verification, source freshness, architecture problems and reliability issues. P0 means urgent remediation, P1 required review, and P2 suggested improvement. Action IDs remain stable for unchanged evidence. A source hash mismatch marks a report stale when the latest repository analysis changes. This detects changes submitted to DevFlow, not unobserved edits on disk. JSON export includes the report and its provenance.

The **Load example** button inserts clearly labeled demonstration source and counters into the input editor. It only saves them when Analyze systems is clicked. The preloaded local project named **Systems engineering demo** is demonstration evidence, not a production benchmark.

## Validation

84 tests pass with optional PQC dependencies. New tests cover architecture cycles and boundaries, incomplete syntax, change-impact targets, nested counter validation, exact budget arithmetic, multiwindow confirmation, period scaling, zero traffic, stale telemetry, persisted reports, stale snapshots, project isolation and non-execution/non-persistence of raw source. Local browser verification covers project creation, example analysis, saved report rendering and the narrow app-panel layout.

Live production telemetry, Git/CI identity verification, multi-user role separation, distributed execution and automatic deployments remain outside this release.
