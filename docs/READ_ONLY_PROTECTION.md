# Read-only security audit

Open `/protection` in the local authenticated owner browser. Select explicit files, or paste a relative-path source snapshot, and run the audit. You can export a redacted JSON report with file/line locations, rule IDs, potential severity, remediation and scope limitations.

The endpoint `POST /api/security-audit` accepts only a `files` map and optional `controls`. Files have the same 100-file, 500-KB, 60,000-character-per-file and safe relative-path bounds as the engineering snapshots. Unknown options and nonboolean control declarations are rejected. There is no target URL, filesystem path, shell command, patch operation or execution option.

Python is processed through syntax/static dataflow analysis. Other checks use selected text rules for potential key/credential patterns, requirements pins, package manifests, container root/latest settings and workflow permission/trust-boundary settings. Detection rules are intentionally bounded; false positives and false negatives require human review. Dependency declarations are examined offline: current CVEs, transitive dependency vulnerabilities and image vulnerabilities are **not checked** by this endpoint.

Production controls include authentication, authorization, TLS, secret management, audit logs, tested backup/restore, rate limiting, vulnerability scanning and independent security review. Missing declarations are unassessed. A `true` declaration means reported enabled, not tested or independently verified. No result certifies production safety or bug-free operation.

## Preservation and privacy

The scanner never imports, executes, alters or writes the submitted project; never makes external network requests; and does not save source or the audit report to SQLite. It operates on an in-memory snapshot. Export is an explicit browser download. Findings omit code excerpts and detected credential values. File paths, line numbers and metadata remain in the report. The browser retains submitted input until navigation/reload and the service receives it in memory; use the trusted local owner session. Known private-key/environment filenames are rejected by the file picker, but the user must still choose appropriate source/configuration files.

## Validation

Regression tests assert malicious submitted code does not execute, a marker file is never created, SQLite contents do not change, candidate secret values and source literals are absent from exported evidence, invalid manifests yield incomplete analysis, missing controls are not silently passed, strict input bounds apply, and relevant container/CI/dependency rules fire on demonstration inputs. These tests join the complete product quality gate.

Live penetration testing, network security testing, current advisory lookups, runtime authorization checks, load testing and independent review require additional authorized tooling and evidence. The product does not silently manipulate or repair an audited customer's project.

Final verification: 105 tests passed, zero failures/skips; 95.13% statement and 85.75% branch coverage. All 152 inventoried function bodies and 55 endpoints were exercised. Browser demonstration detected seven findings in four files, retained unassessed production controls, and exported the redacted report successfully.
