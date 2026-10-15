# Security, trust boundaries, and limitations

**Development demo only. Do not expose the service publicly or upload real customer secrets.**

- No login, authentication, authorization, tenancy, user identity verification, rate limiting, CSRF defenses, or security headers configured for a public service.
- A user's claimed reviewer name, Git reference, test result and CI URL are **not authenticated, independently checked, or executed**. Approved evidence is a human recording of a claim, not a software correctness guarantee.
- Data is stored unencrypted in a local SQLite file. Backups, deletion policies, retention, disaster recovery and encryption at rest are not provided.
- Manual project ID scoping prevents a few accidental cross-project references but is not a substitute for authenticated authorization or row-level access controls.
- `workflow_events` and individual evidence rows provide a review trail through the normal application interface, but a local database administrator can rewrite history. No cryptographic signing or external audit log is provided.
- `analysis.py` parses pasted Python code into an AST without executing it, but is only a narrow heuristic checker. Treat it neither as a comprehensive security scanner nor as a sandbox for arbitrarily large adversarial inputs.
- The browser renders user-originated data as text rather than interpolated HTML to reduce XSS risk. This is *not* a substitute for threat modeling and security testing.
- The server binds to `127.0.0.1` in `run.py` and Docker Compose only publishes to `127.0.0.1` on the host. Do not change this setting without additional production security controls.
- Third-party dependencies are intentionally small, but there is no pinned lockfile, SBOM, dependency scanner or scheduled update policy yet.

## Production readiness blockers

1. Add real sessions/login and per-project RBAC; enforce that approvers and reviewers possess appropriate permissions, with separate authenticated identities.
2. Integrate verified source control and CI providers using minimum-scope tokens, signature-verified webhooks, commit-to-run attestations, and replay protection.
3. Run untrusted code only in hardened isolated ephemeral workers with strict resource budgets, networking restrictions, logs and deletion policies.
4. Add database migrations, data classification, backups, retention/delete APIs, encryption and secrets management.
5. Add append-only external audit logs, monitoring/metrics/traces, structured failure handling, automated security tests and independent review.
6. Design a model for requirement coverage, multi-test evidence per criterion, and validation of code changes rather than trusting self-reported outcomes.

## Responsible claims

The intended demonstration is **traceability with clearly labeled uncertainty**. Do not describe this version as verifying deployed software, running a full test suite, guaranteeing security, or providing a certified compliance record.
