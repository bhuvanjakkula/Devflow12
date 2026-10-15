# DevFlow 0.18 security assessment and engineering argument

Date: 15 October 2026. Type: internal implementation assessment. This is not an independent penetration test, certification or proof of arbitrary program correctness. An external assessor has not been appointed and no live deployment has been supplied.

## Scope and assets

Scope includes `app/`, database backup and operations tools, the production dependency lock and deployment templates. Assets are customer requirements/source-derived evidence, test/review history, identity bindings, tenant databases, audit/backup keys and encrypted backups. Trust boundaries are the identity provider, HTTPS proxy, application request context, tenant storage selection, host administrator and external backup/audit storage.

Attackers considered include unauthenticated callers, a user forging claims or headers, a valid tenant accessing another tenant's IDs, an editor impersonating a reviewer, a reviewer accepting their own report, a network caller exhausting request resources, and someone modifying a backup or audit database without the corresponding secret keys.

## Implemented controls and observed tests

| Threat | Implemented boundary | Regression evidence |
|---|---|---|
| Forged or substituted identity | Pinned RSA key, RS256 allowlist, issuer/audience checks, required times, short token lifetime, access-token type | Wrong key, wrong audience/issuer, HMAC algorithm substitution, malformed/expired/future timestamps, unknown subject and ID-token rejection |
| Header or claim privilege escalation | Tenant/role from administrator-managed subject binding; duplicate security headers rejected | Forged role and tenant claims, spoofed tenant/user headers and duplicate authorization headers |
| Cross-tenant object access | One provisioned SQLite file per tenant; ContextVar supplies DB to worker threads | Identical project IDs in two tenants expose only the corresponding tenant's data; 40 writes through four concurrent clients preserve 20 records per tenant |
| Reviewer impersonation/self-review | Verified hashed actors replace entered names; review role checks and actor inequality | Editor approval denied; spoofed names do not alter identity; administrator self-review denied; a different reviewer succeeds |
| Audit alteration | HMAC chain over actor, tenant, sequence, change count, timestamp and request metadata in the same SQLite transaction as ordinary data writes | Valid chain, modified payload, expected-head mismatch and transaction rollback |
| Snapshot loss or alteration | Consistent SQLite snapshot, AES-256-GCM encryption, integrity/foreign-key/schema checks and new-file recovery | Record preservation, ciphertext tampering, wrong keys, overwrite refusal and scheduled backup/restore job |
| Service exhaustion | Pre-parser body cap, per-identity rate cap, per-process concurrency cap; proxy/container limits supplied | Declared/chunked body overflow, malformed lengths, disconnects, identity rate isolation and saturation rejection |
| Secret-bearing release artifact | Ignored secret directories, key/database/encrypted-backup exclusions and dependency bundles excluded | Release archive inspection; no live credentials are intentionally included |

## Conditional engineering arguments

**Tenant-selection invariant.** Let `V(token)` verify the pinned signature, issuer, audience, required time claims and access-token type. Let `B(subject)` be the operator's immutable-for-process-lifetime mapping to `(tenant, role, database)`. For an accepted API request `r`, its identity is `B(V(r.token).sub)`. Every application database connection resolves `principal.database`; if enterprise mode has no principal, storage raises. No request field selects the database. Therefore, under the assumptions below, a request authenticated for tenant A cannot select tenant B's database even when its project/object IDs collide. This is an argument about storage selection, not immunity to an arbitrary application/OS compromise.

Assumptions: all tenant data access continues through `app.storage.db`; trusted configuration binds distinct tenant files; the identity provider and RSA verification library behave as specified; request ContextVars propagate according to the framework; the host, keys and file permissions are not attacker-controlled. Source inspection found no alternative tenant database connections in `app/`. Tests include simultaneous requests; the entire request/domain space has not been exhaustively verified.

**Review-separation invariant.** Enterprise evidence creation stores `actor(verified_subject)`, ignoring a payload's proposed name. Review requires a reviewer/admin role and rejects equality with that stored actor. A subject therefore cannot accept its own newly submitted enterprise evidence through the review API. This establishes subject separation only; it cannot prove that two accounts represent different humans or that a reported test is truthful. Historical local evidence has unverified attribution.

**Audit continuity argument.** For event `i`, `h_i = HMAC(K, h_(i-1) || newline || canonical_event_i)`. Verification checks contiguous sequence, parent hash and HMAC. Data changes and their appended audit event commit together or roll back together through the storage transaction. Without K, content modifications cannot produce a valid replacement chain under the cryptographic assumptions. Tail deletion requires an independently retained expected head to detect; the API's unanchored scan cannot establish that the newest events still exist. The audit records transaction summaries, not a full value-level CDC stream or all rejected network attempts. Startup schema initialization is outside the mutation-audit claim.

**Recovery argument.** SQLite's backup API yields a consistent snapshot of committed data. Authenticated encryption binds the encrypted snapshot bytes to the backup key and format identifier. A successful restore requires authenticated decryption, SQLite integrity, foreign-key checks and required workflow tables, and creates a new destination. This supports recovery of the tested snapshot. It does not establish off-device durability, restore of lost keys, whole-service failover, RPO or RTO.

## Tool-assisted assessment

`docs/dependency-audit-v0.18.json` records a pip-audit scan of the exact 21 runtime distributions installed from the production requirements resolution, including PyJWT and cryptography. No known advisories were reported by that scan. This is time-bound advisory evidence; unknown vulnerabilities, base images and optional PQC/quality-tool dependencies are outside this result. `requirements-production.lock` pins the scanned runtime versions. The lock targets the Python 3.12 production container; the measured local test interpreter is recorded in the quality report.

`docs/static-security-v0.18.json` contains the Bandit source scan. The earlier medium SQL-construction finding in backup counting was removed by using fixed SQL statements. Four low-severity heuristic findings remain for review:

| Finding | Assessment |
|---|---|
| B311 in `app/mutation.py` | Seeded `random.Random` supports reproducible numeric mutation experiments; it does not generate authentication material |
| B107 in `app/owner_access.py` | Empty default input for a one-use launcher token; validation rejects invalid tokens; this is not a hardcoded accepted password |
| B105 in `app/protection.py` (two findings) | Scanner result status/boolean fields, not credential values |

These dispositions are internal review decisions. Raw scanner findings are retained, not suppressed. Rerun with `python -m bandit -r app backup.py ops_cli.py ops_job.py -f json` and dependency audit with `python -m pip_audit -r requirements-production.lock`. Install `requirements-security.txt` separately. The complete quality gate produces `docs/quality-verification-v0.18.json`; execution coverage is not correctness proof.

## Residual risks and external acceptance

1. Identity-provider onboarding, signing-key provenance, MFA, recovery, client issuance and revocation policy must be exercised against the chosen real provider. Current tests use generated test keys, not an authenticated enterprise account.
2. Shared process/host access remains a common trust boundary. Separate SQLite files do not provide per-tenant OS isolation or encrypted live database storage. Provision host disk encryption, secret ACLs and stronger workload isolation if required.
3. Docker/Nginx templates have not run in this workspace. Staging must verify image provenance/digests, TLS, routing, proxy trust, resource limits, restart and secret permissions. Synchronous analysis is not a hard-deadline sandbox.
4. Backup jobs/timers and authenticated probes are supplied but not enabled against a real service. Configure off-device immutable storage, independently retained audit heads, metrics scraping, an alert destination, retention and incident procedures; measure recovery objectives and load on deployment hardware.
5. Tenant-scoped CI artifact provenance and sandboxed customer test execution are not supplied by these controls. Enterprise mode disables the shared CI credential adapter; customer code is still never executed.
6. Browser accessibility and enterprise sign-in UX have no new browser audit in this release. API workflows and JavaScript syntax are exercised; this is not a usability certification.

An independent assessor should receive the source/archive hash, configuration with secrets removed, dependency and static findings, quality report, role matrix, generated-key security tests and an isolated staging endpoint with separate viewer/editor/reviewer/admin identities in two tenants. Request tests for JWT substitution, IDOR across all object routes, role and review bypass, proxy/header spoofing, resource exhaustion, audit deletion/anchoring and actual failover. Only that separate assessor can issue an independent report. No report is fabricated here.

Reference design guidance: [PyJWT verification API](https://pyjwt.readthedocs.io/en/latest/api.html), [OWASP tenant security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html), [Nginx proxy timeouts](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) and [Docker Compose service controls](https://docs.docker.com/reference/compose-file/services/).
