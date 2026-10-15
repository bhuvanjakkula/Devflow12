# DevFlow 0.17: practical controls and completion status

## Update: version 0.18

Enterprise API identity, role enforcement, separate tenant databases, verified actor attribution, self-review prevention, transaction-bound HMAC audit records, version-1 schema upgrade, AES-256-GCM backup/restore jobs, a scheduler template, authenticated operations probes/metrics and production deployment templates are now implemented. See [enterprise API and deployment setup](ENTERPRISE_API.md) and [internal security assessment](SECURITY_ASSESSMENT_V018.md). The table below is the historical 0.17 backlog, not a statement that those code controls are still absent.

Live identity-provider connection, deployment, off-device storage, alert routing and independent external penetration testing remain external acceptance tasks. No provider issuer/audience/key, hosting account, storage service or independent assessor has been supplied. The user's latest direction selects API integration; it does not identify those services. Tenant-scoped CI and isolated customer-code execution are still outside this release; shared CI credentials are blocked in enterprise mode and submitted code is not executed.

The maintained source for this release is this directory. Earlier version folders and archives are historical snapshots. Start with `python run.py` and use the owner link printed in the terminal. Install the requirements described in the README first.

## Problems solved

The workflow connects a customer requirement to acceptance criteria, linked changes, test reports and explicit review. The engineering, systems and protection pages provide bounded static analysis and evidence exports. Customer source is not executed. Submitted test outcomes remain reported evidence unless independently validated by a separate integration.

This release caps HTTP bodies at 8 MiB before application parsing. Content-Length is checked, duplicate or malformed lengths are rejected, and actual bytes are counted even when the length is absent or inaccurate. A rejected request never reaches a write endpoint. The cap bounds buffered payload bytes per request; it is not a concurrent-memory, CPU, connection, or rate limit. Configure corresponding reverse-proxy controls before network deployment.

## Backup and restore drill

Create a snapshot (destination must not exist):

```powershell
python backup.py data/devflow.sqlite3 data/backups/devflow-2026-10-15.sqlite3
```

Save the printed SHA-256 separately. Restore to a new file using that hash:

```powershell
python backup.py data/backups/devflow-2026-10-15.sqlite3 data/recovery/devflow.sqlite3 --expected-sha256 HASH_FROM_BACKUP
```

SQLite's backup API captures a consistent snapshot, including committed data held in a WAL. Each destination is checked with SQLite integrity and foreign-key checks and required workflow tables. The result includes row counts for three workflow tables; the snapshot copies the entire database. A mismatched checksum fails before destination creation. Existing files are never overwritten. Keep database files stable against other local writers during the drill.

To use a recovered database, stop DevFlow, set `DEVFLOW_DB` to the recovered absolute path, then restart and inspect project records. Keep the old file until acceptance. Backups contain sensitive project data in plaintext; place them on access-controlled encrypted storage. The checksum detects accidental change against a trusted saved value; it does not authenticate an attacker-controlled backup. Encryption keys and quality reports are separate from this database snapshot.

## Reproducible evidence

Run `python quality_gate.py` after installing `requirements-quality.txt`; Node is also required. It executes this trusted checkout's tests, statement/branch coverage, static correctness checks and JavaScript syntax checks. View current results at `/quality`. Source changes make previous results stale. Exported evidence is local, unsigned evidence.

`tests/test_operational_controls.py` exercises body boundaries, malformed lengths, chunked overflow, disconnects, backup/restore record preservation, overwrite refusal, invalid databases and checksum mismatch. These are regression checks for stated properties. Finite numeric checks elsewhere prove only the enumerated domain under their supported interpreter semantics, not arbitrary program correctness.

## Remaining production work

| Pending capability | Acceptance evidence still required |
|---|---|
| Per-user identity, roles and tenant isolation | Trusted identity provider, authorization matrix, cross-tenant adversarial tests and account recovery |
| Independently verified Git/CI evidence | Scoped integration, trusted run identity, artifact/hash binding and replay rejection |
| Tamper-resistant audit trail | External protected anchor, retention policy and modification/deletion detection |
| Schema versioning and upgrades | Versioned migrations and upgrade/rollback drills on prior databases |
| Operational recovery | Scheduled encrypted off-device backups, monitored restore drills and measured RPO/RTO |
| Network service protection | Rate/concurrency limits, request deadlines, trusted host/proxy configuration and load tests |
| Production observability | Authenticated telemetry, measured SLOs, paging and incident exercises |
| Customer test execution | Isolated disposable runners, resource quotas, network/filesystem boundaries and hostile-input tests |
| Independent security assurance | Threat model, dependency vulnerability review and external penetration test |
| Product usability and scale | Browser workflow/accessibility tests, user trials and repeatable load benchmarks |

These tasks are not marked complete by passing local tests. No cloud deployment, enterprise certification, unlimited correctness proof or equivalence to another vendor's products is claimed. Backup/recovery and request-size controls are implemented; the remaining items above require further engineering and, where applicable, operational infrastructure.
