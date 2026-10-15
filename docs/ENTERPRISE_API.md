# DevFlow 0.18 enterprise API

Enterprise mode is an API resource server. Your identity service issues tokens; DevFlow verifies them. It does not create an identity-provider account, enroll MFA or implement a password-reset service. Perform enrollment, MFA, service-account issuance and account recovery at the identity provider.

## Identity contract

The configured issuer must issue RS256 JWT **access tokens** with `typ: at+jwt` (RFC 9068), a dedicated API audience, and `sub`, `iss`, `aud`, `iat`, `nbf` and `exp`. Maximum lifetime is one hour. Plain opaque API keys and OIDC ID tokens are not accepted. Providers issuing other token formats need an adapter; arbitrary Microsoft or Google tokens are not automatically compatible.

DevFlow pins an operator-supplied RSA public key (at least 2048 bits), issuer and audience. It never fetches a key URL supplied by the token. Rotate public keys and remove user bindings through a configuration update followed by restart. Removing a binding revokes that subject when the updated service starts; otherwise issued tokens remain valid until expiration. Provision a dedicated audience to prevent token reuse across services.

Copy `deploy/enterprise.example.json` to a private configuration file and replace the issuer, audience, origin, key paths, data root and identity subjects. Identity subjects come from the verified provider, not email display names. Tenant names are validated identifiers. The file's `identities` array binds one subject to one tenant and role. Tenant and role claims or request headers cannot change those bindings. Configuration is loaded at startup; updates require a restart.

| Role | GET/HEAD | Ordinary writes | Approve/review | Operations APIs |
|---|---|---|---|---|
| viewer | Yes | No | No | No |
| editor | Yes | Yes | No | No |
| reviewer | Yes | No | Yes | No |
| admin | Yes | Yes | Yes | Yes |

`/api/identity` is readable by every authenticated role. An admin still cannot review evidence they submitted. Existing text-only local evidence remains historical reported evidence; migration does not authenticate old names. Verified actors are stored as stable subject hashes prefixed `oidc:`. Requirements and evidence remain human-defined; identity verification does not validate a passing test claim.

## API usage

Acquire an API access token from your configured identity provider using its approved client flow. Keep it in process memory or an access-controlled token file. Example PowerShell client, with an already-issued token supplied through the environment:

```powershell
$headers = @{ Authorization = "Bearer $env:DEVFLOW_ACCESS_TOKEN" }
Invoke-RestMethod https://devflow.example.com/api/identity -Headers $headers
Invoke-RestMethod https://devflow.example.com/api/projects -Headers $headers
Invoke-RestMethod https://devflow.example.com/api/projects -Method Post -Headers $headers -ContentType application/json -Body '{"name":"Invoice quality","description":"Track reviewed invoice behavior"}'
```

The existing requirements, workflow, engineering, systems and protection APIs use the same bearer token. JSON OpenAPI is available at `/openapi.json` with authorization. API authentication also protects `/api/docs`; use an API client to retrieve the schema for enterprise integration. The existing browser token prompt can accept the same short-lived access token and keeps it in page memory.

`GET /api/ops/readiness` checks tenant database availability and schema version. `GET /api/ops/audit` verifies that tenant's HMAC audit chain. `GET /api/ops/metrics` exposes completed request counts, server error counts and summed latency for that tenant in this worker. Counters reset on restart; scrape deltas externally. `GET /health/live` is public and reports process liveness only.

## Isolation and startup

Every tenant uses its own SQLite database under the configured data root. A request's verified identity supplies the database through a ContextVar propagated into worker threads. Tenant data is not selected from project IDs, JSON fields or headers. Enterprise storage without identity context fails closed. Startup initializes each provisioned tenant; existing local databases are never silently assigned to a tenant. Migrate selected local data through an explicit reviewed export/import or stopped-server database copy with a backup.

This isolates application data under the service's access-control boundary. Tenants still share the process, OS account, container, audit key and host administrator. It is not an OS sandbox against code execution. Uploaded customer code remains non-executing. The legacy server-wide CI integration is disabled in enterprise mode to prevent exposing another tenant's provider credentials or run metadata. A tenant-scoped provider adapter remains separate work.

Set `DEVFLOW_ENTERPRISE_MODE=1` and `DEVFLOW_ENTERPRISE_CONFIG` to your configuration path before starting `app.main:app` with Uvicorn. Use the production Compose command for deployment. **Do not use `run.py` or public-owner launchers for enterprise mode**: they select a different identity boundary and conflicting modes are rejected. Enterprise startup requires the JWT dependency in `requirements.txt`; the production image uses the exact versions in `requirements-production.lock` on Python 3.12. The general local requirements can resolve compatible versions for Python 3.10.

## Deployment and operations

`compose.production.yaml` provides a private application network, TLS proxy, non-root application user, read-only root filesystems, capability drops, resource limits and secrets mounted as files. Set the domain consistently in Nginx and enterprise configuration. Supply real TLS files and identity/audit keys in the ignored `secrets` directory. Protect file ACLs; Compose file secrets do not encrypt their host source files. Replace image tags with reviewed digest pins before deployment.

The application accepts only the configured HTTPS host. Uvicorn trusts forwarded scheme information only from the private proxy subnet. Never publish the application port or attach untrusted containers to that network. The example denies application egress; this also disables external integrations unless explicitly provisioned.

Nginx bounds bodies, per-IP rates, connections and idle timeouts. DevFlow caps authenticated concurrency and per-identity requests per minute in one worker. These are per-process controls; multiple replicas require shared global limits. Idle proxy timeouts do not cancel synchronous analysis already running. CPU and memory limits bound the service container, not an individual analysis job. There is no hard CPU deadline or customer-code execution facility.

The deployment template has not been executed here: Docker and Nginx are unavailable in the workspace. Validate `docker compose -f compose.production.yaml config`, build the image, run `nginx -t`, then exercise TLS, proxy-spoofing, saturation and restart recovery in staging before routing users to it. A real domain, identity service and hosting target have not been supplied.

## Encrypted backup and monitored restore

Generate separate cryptographically random binary keys: audit key at least 32 bytes, backup key exactly 32 bytes. Keep them on an access-controlled secret store outside source control and outside backup storage. Losing the backup key makes encrypted recovery impossible. Use encrypted storage and restricted ACLs for the live databases and temporary directory; live SQLite files are not encrypted by the app.

```powershell
python ops_job.py backup --config PRIVATE_CONFIG_PATH --backup-key PRIVATE_BACKUP_KEY_PATH --output-root OFF_DEVICE_BACKUP_DIRECTORY
python ops_cli.py drill ENCRYPTED_BACKUP_PATH --key PRIVATE_BACKUP_KEY_PATH
python ops_cli.py restore ENCRYPTED_BACKUP_PATH NEW_DATABASE_PATH --key PRIVATE_BACKUP_KEY_PATH
python ops_cli.py audit NEW_DATABASE_PATH --key PRIVATE_AUDIT_KEY_PATH --expected-head HEAD_FROM_TRUSTED_MANIFEST
python ops_job.py probe --origin https://devflow.example.com --token-file PRIVATE_SHORT_LIVED_ADMIN_TOKEN_FILE
```

Each backup job snapshots every tenant, encrypts with AES-256-GCM, restores to a temporary database, checks integrity and audit chain, and writes an HMAC-authenticated manifest with counts, timing, hash and chain head. Payloads up to 256 MiB are supported. Manifest signing and backup encryption use separate keys. The job fails on backup/restore/audit errors; the probe exits nonzero for readiness or audit failure. Monitor exit status in your scheduler. Token rotation for probes belongs to the identity service.

`deploy/devflow-backup.service` and `.timer` supply an hourly Linux scheduler example. Configure a real off-device mount, host-specific paths, user permissions and an alert destination before enabling the timer. The example timer is supplied, not installed. Use versioned immutable storage for backup/manifest retention; keep audit heads independently. Without an external trusted head, deleting the tail of an HMAC chain cannot be detected. An hourly schedule is an intended backup cadence, not a measured RPO; a database drill is not a production failover or an established RTO. Measure both on the deployed system.

Schema version 1 upgrades the prior unversioned schema idempotently and adds the audit table. Newer schemas are rejected to prevent unsupported downgrades. There is no invented rollback migration: preserve a stopped-server backup before upgrading and restore it with the matching application version when rolling back.
