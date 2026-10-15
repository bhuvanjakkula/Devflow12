# OpenAI assistance — DevFlow 0.19

Open `/ai`, also linked from Engineering. Select a project and one of three tasks: requirements analysis, bug investigation or code/behavior explanation. Enter only the relevant question and optional context, confirm that this text may be sent to OpenAI, then generate suggestions. Download results as JSON. All results are suggestions requiring human review; they do not alter requirements, code, approvals, evidence or verification status. Rendering uses text nodes, not model-generated HTML.

## Enable locally

Existing runtime dependencies already include HTTPX; no additional AI SDK is required. The server calls the official Responses REST endpoint at `https://api.openai.com/v1/responses`.

Supply an API key through your process environment or an access-controlled key file. Keep keys out of chat, browser forms and source control. Configure before starting the server:

```powershell
$env:DEVFLOW_OPENAI_ENABLED = '1'
$env:OPENAI_API_KEY_FILE = 'C:\private\openai-api-key.txt'
$env:OPENAI_MODEL = 'YOUR_SUPPORTED_MODEL_ID'
$env:DEVFLOW_OPENAI_DAILY_LIMIT = '20'
python run.py
```

Alternatively, supply `OPENAI_API_KEY` through your secret manager's environment injection. `OPENAI_API_KEY_FILE` takes precedence when set. Choose a model available to your OpenAI API project that supports the Responses API and strict structured outputs. No model name or account access is guessed. An existing ChatGPT/Codex session does not configure this server's API credential.

`GET /api/ai/status` reports configuration and tenant availability without exposing the credential or secret-file path. Configuration is read per request; environment changes require restarting the process, while replacing the configured key file can rotate the key. AI is disabled unless `DEVFLOW_OPENAI_ENABLED=1`, a key and a syntactically valid model ID are present. Configuration status does not prove a key/model can successfully call OpenAI.

## Enterprise and production

In enterprise mode, also set `DEVFLOW_OPENAI_TENANTS` to an explicit comma-separated list of approved tenant IDs. A missing list permits no enterprise tenants. Editors/admins may submit requests; viewers/reviewers retain their existing read/review restrictions. The project lookup and quota reservation use the authenticated tenant's database. Payloads cannot select another tenant, change the model or supply provider credentials.

For the production container, put the provider key in the ignored `secrets/openai-api-key.txt` and set `OPENAI_MODEL` and `DEVFLOW_OPENAI_TENANTS` in the deployment environment. Merge the optional overlay:

```text
docker compose -f compose.production.yaml -f compose.openai.yaml config
docker compose -f compose.production.yaml -f compose.openai.yaml up --build
```

The base production network intentionally blocks outbound access. The explicit OpenAI overlay adds an egress network without publishing the application port. This network permits general outbound connectivity; deploy an external firewall/egress gateway to restrict it to approved OpenAI destinations if required. Secret mounting and networking need staging verification; Docker is unavailable here. Other enterprise setup requirements still apply.

## API example

`POST /api/projects/{project_id}/ai/assist` accepts:

```json
{
  "task": "debug",
  "text": "Why does an empty list cause this error?",
  "context": "def average(values): return sum(values) / len(values)",
  "consent_to_send": true
}
```

Supported tasks are `requirements`, `debug` and `explain`. Text and optional context are each limited to 20,000 characters. Consent must be the JSON boolean `true`. Unknown fields are rejected. The response contains `summary`, `findings`, `suggested_actions`, `acceptance_criteria`, `verification_steps` and `limitations`, plus `verified: false`. No other project records, repository files, previous prompts or stored reports are automatically attached.

Requests use strict JSON Schema output, a 2,000-token output cap, bounded response bytes, a five-second connection timeout and 45-second HTTP phase timeout. There are no tools, code execution, browsing or automatic retries. Provider failures, refusals, invalid/incomplete output and rate limits are returned as safe errors. Provider diagnostics and credentials are not echoed. These safeguards do not prove that model suggestions are correct or immune to prompt manipulation.

## Cost, persistence and privacy

The default quota is 20 reserved AI attempts per tenant database per UTC day, across all its projects. Configure `DEVFLOW_OPENAI_DAILY_LIMIT` from 1 to 1,000. Reservation uses a SQLite write transaction before contacting OpenAI; crashes and failed/denied provider requests still count. This is a request limit, not a currency spending cap. Configure provider project spend controls separately. API usage can incur charges.

DevFlow stores only request metadata: project ID, task, configured model, input digest, outcome and timestamp. It does not persist AI request text/context or generated suggestions. Enterprise audit records cover the metadata writes. An input hash is not anonymization; avoid including sensitive information you cannot share. Model output remains in the browser/API caller unless exported. Existing non-AI project records retain their existing persistence behavior.

The request sets `store: false` and does not create a conversation, reuse a response ID or attach provider tools. This does **not** guarantee zero provider retention; OpenAI's applicable account and abuse-monitoring policies still govern processing. Review [OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data) for your API project before sending confidential content.

Schema version 2 adds the metadata/quota table to the prior schema without altering existing workflow records. Back up before upgrading. Restore a pre-upgrade backup with the matching application version if rollback is needed; older versions reject newer schemas.

## Verification and activation boundary

Tests simulate Responses transport and exercise all three tasks, explicit consent, request formatting, strict output validation, refusals, oversized/incomplete output, provider authentication/rate errors, timeouts, connection errors, quotas, tenant opt-in, role denial and preservation of workflow records. They do not evaluate model answer quality or prove actual provider access. The full local quality report is `docs/quality-verification-v0.19.json`.

No API key was available in the workspace, so no live request or paid inference was performed. To activate, supply the private key and supported model, restart DevFlow, check `/api/ai/status`, and submit a nonsensitive example in `/ai`. Verify the returned suggestions with real tests before relying on them.

Implementation references: [Responses API](https://developers.openai.com/api/reference/responses/overview), [strict structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses) and [data controls](https://developers.openai.com/api/docs/guides/your-data).
