# Free passwordless owner access — v0.10

Owner profile: **bhuvanjakkula@gmail.com**. This release provides no-cost local owner access, with no DevFlow account password, payment integration, subscription or API token entry.

## Open your website

From the extracted project folder, install dependencies if needed:

```powershell
python -m pip install -r requirements.txt
python run.py
```

On Windows you can also double-click `Start-DevFlow-Owner.cmd` after installing requirements. The terminal prints a fresh owner link beginning with `http://127.0.0.1:8000/owner/enter?token=...`. Open that link on this computer within five minutes. The website opens the engineering dashboard and shows your configured email and owner role. You can switch to Traceability, API docs or other tools without entering a password or token.

The link is a secret, one-use credential. Do not share it. A later ordinary visit to `/engineering` works while the browser session remains valid. The session expires after eight hours, sign-out or server restart. Restart `python run.py` to get a fresh link. Access logs are disabled by the owner launcher so the URL token is not written to its normal HTTP access log.

Owner access verifies possession of a link printed by your local process. **It does not verify Gmail ownership.** The email is a configured profile label, not a login credential. Entering the email alone never grants access. Anyone able to read the local terminal link can claim that session; use this only on your own trusted computer.

## Access protections

- Local client and localhost host checks.
- Five-minute one-use launcher token, compared through its hash.
- Opaque browser session in an HttpOnly, SameSite=Strict, host-only cookie.
- API and application pages require the owner session when launched using `run.py`.
- Existing cross-origin write checks and response headers remain enabled.
- Old links/sessions are invalidated when a new launcher link is issued.
- An API bearer token cannot bypass the owner session in owner mode.

The cookie uses Secure on HTTPS; local HTTP needs a non-Secure cookie. State is in process memory, so run the single default worker without reload. This is a local access mechanism, not a public identity system or multi-user authorization service. Directly starting `uvicorn app.main:app` does not enable this owner mode; use the included launcher. PQC export tools remain separate and their private keys still require strong key passphrases.

## Public access

Version 0.11 adds an email-protected temporary public link. See [Public owner access](PUBLIC_OWNER_ACCESS.md). Local launcher sessions still do not verify Gmail ownership; public access uses Cloudflare email PIN authentication.
