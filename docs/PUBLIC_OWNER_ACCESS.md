# Public owner access — v0.11

Run `python public_owner.py` or double-click `Start-DevFlow-Public-Owner.cmd`. Install requirements.txt first. The official Windows cloudflared client must be installed as `.bin/cloudflared.exe`; it is deliberately excluded from the source release. Download it from https://github.com/cloudflare/cloudflared/releases and use a version supporting `--allowed-mail`.

The launcher prints a temporary HTTPS URL and saves it to `data/public-url.txt` while running. Open the URL, enter `bhuvanjakkula@gmail.com`, then enter the PIN delivered by Cloudflare. No DevFlow password, paid subscription, Cloudflare account or domain is required. The app relies on Cloudflare's email authentication at the tunnel edge. It does not send email itself or implement Google OAuth.

Only the configured owner email is allowlisted. The launcher never falls back to an unprotected tunnel. Its isolated origin binds to loopback on a random port and requires a random secret Host header supplied by cloudflared. Proxy header trust is disabled, so a forged forwarded address cannot bypass the loopback check. Browser writes must originate from the exact generated HTTPS origin. Access and bootstrap tokens are not logged by the origin server. The secret is local process configuration; users with access to your computer/processes are trusted.

Local `python run.py` access can run alongside this launcher. Each server uses the same SQLite project database by default. Stop the public launcher to revoke the public link and its sessions. If either subprocess exits, the launcher stops both. A new start creates a new hostname. Public logout is handled by terminating the tunnel, not the local session logout route.

This is temporary development access, not permanent production hosting. Your computer must remain online, and Quick Tunnels have no uptime guarantee. Cloudflare processes authentication and proxied traffic. See https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/ for service behavior and limits.

## Completion and validation

- Completed interrupted owner-only public access with an email-protected tunnel.
- Preserved passwordless local owner access.
- Added rejection tests for direct origin access, wrong secret host, remote clients, absent configuration and cross-origin writes.
- Clean source packaging excludes binaries, dependency caches, logs, environment files, private PQC artifacts and runtime data.
- Full suite: 70 tests passed with optional PQC dependencies on 14 October 2026.

Permanent hosting, multi-user roles, trusted CI integration and sandboxed execution are separate roadmap work, not implemented by this release.
