# DevFlow 12 v0.9 — post-quantum report protection

This release provides offline signed, encrypted report exchange with ML-KEM-768 and ML-DSA-65 library primitives, plus optional bearer-token API protection and browser-origin checks. It is a security foundation, not a claim that the entire application is quantum-safe or production-ready.

ML-KEM is specified by [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final); ML-DSA by [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). The pinned `pqcrypto` implementation is not claimed to be a FIPS-validated cryptographic module. The application envelope composition has not received an independent cryptographic audit.

## Install and start

```powershell
python -m pip install -r requirements-pqc.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The package uses `pqcrypto==0.4.0` and `cryptography==46.0.3`. Wheels must support your interpreter/platform. The main app remains usable without the optional PQC dependencies; PQC tests are skipped if the optional provider is unavailable. Review dependency updates and security advisories before production use.

## Protect live APIs

Generate a fresh random bearer token in your own terminal, retain it securely, then start the app in that shell:

```powershell
$env:DEVFLOW_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
python run.py
```

The token must be at least 32 characters; an empty/short configured token fails closed. API calls require `Authorization: Bearer <token>`. The local dashboards prompt with a password field and retain the token only in page memory. Reloading prompts again. API docs/schema and HTML assets are available without a token; use **Authorize** in `/api/docs` to send the bearer token. Without the environment variable, the app remains in its original unauthenticated local mode.

Cross-origin browser writes are rejected. This is a shared-token local boundary, not authenticated user roles, tenant isolation, a rate limiter or protection against arbitrary local malware/XSS. Keep the default `127.0.0.1` binding. Do not expose this HTTP service publicly; network deployments require hardened authentication/authorization and appropriately configured TLS termination. No PQ-TLS negotiation is added by this release.

## Generate encrypted offline key bundles

```powershell
python pqc_cli.py keygen --directory pqc_keys_sender
python pqc_cli.py keygen --directory pqc_keys_recipient
```

Each directory receives a public-key JSON and password-encrypted private-key JSON. Passphrases are prompted with hidden input, never command arguments. Use a high-entropy passphrase of at least 16 characters. The key file uses fixed scrypt parameters and AES-256-GCM with random salt/nonce. Configure OS permissions yourself: this CLI does not establish Windows ACLs or provide an HSM/KMS. Back up private keys and passphrases securely; losing them loses decryption/signing capability. Python memory cannot guarantee secret zeroization.

Share only `public.pqc.json`. The CLI prints its SHA-256 fingerprint; verify that fingerprint through an independently trusted channel before accepting a sender or recipient key. Trust is supplied by pinned public-key files, not by a public key bundled with an incoming report. Replacement keys require explicit out-of-band trust; automated revocation/rotation registries are not implemented.

## Seal an exported report

Download a normal JSON report from DevFlow, then:

```powershell
python pqc_cli.py seal --report report.json --private pqc_keys_sender/private.pqc.json --recipient pqc_keys_recipient/public.pqc.json --output report.pqc.envelope.json
python pqc_cli.py verify --envelope report.pqc.envelope.json --sender pqc_keys_sender/public.pqc.json
python pqc_cli.py open --envelope report.pqc.envelope.json --private pqc_keys_recipient/private.pqc.json --sender pqc_keys_sender/public.pqc.json --output recovered-report.json
```

ML-KEM establishes a fresh shared secret per export. HKDF-SHA256 derives an AES-256-GCM key using a versioned domain and header context. AES-GCM authenticates the canonical header, and ML-DSA signs the header plus ciphertext under a separate domain. Version, exact suite, sender/recipient fingerprints, KEM ciphertext and nonce are bound to the protected export. Signature checking against a pinned sender key precedes decapsulation/decryption. Wrong keys, tampering and suite changes fail. Output files are created exclusively and never overwritten.

Limits: 8 MB plaintext report; CLI input files at most 12 MB. Envelopes contain no private keys. No signing or decryption web endpoint is exposed. The recipient verifies origin/integrity and decrypts; signatures do not prove the report's findings or self-reported test outcomes are true. Archived envelopes can be replayed; there is no transport anti-replay protocol. Check the report's source/requirement freshness separately.

Private keys, local dependencies, data directories and encrypted export files are excluded from the source-release packager. Store keys in the documented `pqc_keys*` directories. This is not a secret-scanning mechanism; manually putting secrets in arbitrary source files can still leak them through packaging.

## What remains outside protection

SQLite, downloaded plaintext reports, entered source and process memory remain plaintext. The localhost HTTP connection has no PQ-TLS. No whole-repository access control, per-user identities, audit-log signatures, HSM integration, certified module, hybrid classical/PQ combiner or global cyber-security guarantee is claimed.

64 tests passed with the actual PQC libraries loaded: real encryption/signature roundtrip, fresh ciphertext, modified ciphertext/signature/KEM/nonce rejection, wrong pinned sender/recipient rejection, downgrade rejection, encrypted private-key recovery, wrong-password rejection, token protection, origin restrictions and all existing DevFlow tests.
