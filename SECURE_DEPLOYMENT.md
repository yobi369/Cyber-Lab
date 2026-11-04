# Production security and external assurance runbook

Sentinel Lab remains a local prototype. The controls in security_controls.py are reusable primitives; they do not imply that the current dashboard has integrated them.

## MFA and enterprise OIDC

TOTP uses RFC 6238, HMAC-SHA1, six digits, 30-second periods and a one-step clock-skew window. The local password login flow now accepts and enforces TOTP for enrolled users. Terminal enrollment verifies a first code before storing the seed encrypted with AES-GCM under SENTINEL_MFA_ENCRYPTION_KEY. Set SENTINEL_REQUIRE_MFA=1 to block unenrolled users. Recovery codes, reset/re-enrollment governance and enterprise step-up assurance remain to be implemented.

OIDC authorization-code + PKCE is not yet integrated. Select an enterprise IdP (Entra ID, Okta, or Keycloak), register exact redirect URIs, validate signature against trusted JWKS, issuer, audience, expiry, nonce, state and PKCE verifier, reject replay, and map immutable issuer+subject to a local identity. Restrict tenant IDs and require MFA/conditional access at the IdP. Never authorize by email domain alone. Add negative tests for every validation failure before enabling SSO.

## TLS, cookies and CSP

Production configuration must fail closed when TLS certificates or Secure cookies are absent. Required environment values: SENTINEL_ENV=production, SENTINEL_TLS_CERT, SENTINEL_TLS_KEY, SENTINEL_COOKIE_SECURE=1. The dashboard now calls tls_context() at startup and uses secure_cookie_attributes() for session cookies. Production startup fails when TLS certificate/key or Secure-cookie configuration is absent. When TLS terminates at a reverse proxy, configure a trusted deployment boundary and exact SENTINEL_PUBLIC_ORIGIN; do not trust arbitrary forwarded headers.

The current HTML uses inline scripts and styles. A per-response nonce must be generated, inserted into every script/style element and sent in the matching CSP header. Remove unsafe-inline and unsafe-eval. The dashboard now generates a fresh random nonce per HTML response and applies it to the inline script and style elements. Browser CI asserts nonce directives and rejects unsafe-inline/unsafe-eval. Revisit policy when adding new inline elements or external assets.

## Encrypted database and recovery

encrypted_sqlite_connect() uses SQLCipher and refuses plaintext fallback. Install a maintained SQLCipher binding and supply SENTINEL_DB_KEY as a 64-character hex value from a secret manager. Existing IdentityStore and TrainingStore still use sqlite3; the active app database is therefore NOT encrypted by this helper yet.

backup_sqlite() uses SQLite's online backup API; optional AES-256-GCM encryption requires cryptography and a 32-byte key. restore_sqlite() validates PRAGMA integrity_check and atomically installs the restored file. Automated tests exercise round-trip restore, but no production disaster-recovery exercise has occurred.

Run a recovery drill in an isolated environment: restore DB, audit JSONL, configuration and keys; validate row counts, audit chain and latest external checkpoint; perform a synthetic learner submission and review; record RPO/RTO; then destroy the test environment.

## Immutable external audit storage

S3ObjectLockArchive writes content-addressed audit objects with COMPLIANCE retention. Provision an Object-Lock-enabled bucket with versioning, default retention, separate security-account ownership, CloudTrail data events, and a write-only application role. Verify the bucket configuration before upload. The adapter is not yet wired to the audit checkpoint scheduler and has not been tested against a real bucket. Do not claim external immutable retention until that integration and a live acceptance test pass.

## Key rotation

Keep database, backup, OIDC and audit keys independent. Use secret-manager versioning and two-person approval. For audit HMAC rotation, publish a transition checkpoint signed by both old and new keys, retain old verification keys for the full retention period, and record key IDs. For SQLCipher, back up and verify first, use the supported rekey/export process, validate the new DB, test restore, then revoke the old key. Retain backup decryption keys for every backup still within retention. Never overwrite key versions.

## Independent penetration testing

No independent penetration test or retest has been performed. Engage an independent qualified firm under written authorization and test a staging deployment. Scope: MFA/OIDC, session lifecycle, CSRF/CORS, CSP/XSS, authorization/IDOR, tenant isolation, injection, backup and key handling, audit tampering, dependency/supply chain, TLS/proxy trust, and rate limits. Require a signed report, severity-ranked reproducible findings, remediation owners and retest evidence. Production readiness requires closure and retest of all critical/high findings.

## Release blockers

- MFA and OIDC integration with identity lifecycle, account linking and recovery.
- CSP nonce/hash integration in all HTML responses.
- SQLCipher adoption by both identity and training stores, including migration and key rotation.
- TLS/cookie wiring in the actual HTTP server and deployment proxy.
- Scheduled external audit anchoring to real Object Lock storage.
- A witnessed restore drill and independent penetration test plus retest.

