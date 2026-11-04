# Sentinel Lab production security runbook

This is an implementation and operations guide. Code-level tests do not prove a production IdP, secret manager, TLS endpoint, cloud Object Lock bucket, or external penetration test has been provisioned.

## MFA and enterprise OIDC/SSO

### Local TOTP MFA
- RFC 6238 TOTP: 6 digits, 30-second steps, one-step clock-skew tolerance.
- Authenticator seeds are encrypted with AES-256-GCM using SENTINEL_MFA_ENCRYPTION_KEY.
- Accepted time-step counters are persisted atomically to reject replay.
- Enroll from a trusted terminal: `python manage_users.py --db sentinel-lab.sqlite3 enroll-mfa <username>`.
- Set SENTINEL_REQUIRE_MFA=1 to deny password-only login for accounts not yet enrolled.
- Recovery codes and self-service recovery are intentionally not present; use a controlled administrator re-enrollment process and identity proofing until a reviewed recovery workflow is implemented.

### Enterprise OIDC
The dashboard implements OIDC Authorization Code flow with PKCE S256. It validates discovery issuer, HTTPS endpoints, ID-token signature via JWKS, issuer, audience, expiry/issued-at, nonce, subject, and optional tenant ID. State transactions are random, stored server-side, expire after five minutes, and are consumed once. It never provisions roles from claims or email domains: an administrator must map the immutable issuer+subject to a pre-provisioned local user.

Set these environment variables from a secret manager:
- SENTINEL_OIDC_ISSUER — exact HTTPS issuer URL.
- SENTINEL_OIDC_CLIENT_ID
- SENTINEL_OIDC_CLIENT_SECRET
- SENTINEL_OIDC_REDIRECT_URI — exact registered HTTPS callback, `https://your-host/auth/oidc/callback`.
- Optional SENTINEL_OIDC_TENANT_ID — restrict the token `tid` claim.
- Optional SENTINEL_OIDC_REQUIRE_MFA=1 — require `amr` to include `mfa`.

Provision and link a user from a trusted terminal after verifying the subject with the IdP administrator:
```bash
python manage_users.py --db sentinel-lab.sqlite3 link-oidc <username> --issuer 'https://idp.example.com' --subject '<immutable-subject>'
```
The browser offers “Continue with enterprise SSO”. Unlinked subjects are denied. Test against the organization's real IdP in a staging tenant before enabling production use. Configure IdP MFA/conditional access; do not rely on an email address as an identity key.

## TLS, cookies and CSP
The HTTP server can terminate TLS directly. It enforces TLS 1.2 minimum and requires TLS cert/key and Secure cookies when SENTINEL_ENV=production. Set:
- SENTINEL_ENV=production
- SENTINEL_TLS_CERT=/run/secrets/tls.crt
- SENTINEL_TLS_KEY=/run/secrets/tls.key
- SENTINEL_COOKIE_SECURE=1
- SENTINEL_PUBLIC_ORIGIN=https://your-host (exact public origin)

The server binds to loopback by default. Only set SENTINEL_BIND to a public interface behind an explicitly trusted TLS edge. If using a reverse proxy, the proxy must reject plaintext external traffic and set the exact public origin; the app does not trust arbitrary forwarded headers.

Every HTML response receives a fresh cryptographically random nonce. The same nonce is applied to inline script/style elements and the CSP header. Browser tests assert matching nonce, per-response rotation, and absence of unsafe-inline/unsafe-eval. Keep CSP restrictive when adding assets.

## Encrypted database and migration
Both IdentityStore and TrainingStore now use the shared database connector. In development, SQLite remains the default. In production, the app refuses to start unless SENTINEL_DB_ENCRYPTION=1; this activates SQLCipher and refuses plaintext fallback.

Set SENTINEL_DB_KEY to a 64-character hex value (256-bit key) from a secret manager. Install dependencies:
```bash
python -m pip install -r requirements-security.txt
```

For an existing plaintext database:
1. Stop the application and create a verified backup.
2. Generate a new database key in the secret manager.
3. Create an encrypted copy:
```bash
export SENTINEL_DB_KEY='<64-hex-character-key>'
python migrate_database.py encrypt sentinel-lab.sqlite3 sentinel-lab.encrypted.sqlite3
```
4. Verify the encrypted copy and perform a test restore before switching SENTINEL_DB to it.
5. Set SENTINEL_DB_ENCRYPTION=1 and start the app against the encrypted file.
6. Retain the original backup under restricted retention until acceptance is signed.

For key rotation, stop all app processes, set SENTINEL_DB_OLD_KEY and SENTINEL_DB to the new key, then run:
```bash
export SENTINEL_DB_OLD_KEY='<old-64-hex-key>'
export SENTINEL_DB_KEY='<new-64-hex-key>'
python migrate_database.py rekey sentinel-lab.encrypted.sqlite3
```
The rekey operation checkpoints WAL, copies into a newly encrypted database, validates integrity using the new key, and atomically replaces the database. Retain the old key until restore validation is complete. Keys must be unique across database, MFA, backup and audit uses.

## Backup and recovery
`backup_sqlite()` uses the SQLite/SQLCipher online backup API and honors SENTINEL_DB_ENCRYPTION. Optional AES-256-GCM backup wrapping requires a separate 32-byte backup key. `restore_sqlite()` authenticates encrypted backup bytes, checks database integrity using the configured SQLite/SQLCipher backend, applies restrictive file permissions and atomically installs the restored database.

CI verifies plaintext and encrypted backup/restore, wrong-key rejection, SQLCipher migration, live IdentityStore/TrainingStore operation, and SQLCipher key rotation. This is not a witnessed recovery drill for a deployed system.

Production recovery drill:
1. Quiesce the service; capture database, audit JSONL, configuration, and all key versions.
2. Store encrypted backup in a separate security account/region with retention and least privilege.
3. Restore into an isolated environment with outbound access and production credentials disabled.
4. Validate SQLCipher integrity, identity/training row counts, audit-chain validity, and latest external checkpoint.
5. Run a synthetic learner submission and independent review.
6. Record measured RPO/RTO, evidence, approver, and exceptions; destroy the isolated restore environment securely.

## External immutable audit storage
The checkpoint utility supports:
```bash
export SENTINEL_AUDIT_HMAC_KEY='<secret-from-secret-manager>'
export SENTINEL_AUDIT_KEY_ID='audit-2026-q4'
python audit_checkpoint.py training-audit.jsonl /secure-export/checkpoint.json --key-id "$SENTINEL_AUDIT_KEY_ID" --s3-bucket '<object-lock-bucket>' --retention-days 365
```
The command verifies the bucket has versioning and Object Lock default retention, then writes the signed checkpoint using S3 Object Lock COMPLIANCE retention. CI uses a mocked S3 client to verify the required retention-mode write. No real bucket has been provisioned or tested in this repository environment. Configure a dedicated security-account bucket, separate write-only application role, auditor read role, CloudTrail data events, and lifecycle/retention policy before claiming live external immutability.

## Audit key rotation
`create_rotation_checkpoint()` creates a transition record signed by both old and new audit keys; `verify_rotation_checkpoint()` requires both key versions. Keep both verification keys for the complete audit-retention period. Record key IDs, approvers and transition checkpoints. Never overwrite old key versions. Database rekey and backup-key rotation are separate operations.

## Independent penetration test and retest
No independent penetration test has been performed. Internal unit, browser, SQLCipher, OIDC-token-validation, CSP, and TLS-configuration tests are not an independent security assessment. Engage an independent qualified security firm under written authorization against a staging deployment. Scope: OIDC/MFA, session lifecycle, CSRF, CSP/XSS, authorization/IDOR, tenant isolation, SQL injection, encrypted DB and backup/key handling, audit retention/tampering, dependency/supply chain, TLS/proxy trust, rate limiting and operational recovery. Require a signed report, severity-ranked reproducible evidence, remediation owners, and independent retest of all critical/high findings.

## Remaining release gates
- Configure and verify the organization's real OIDC provider, client credentials, redirect URI, tenant policy and IdP MFA.
- Provision production TLS certificate, public origin, reverse proxy and secret-manager policies.
- Run migration on the actual deployment DB, then perform a witnessed recovery and key-rotation drill.
- Provision the external S3 Object Lock bucket and verify a real retained object plus auditor retrieval.
- Commission independent penetration testing and retest.
- Define and test tenant isolation before multi-organization hosting; this prototype is not yet a multi-tenant service.
