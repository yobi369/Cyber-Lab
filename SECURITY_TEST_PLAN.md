# Security verification and independent assessment plan

## Automated CI coverage
- Python 3.11 and 3.12 compilation and unit/security tests.
- Chromium browser integration: unauthenticated state, password + MFA login, server-provided role, forged actor rejection, CSRF rejection, CSP nonce/header match, nonce rotation, and fail-closed OIDC endpoints.
- TOTP RFC 6238 vectors, encrypted seed handling, replay-counter enforcement and mandatory MFA policy.
- OIDC PKCE challenge, JWKS signature validation, issuer, audience, nonce, tenant, MFA assurance, authorized-party and discovery mismatch rejection; server-side one-time state and explicit subject mapping.
- TLS certificate loading and TLS 1.2 minimum; production cookie and database-encryption fail-closed behavior.
- SQLCipher plaintext migration, active identity/training store operations, encrypted backup/restore, wrong-key rejection and key rotation.
- Audit-chain tamper detection, signed checkpoint verification, dual-signature key rotation, invalid-chain refusal and mocked S3 Object Lock COMPLIANCE retention writes.
- CodeQL static analysis and pip-audit dependency vulnerability scanning.

## Manual pre-release security test plan
1. **Identity:** verify the configured enterprise IdP in a dedicated tenant; test invalid signature, issuer, audience, nonce, state, expired token, replayed code, unapproved tenant, missing MFA assurance, disabled account, unlinked subject, account linking, logout and IdP session behavior.
2. **Authentication:** password guessing, username enumeration, session fixation, cookie replay, logout invalidation, expired sessions, account disablement, MFA reset and recovery governance.
3. **Authorization:** horizontal and vertical privilege escalation across every endpoint and role; direct object reference tests for submissions, scenarios, assessments and audit records.
4. **Web security:** CSRF, reflected/stored XSS, CSP bypass attempts, reverse-proxy request smuggling, content-type confusion, oversized JSON and malformed encodings.
5. **Persistence:** concurrent writes, process termination during writes, SQLCipher migration and rekey interruption, WAL recovery, backup/restore, row-count reconciliation and audit/database consistency.
6. **External audit:** provision a separate security-account S3 bucket with Object Lock and versioning; verify a live object in COMPLIANCE mode, retained-until date, auditor-role retrieval, inability of the application role to delete/shorten retention, and recovery after simulated host loss.
7. **Assessment governance:** blind second reviews, reviewer conflicts, rubric calibration, score distributions, disagreement rates and adjudication evidence.
8. **Operations:** dependency inventory, SAST, secret scanning, host/container hardening, TLS/HSTS, security headers, logging, alerting, incident response and key custody.

## Independent penetration test scope
Engage an independent qualified tester under written authorization against a staging deployment using synthetic records only. Provide the threat model, role matrix, endpoint inventory, deployment diagram and test accounts. Require a signed report with reproducible findings, severity, impact, evidence, remediation guidance, owners and retest results. No independent penetration test or retest has been performed by this repository change; automated tests and CodeQL are not substitutes.

## External audit anchoring acceptance criteria
- The app verifies the local audit chain before creating a checkpoint.
- The background archiver sends changed audit heads to the configured S3 Object Lock bucket, signed with a key ID.
- The bucket must have versioning, Object Lock enabled and a default retention mode/duration; each object write explicitly requests COMPLIANCE retention.
- A separate auditor retrieves and verifies the retained object after simulated application-host compromise.
- Dual-signed transition checkpoints verify with both historical and new audit keys.
- A live bucket, separate security account, IAM separation, CloudTrail data events and auditor retrieval evidence are still required before external anchoring is accepted as production-ready.
