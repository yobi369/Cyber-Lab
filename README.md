# Sentinel Lab — Defensive Cybersecurity Training

Sentinel Lab is a local-first training platform for defensive incident response, evidence-based assessment, scenario authoring, and audit integrity. It replaces the original reverse-shell prototype; it is not a remote administration tool.

> **Safety boundary:** no outbound connections, OS command execution, malware, persistence, live scanning, or real file transfer. Scenario artifacts are synthetic. The web server binds to loopback (127.0.0.1).

## Implemented capabilities
- SQLite-backed users, sessions, scenarios, scenario versions, submissions, and assessments.
- Server-side role assignment; browser requests cannot select or impersonate a role.
- PBKDF2-HMAC-SHA256 password hashes, opaque HttpOnly/SameSite session cookies, CSRF tokens, same-origin POST checks, and persistent login throttling.
- Optional per-account TOTP MFA with encrypted authenticator seeds; terminal enrollment and login challenge are implemented.
- Nonce-based Content Security Policy, TLS 1.2+ server context, and production fail-closed Secure-cookie/TLS configuration.
- SQLCipher-backed identity and training stores when production encryption is enabled; plaintext-to-encrypted migration, encrypted backup/restore and tested database key rotation.
- Enterprise OIDC Authorization Code + PKCE, JWKS signature validation, tenant/nonce/state checks, and administrator-controlled immutable subject mapping.
- Signed audit checkpoint key IDs, dual-signature rotation records, and an S3 Object Lock COMPLIANCE archive command.
- Out-of-band account provisioning; no public registration or browser role selector.
- Scenario lifecycle: instructor drafts, edits create immutable new versions, and publishing is explicit.
- Synthetic incident datasets and facilitator injects in [FACILITATOR_GUIDE.md](FACILITATOR_GUIDE.md).
- Learner evidence submissions and five-dimension human-reviewed scoring.
- Independent second review, reviewer separation, dimension-level agreement reporting, and adjudication flagging.
- SHA-256 hash-chained audit events plus signed audit-head checkpoint export.
- Responsive authenticated dashboard, unit tests, and Chromium browser security tests.

## First-time setup

Requires Python 3.11+.

Create a dedicated local database and provision your first instructor account from a trusted terminal:

```bash
python manage_users.py --db sentinel-lab.sqlite3 create-user brian --role instructor
```

The command prompts for a password (minimum 12 characters). Passwords are not accepted as command-line arguments and there is no public sign-up route.

Provision additional learners/reviewers/auditors the same way, choosing the appropriate role.

## Run
```bash
export SENTINEL_DB=./sentinel-lab.sqlite3
export ADMIN_LAB_AUDIT_FILE=./training-audit.jsonl
python dashboard.py
```
Open http://127.0.0.1:8765. Sign in with the account provisioned above. The server listens on loopback only.

The original safe command simulator is separate:
```bash
python admin_lab.py
```

## MFA enrollment

Install security dependencies with `python -m pip install -r requirements-security.txt`. Set `SENTINEL_MFA_ENCRYPTION_KEY` to a 64-character hex key from a secret manager, then enroll each account from a trusted terminal:

```bash
python manage_users.py --db sentinel-lab.sqlite3 enroll-mfa brian
```

The command displays an authenticator URI and requires a valid first code before storing the encrypted seed. Set `SENTINEL_REQUIRE_MFA=1` to block accounts that have not enrolled. Keep the MFA encryption key separate from database and backup keys.

## Enterprise SSO
Configure `SENTINEL_OIDC_ISSUER`, `SENTINEL_OIDC_CLIENT_ID`, `SENTINEL_OIDC_CLIENT_SECRET`, and `SENTINEL_OIDC_REDIRECT_URI` from a secret manager. Optionally set `SENTINEL_OIDC_TENANT_ID` and `SENTINEL_OIDC_REQUIRE_MFA=1`. Link the verified immutable subject to a pre-provisioned local account:

```bash
python manage_users.py --db sentinel-lab.sqlite3 link-oidc brian --issuer 'https://idp.example.com' --subject '<immutable-subject>'
```

The application does not trust email domains or IdP role claims. See [SECURE_DEPLOYMENT.md](SECURE_DEPLOYMENT.md) for IdP setup and validation details.

## Data persistence and encryption
In development, the stores use SQLite. Production requires `SENTINEL_ENV=production`, `SENTINEL_DB_ENCRYPTION=1`, and `SENTINEL_DB_KEY` (64 hex characters from a secret manager). Both identity and training stores use SQLCipher when enabled; production refuses plaintext fallback. For an existing database, stop the app, back it up, then run `python migrate_database.py encrypt plaintext.db encrypted.db` with `SENTINEL_DB_KEY` set. Set `SENTINEL_DB` to the verified encrypted file before restarting.

## Backup and restore helpers

Use `backup_sqlite()` and `restore_sqlite()` from `security_controls.py` for a consistent online SQLite/SQLCipher snapshot and integrity-checked restore. Optional AES-256-GCM wrapping requires a separate 32-byte key. SQLCipher migration, active store access, encrypted backup/restore and database key rotation are covered by CI tests. A witnessed recovery drill against the deployed database is still required.

## Signed audit checkpoints
Set a high-entropy key supplied by a secret manager (do not commit it):
```bash
export SENTINEL_AUDIT_HMAC_KEY='use-a-secret-of-at-least-32-characters'
python audit_checkpoint.py training-audit.jsonl /secure-export/checkpoint.json --key-id audit-v1 --s3-bucket '<object-lock-bucket>' --retention-days 365
python audit_checkpoint.py training-audit.jsonl /secure-export/checkpoint.json --verify --key-id audit-v1
```
The output is a signed statement of event count and audit head. With `--s3-bucket`, the command verifies bucket versioning/Object Lock and archives the checkpoint in COMPLIANCE mode. The adapter, background changed-head scheduler and retention-mode write are tested with a mocked client; a real bucket, credentials, auditor retrieval and external account controls still need live provisioning. Set `SENTINEL_AUDIT_S3_BUCKET` to enable scheduled archiving; set `SENTINEL_REQUIRE_EXTERNAL_AUDIT=1` to make it a startup requirement. `create_rotation_checkpoint()` creates dual-signed audit key transition records.

## Scenario and assessment workflow
- Instructors create draft scenarios and can create revised versions; prior versions remain preserved.
- Instructors explicitly publish a selected version. Learners can submit against published versions only; each submission records the exact scenario version.
- Reviewers grade evidence across evidence quality, reasoning, containment, preservation, and remediation (0–4 each).
- A reviewer may review a submission once. A second, different reviewer can independently assess it. Dimension differences above one point require adjudication; agreement metrics are reported for calibration, not as proof of reliability.

## Tests
Unit and security tests:
```bash
python -m pip install -r requirements-security.txt
python -m compileall -q admin_lab.py audit_chain.py audit_checkpoint.py security_controls.py oidc.py identity.py storage.py training_platform.py dashboard.py manage_users.py migrate_database.py tests
python -m unittest discover -s tests -v
```
Browser tests require Chromium:
```bash
python -m pip install -r requirements-browser-test.txt
python -m playwright install chromium
python -m unittest discover -s browser_tests -v
```
GitHub Actions runs Python 3.11/3.12 unit tests and a real Chromium authentication/CSRF integration job.

## Security status and limitations
This remains a local prototype pending deployment-specific acceptance. TOTP MFA, OIDC protocol flow, SQLCipher store integration, TLS startup, Secure cookies, nonce CSP, SQLCipher migration/rekey, encrypted recovery helpers and S3 Object Lock checkpoint archiving are implemented and have automated tests. Real IdP registration/credentials, TLS certificates and secret-manager configuration, a real Object Lock bucket, tenant isolation, a witnessed recovery drill, and independent penetration testing plus retest remain release gates. Password recovery codes and a scheduled remote checkpoint service are also not implemented.

Read [THREAT_MODEL.md](THREAT_MODEL.md), [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md), and [SECURE_DEPLOYMENT.md](SECURE_DEPLOYMENT.md) before use.

## License
No license is currently declared. All rights remain with the repository owner unless a license is added.
