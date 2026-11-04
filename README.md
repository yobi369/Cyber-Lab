# Sentinel Lab — Defensive Cybersecurity Training

Sentinel Lab is a local-first training platform for defensive incident response, evidence-based assessment, scenario authoring, and audit integrity. It replaces the original reverse-shell prototype; it is not a remote administration tool.

> **Safety boundary:** no outbound connections, OS command execution, malware, persistence, live scanning, or real file transfer. Scenario artifacts are synthetic. The web server binds to loopback (127.0.0.1).

## Implemented capabilities
- SQLite-backed users, sessions, scenarios, scenario versions, submissions, and assessments.
- Server-side role assignment; browser requests cannot select or impersonate a role.
- PBKDF2-HMAC-SHA256 password hashes, opaque HttpOnly/SameSite session cookies, CSRF tokens, same-origin POST checks, and persistent login throttling.
- Optional per-account TOTP MFA with encrypted authenticator seeds; terminal enrollment and login challenge are implemented.
- Nonce-based Content Security Policy, TLS 1.2+ server context, and production fail-closed Secure-cookie/TLS configuration.
- SQLCipher-only encrypted connection helper, consistent SQLite backup, AES-256-GCM backup encryption/restore, and an S3 Object Lock COMPLIANCE archive adapter.
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

## Data persistence
SQLite stores identities, sessions, scenario versions and lifecycle state, learner submissions, and reviewer assessments. Use a consistent backup procedure for both the SQLite database (including WAL state; use SQLite's backup API or stop the app cleanly) and the JSONL audit log. Never copy only the main database file while WAL writes are active.

## Backup and restore helpers

Use `backup_sqlite()` and `restore_sqlite()` from `security_controls.py` for a consistent online SQLite snapshot and integrity-checked restore. Optional AES-256-GCM encryption requires `cryptography` and a 32-byte key. These helpers are tested with synthetic databases; a production recovery drill is still required. SQLCipher connection support is provided but the existing identity and training stores have not yet migrated to it.

## Signed audit checkpoints
Set a high-entropy key supplied by a secret manager (do not commit it):
```bash
export SENTINEL_AUDIT_HMAC_KEY='use-a-secret-of-at-least-32-characters'
python audit_checkpoint.py training-audit.jsonl /secure-export/checkpoint-2026-11-04.json
python audit_checkpoint.py training-audit.jsonl /secure-export/checkpoint-2026-11-04.json --verify
```
The output is a signed statement of event count and audit head. Copy it to a separately administered immutable/WORM store or independent security account. This repository does **not** itself configure that external store; independent retention, key rotation, access review, and restore verification remain operational responsibilities. HMAC checkpoints require secure protection and backup of the signing key.

## Scenario and assessment workflow
- Instructors create draft scenarios and can create revised versions; prior versions remain preserved.
- Instructors explicitly publish a selected version. Learners can submit against published versions only; each submission records the exact scenario version.
- Reviewers grade evidence across evidence quality, reasoning, containment, preservation, and remediation (0–4 each).
- A reviewer may review a submission once. A second, different reviewer can independently assess it. Dimension differences above one point require adjudication; agreement metrics are reported for calibration, not as proof of reliability.

## Tests
Unit and security tests:
```bash
python -m compileall -q admin_lab.py audit_chain.py audit_checkpoint.py identity.py storage.py training_platform.py dashboard.py manage_users.py tests
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
This is a hardened local prototype, not a production multi-user deployment. Before public or organizational use, complete enterprise OIDC/SSO, password reset and recovery, SQLCipher migration of both stores, tenant isolation, real-bucket Object Lock integration, witnessed backup/restore, rate-limit monitoring, dependency and SAST scanning, and independent penetration testing plus retest. TOTP MFA, TLS startup support, Secure cookies, and nonce-based CSP are implemented, but production deployment still requires secret/certificate provisioning and verification. The S3 adapter is not yet connected to a scheduled checkpoint exporter.

Read [THREAT_MODEL.md](THREAT_MODEL.md), [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md), and [SECURE_DEPLOYMENT.md](SECURE_DEPLOYMENT.md) before use.

## License
No license is currently declared. All rights remain with the repository owner unless a license is added.
