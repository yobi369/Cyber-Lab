# Security verification and independent assessment plan

## Automated CI coverage
- Python 3.11 and 3.12 compilation and unit tests.
- Password policy, password hashing, role provisioning, opaque session, CSRF validation, logout, and login-throttle tests.
- Service-level authorization checks and learner data scoping.
- SQLite persistence across platform restarts.
- Scenario draft/edit/version/publish lifecycle and published-version submission constraints.
- Independent second-review enforcement and dimension-level agreement calculations.
- Audit-chain tamper detection and HMAC checkpoint tamper detection.
- Chromium browser flow: unauthenticated access, login, role display from server identity, forged request actor rejection, and CSRF rejection.

## Manual pre-release security test plan
1. Authentication: password guessing, username enumeration, session fixation, cookie replay, logout invalidation, expired sessions, account disablement.
2. Authorization: horizontal and vertical privilege escalation across all endpoints and every role; direct object reference tests for submissions, scenarios, assessments and audit.
3. Web security: CSRF, reflected/stored XSS, CSP validation, request smuggling through reverse proxy, content-type confusion, oversized JSON and malformed encodings.
4. Persistence: concurrent writes, process termination during writes, SQLite integrity checks, WAL recovery, backup/restore and audit/database reconciliation.
5. Audit: alter, truncate, reorder and delete JSONL events; test checkpoint signatures with wrong keys; verify checkpoint retention in a separate account and restore process.
6. Assessment governance: blind second reviews, reviewer conflicts, rubric calibration sessions, score distributions, disagreement rates and adjudication evidence.
7. Operational security: dependency inventory, SAST, secret scanning, container/host hardening, TLS configuration, security headers, logging and alerting.

## Independent penetration test scope
Engage an independent tester with written authorization and a staging environment containing synthetic records only. Provide the threat model, role matrix, endpoint inventory, deployment diagram and test accounts. Require a report with reproducible findings, severity, impact, evidence, remediation guidance and retest results. No independent penetration test has been performed by this repository change.

## External audit anchoring acceptance criteria
- Checkpoint generation refuses invalid chains and requires a high-entropy HMAC key.
- The checkpoint includes event count, head hash, timestamp and signature.
- An operator uploads the artifact to an independently administered immutable/WORM store.
- A separate operator can retrieve and verify it after a simulated application-host compromise.
- Key rotation and recovery procedures are documented and tested.
