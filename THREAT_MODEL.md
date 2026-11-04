# Threat model and security testing plan

## Scope and trust boundaries
This is a local educational application using synthetic incident artifacts. The dashboard binds only to 127.0.0.1. It does not connect to endpoints, execute commands, ingest real telemetry, or process real personal data.

## Assets and roles
- Learner: reads scenarios, submits evidence, reads only their own assessments.
- Instructor: reads submissions, grades evidence, reviews audit integrity.
- Reviewer: reads submissions and grades evidence.
- Auditor: reads scenarios and verifies audit integrity.
- Protected data: learner evidence, feedback, role decisions, scenario records, and audit metadata.

## Threats and mitigations
| Threat | Mitigation | Residual limitation |
|---|---|---|
| Unauthorized action | Central permission checks; deny-by-default role map | Demo role selection is not identity authentication |
| Evidence tampering | Hash-linked events, sequence numbers, canonical JSON, fsync | Whole-file rewrite can rebuild an unanchored chain |
| Malicious input | Bounded fields, JSON parsing, textContent rendering, no shell interpolation | Not hardened for hostile multi-user hosting |
| Assessment manipulation | Explicit rubric, bounded integer scores, reviewer identity in audit | No moderation or inter-rater calibration yet |
| Scenario misuse | Synthetic artifacts and tabletop-only exercises | Facilitators must enforce scope |
| Data disclosure | In-memory training records; loopback-only server | No encryption-at-rest or production retention controls |

## Security tests
- Verify hash-chain integrity and detect edited events.
- Verify allowed and denied role operations.
- Reject unknown scenarios, missing/oversized evidence, and invalid rubric scores.
- Check that the dashboard binds to loopback and uses restrictive response headers.
- Run dependency, static-analysis, and secret-scanning checks in CI.

## Production blockers
Do not expose this prototype publicly or use real customer, personal, or production security data. Production requires OIDC, CSRF protection, secure per-user sessions, database-backed isolation, encrypted storage, retention policy, backups, external audit anchoring, rate limiting, and independent penetration testing.
