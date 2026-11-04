# Sentinel Lab threat model

## Scope and security boundary
Local-first defensive training with synthetic evidence. The server binds to 127.0.0.1. It does not execute commands, connect to target systems, scan networks, run malware, or ingest production telemetry.

## Assets
- Account credentials, password salts/hashes, active session tokens and CSRF tokens.
- User roles and permissions.
- Scenario content, immutable versions, publication state, learner evidence, reviewer feedback and moderation records.
- Hash-chained audit events and signed checkpoint keys/artifacts.

## Trust boundaries
1. Browser to loopback HTTP server: untrusted request bodies, headers, cookies and client JavaScript.
2. Server to SQLite: trusted application data store, but filesystem access is privileged.
3. Server to audit JSONL: append-only application behavior; filesystem administrators can still alter it.
4. Checkpoint export to independent retention: requires an operator to move the signed checkpoint and protect the HMAC key outside the application host.

## Threat analysis
| Threat | Implemented mitigation | Residual risk |
|---|---|---|
| Browser role spoofing | Identity and role are loaded from server-side session; request body actor is ignored | CLI/database administrators can assign roles |
| Password guessing | PBKDF2-HMAC-SHA256, per-user salts, persistent IP-hash throttling | No MFA; local host compromise bypasses application controls |
| Session theft | Random opaque token, SHA-256 token storage, HttpOnly, SameSite=Strict, expiry, logout revocation | HTTP loopback is not TLS; Secure cookie not set for local HTTP |
| CSRF / cross-origin requests | CSRF token, same-origin Origin check, SameSite cookie | Reverse-proxy deployment needs a carefully configured trusted origin |
| XSS | DOM textContent for untrusted values, restrictive CSP, no third-party scripts | Inline script/style requires unsafe-inline until nonce/hash CSP work |
| Unauthorized data access | Service-layer permission checks; learner assessments scoped to own submissions | No multi-tenant boundary or organization isolation |
| Data loss | SQLite persistence and separate audit log | Backup/restore process must be operated and tested; audit and DB can diverge |
| Scenario tampering | Versioned records; published versions preserved; edits create a new draft version | No approval workflow or author/reviewer separation on publication |
| Assessment bias | Two independent reviewers, one review per reviewer, dimension deltas and adjudication threshold | Rubric validity and inter-rater reliability have not been empirically established |
| Audit rewrite | SHA-256 hash chain and HMAC-signed head checkpoint | HMAC key compromise permits forged checkpoints; remote immutable storage is not provisioned here |

## Security controls in code
- No public registration endpoint; user creation is terminal-only.
- Passwords are prompted interactively by manage_users.py.
- Server binds to loopback; JSON request bodies are bounded.
- Mutating requests require a valid session and CSRF token.
- Same-origin POST validation and persistent login throttling are applied.
- SQLite foreign keys and WAL mode are enabled.
- Evidence and scenario fields are length-bounded.
- Browser rendering uses textContent rather than HTML injection.

## Production blockers
Do not expose this prototype publicly or enter real customer, personal, or production incident data. Production requires TLS, Secure cookies, MFA/SSO, password reset and account recovery, hardened reverse-proxy origin configuration, tenant isolation, encryption at rest, secret management, tested backups and restores, independent WORM audit storage, key rotation, security monitoring, rate-limit operations, and independent penetration testing.

## Verification status
Automated unit and Chromium tests validate selected controls. They do not constitute a penetration test, formal security audit, or certification.
