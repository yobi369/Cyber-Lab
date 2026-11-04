# Sentinel Lab — Authorized Administration & Defensive Cybersecurity Training

A safe, local-only training environment for defensive incident response, evidence-based assessment, role-based workflows, and audit integrity.

> **Safety boundary:** This is not a remote administration product. It does not open outbound connections, execute operating-system commands, transfer real files, install persistence, scan networks, or run malware. All incident evidence is synthetic. The browser app binds to loopback only.

## Training capabilities
- **Scenario library:** suspicious account activity, ransomware tabletop (no malware), and possible sensitive-data exposure.
- **Instructor authoring:** create additional bounded scenarios with objectives, synthetic artifacts, and explicit safety boundaries.
- **Incident-response practice:** learners submit observations, timelines, containment decisions, reasoning, confidence, and remediation.
- **RBAC:** learner, instructor, reviewer, and auditor roles. Permissions are checked in the service layer, not only in the interface.
- **Evidence-based assessment:** reviewers score five dimensions from 0–4 (20 points maximum) and provide written feedback.
- **Tamper-evident audit:** append-only JSONL records form a SHA-256 hash chain; sequence, previous hash, and event digest are verified.
- **Professional local dashboard:** scenario library, authoring form, learner evidence form, review queue, and audit integrity status.

## Run the simulator
Requires Python 3.11+ and no third-party runtime packages.

```bash
export ADMIN_LAB_TOKEN='local-training-token'
python admin_lab.py
```

The legacy command-line simulator demonstrates authentication and a strict in-memory command allowlist. It is separate from the scenario training dashboard.

## Run the training dashboard
```bash
python dashboard.py
```
Open http://127.0.0.1:8765. Stop with Ctrl+C. The demo role selector is intentionally not an authentication system: anyone with local browser access can select a role. Do not expose the server publicly or use real learner or incident data.

Optional audit file location:
```bash
ADMIN_LAB_AUDIT_FILE=./training-audit.jsonl python dashboard.py
```

Audit integrity can be checked from the dashboard or with the platform's AuditChain.verify() method. The file is tamper-evident, **not tamper-proof**. A privileged attacker able to rewrite the complete file can recompute the chain. Production requires signed checkpoints anchored in a separate trusted system.

## Tests
```bash
python -m compileall -q admin_lab.py audit_chain.py training_platform.py dashboard.py tests
python -m unittest discover -s tests -v
```

CI runs on Python 3.11 and 3.12.

## Architecture
- `admin_lab.py` — safe command simulation.
- `audit_chain.py` — hash-chained audit events and integrity verification.
- `training_platform.py` — scenarios, RBAC, submissions, grading, and audit integration.
- `dashboard.py` — loopback-only browser interface and JSON endpoints.
- `tests/` — simulator, audit, authorization, assessment, and scenario-authoring tests.
- `THREAT_MODEL.md` — trust boundaries, threat analysis, residual risk, and production blockers.
- `SECURITY.md` — responsible-use policy.

## Assessment model
Each submission is reviewed across evidence quality, reasoning, containment, preservation, and remediation. Each dimension receives an explicit 0–4 score. The platform records the reviewer and score in the audit chain. Scoring is human-reviewed; the software does not claim to infer incident-response competence from keyword matching.

## Threat model and production limitations
Read [THREAT_MODEL.md](THREAT_MODEL.md) before use. Current records and assessments are held in memory; the audit log is local JSONL. The demo role selector is not authentication, and there is no CSRF/session model, multi-tenant database, encryption-at-rest, backup/restore workflow, retention policy, or external audit anchoring. These are deliberate prototype limitations, not production-ready claims.

## License
No license is currently declared. All rights remain with the repository owner unless a license is added.
