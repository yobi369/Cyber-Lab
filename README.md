# Authorized Administration Lab

A deliberately safe, local-only training simulator for practicing administrative-session concepts: authentication, command allowlisting, and audit events.

> **Safety notice:** This project does not provide remote access. It opens no network connections, executes no operating-system commands, transfers no files, and installs no persistence. It is not a production remote-management tool.

## Why the project changed
The original prototype was described as a reverse shell. It had unsafe arbitrary shell execution and material protocol/security defects: generated encryption keys were not shared durably, TCP message framing was undefined, and configuration included a weak default password. This branch replaces that implementation with a transparent simulator.

## Features
- In-memory authentication demonstration using constant-time token comparison.
- Narrow command allowlist: `help`, `status`, `inventory`, and `exit`.
- Rejection and audit recording for unknown commands.
- Deterministic local execution with no network or subprocess dependency.
- Unit tests and a Python 3.11/3.12 CI matrix.

## Run locally
Requires Python 3.11+ and no third-party runtime packages.

```bash
export ADMIN_LAB_TOKEN='local-training-token'
python admin_lab.py
```

Enter the same token at the prompt. Try `help`, `status`, `inventory`, and `exit`. Use a disposable training token, never a production password.

## Run tests
```bash
python -m unittest discover -s tests -v
```

## Layout
- `admin_lab.py` — local-only simulator.
- `backdoor.py` — compatibility launcher for the safe simulator; no backdoor functionality remains.
- `tests/` — unit tests.
- `SECURITY.md` — intended-use policy and safety boundaries.
- `config.example.ini` — non-secret example settings.

## Roadmap
1. Structured append-only local audit export with integrity verification.
2. Scenario-based defensive exercises and rubric-based assessment.
3. Threat-model documentation and dependency/security scanning.
4. For real remote administration, integrate a mature authenticated platform such as OpenSSH rather than inventing a covert remote-control protocol.

## License
No license is currently declared. All rights remain with the repository owner unless a license is added.
