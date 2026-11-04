# Security policy and scope

## Intended use
This repository is an educational, local-only simulation for learning about
authentication, command allowlists, and audit events. Use it only in systems
and environments you own or are explicitly authorized to assess.

## Deliberate safety boundaries
- No reverse shell, listener, callback, socket, or remote-control channel.
- No arbitrary command execution or subprocess invocation.
- No persistence, stealth, evasion, credential collection, or privilege escalation.
- No real file upload/download; the inventory and session are in-memory examples.
- Unknown commands are rejected and recorded.

The historical `backdoor.py` filename is retained only as a compatibility
entry point. It launches the safe simulator and does not implement a backdoor.

## Reporting
Please report suspected vulnerabilities privately to the repository owner.
Do not include live credentials, private keys, or sensitive personal data in
issues or pull requests.
