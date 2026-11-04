"""Safe, local-only remote-administration training simulator.

This module deliberately performs no networking, shell execution, persistence,
or real file transfer. It models an authenticated administrative session using
in-memory state so learners can practice command validation and audit concepts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import argparse
import hmac
import os
from typing import Callable


@dataclass
class AuditEvent:
    timestamp: str
    actor: str
    action: str
    outcome: str


@dataclass
class AdminLab:
    """In-memory training session with a deliberately narrow command set."""

    expected_token: str
    actor: str = "trainee"
    authenticated: bool = False
    inventory: tuple[str, ...] = ("demo-host-01", "demo-host-02")
    audit_log: list[AuditEvent] = field(default_factory=list)

    def _audit(self, action: str, outcome: str) -> None:
        self.audit_log.append(AuditEvent(
            datetime.now(timezone.utc).isoformat(), self.actor, action, outcome
        ))

    def authenticate(self, supplied_token: str) -> bool:
        # Compare in constant time; real deployments should use an identity
        # provider and short-lived credentials, not a shared static token.
        self.authenticated = bool(self.expected_token) and hmac.compare_digest(
            supplied_token.encode(), self.expected_token.encode()
        )
        self._audit("authenticate", "success" if self.authenticated else "denied")
        return self.authenticated

    def execute(self, command: str) -> str:
        """Run a simulated command; never invokes an operating-system shell."""
        if not self.authenticated:
            self._audit("command", "denied:not-authenticated")
            return "Access denied: authenticate first."

        handlers: dict[str, Callable[[], str]] = {
            "help": lambda: "Commands: help, status, inventory, exit",
            "status": lambda: "Training session active (simulation only).",
            "inventory": lambda: ", ".join(self.inventory),
            "exit": lambda: "Training session ended.",
        }
        action = command.strip().lower()
        handler = handlers.get(action)
        if handler is None:
            self._audit(action or "empty-command", "denied:not-allowlisted")
            return "Command rejected: not in the training allowlist."
        result = handler()
        self._audit(action, "success")
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Local-only authorized admin lab simulator")
    parser.add_argument("--token", default=os.getenv("ADMIN_LAB_TOKEN", ""),
                        help="training token (or set ADMIN_LAB_TOKEN)")
    args = parser.parse_args()
    if not args.token:
        parser.error("provide --token or ADMIN_LAB_TOKEN; no default credential is configured")
    lab = AdminLab(expected_token=args.token)
    supplied = input("Training token: ")
    if not lab.authenticate(supplied):
        print("Authentication denied.")
        return 1
    print("Authenticated local training session. Type help.")
    while True:
        command = input("lab> ")
        print(lab.execute(command))
        if command.strip().lower() == "exit":
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
