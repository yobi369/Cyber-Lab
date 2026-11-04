"""Append-only, hash-chained audit events for local training.

Detects edits, deletion, reordering, and partial corruption. It is tamper-evident,
not tamper-proof: a full rewrite can rebuild an unanchored chain. Production
systems need signed checkpoints anchored outside the host.
"""
from __future__ import annotations
import hashlib, json, os, threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

GENESIS = "0" * 64

def canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

class AuditChain:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._events = self._read() if self.path and self.path.exists() else []

    def _read(self):
        assert self.path is not None
        events = []
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            try: events.append(json.loads(line))
            except json.JSONDecodeError as exc: raise ValueError(f"invalid audit JSON at line {number}") from exc
        return events

    @property
    def head(self):
        return self._events[-1]["event_hash"] if self._events else GENESIS

    def append(self, actor: str, role: str, action: str, details: dict[str, Any] | None = None):
        with self._lock:
            event = {"sequence": len(self._events)+1, "timestamp": datetime.now(timezone.utc).isoformat(),
                     "actor": actor, "role": role, "action": action, "details": details or {},
                     "previous_hash": self.head}
            event["event_hash"] = hashlib.sha256(canonical(event)).hexdigest()
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event, sort_keys=True, ensure_ascii=False)+"\n")
                    stream.flush(); os.fsync(stream.fileno())
            self._events.append(event)
            return dict(event)

    def verify(self):
        previous = GENESIS
        for sequence, event in enumerate(self._events, 1):
            supplied = event.get("event_hash")
            payload = {key:value for key,value in event.items() if key != "event_hash"}
            calculated = hashlib.sha256(canonical(payload)).hexdigest()
            if event.get("sequence") != sequence: return {"valid":False,"at_sequence":sequence,"reason":"sequence_mismatch"}
            if event.get("previous_hash") != previous: return {"valid":False,"at_sequence":sequence,"reason":"previous_hash_mismatch"}
            if supplied != calculated: return {"valid":False,"at_sequence":sequence,"reason":"event_hash_mismatch"}
            previous = supplied
        return {"valid":True,"events":len(self._events),"head":previous}

    def export(self):
        return [dict(event) for event in self._events]
