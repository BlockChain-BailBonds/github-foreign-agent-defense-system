from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path
from time import monotonic
from typing import Any

from .crypto import verify
from .ledger import EvidenceLedger
from .models import Manifest, Session, TrustState


class GuardianError(RuntimeError):
    pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class Guardian:
    def __init__(self, ledger: EvidenceLedger):
        self.ledger = ledger
        self.sessions: dict[str, Session] = {}

    def create_session(self, manifest: Manifest, pid: int, executable: Path) -> Session:
        process_root = Path(f"/proc/{pid}")
        if pid <= 0 or not process_root.exists():
            raise GuardianError("agent PID does not exist")
        observed_executable = (process_root / "exe").resolve(strict=True)
        if executable.resolve(strict=True) != observed_executable:
            raise GuardianError("claimed executable does not match operating-system observation")
        if file_sha256(observed_executable) != manifest.executable_sha256:
            raise GuardianError("agent executable identity mismatch")
        session = Session(secrets.token_hex(32), manifest, pid, observed_executable, secrets.token_bytes(32))
        self.sessions[session.session_id] = session
        self.ledger.append("SESSION_CREATED", agent=manifest.agent_id, session=session.session_id, pid=pid)
        return session

    def heartbeat(self, session_id: str, payload: dict[str, Any], signature: str) -> bool:
        session = self.sessions.get(session_id)
        if session is None or session.state == TrustState.TERMINATED:
            return False
        expected_keys = {"session", "counter", "task"}
        if set(payload) != expected_keys or payload["session"] != session_id:
            self._degrade(session, TrustState.QUARANTINED, "malformed_heartbeat")
            return False
        counter = payload["counter"]
        if not isinstance(counter, int) or counter <= session.last_counter:
            self._degrade(session, TrustState.QUARANTINED, "heartbeat_replay")
            return False
        if not verify(session.secret, payload, signature):
            self._degrade(session, TrustState.QUARANTINED, "heartbeat_authentication_failed")
            return False
        session.last_counter = counter
        session.last_heartbeat = monotonic()
        return True

    def inspect(self, session_id: str, now: float | None = None) -> TrustState:
        session = self.sessions[session_id]
        if session.state == TrustState.TERMINATED:
            return session.state
        if not Path(f"/proc/{session.pid}").exists():
            self._degrade(session, TrustState.TERMINATED, "agent_process_missing")
            return session.state
        try:
            observed_executable = Path(f"/proc/{session.pid}/exe").resolve(strict=True)
            identity_ok = observed_executable == session.executable and file_sha256(observed_executable) == session.manifest.executable_sha256
        except (FileNotFoundError, PermissionError):
            identity_ok = False
        if not identity_ok:
            self._degrade(session, TrustState.QUARANTINED, "runtime_identity_mismatch")
            return session.state
        elapsed = (monotonic() if now is None else now) - session.last_heartbeat
        limit = session.manifest.heartbeat_seconds * session.manifest.max_missed_heartbeats
        if elapsed > limit:
            self._degrade(session, TrustState.RESTRICTED, "heartbeat_timeout")
        return session.state

    def report_violation(self, session_id: str, reason: str, severity: TrustState) -> None:
        if severity == TrustState.TRUSTED:
            raise ValueError("a violation cannot increase trust")
        self._degrade(self.sessions[session_id], severity, reason)

    def terminate(self, session_id: str, reason: str = "operator_termination") -> None:
        self._degrade(self.sessions[session_id], TrustState.TERMINATED, reason)

    def _degrade(self, session: Session, target: TrustState, reason: str) -> None:
        previous = session.state
        if session.degrade(target, reason):
            self.ledger.append(
                "STATE_TRANSITION", agent=session.manifest.agent_id, session=session.session_id,
                previous_state=previous.name, new_state=target.name, reason=reason,
            )
