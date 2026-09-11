from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .guardian import Guardian, file_sha256
from .models import Capability, Session, TrustState


class CapabilityDenied(PermissionError):
    pass


_STATE_CAPABILITIES = {
    TrustState.TRUSTED: frozenset(Capability),
    TrustState.RESTRICTED: frozenset({Capability.READ}),
    TrustState.QUARANTINED: frozenset({Capability.READ}),
    TrustState.TERMINATED: frozenset(),
}


class CapabilityBroker:
    """The sole privileged interface exposed to an agent sandbox."""

    def __init__(self, guardian: Guardian):
        self.guardian = guardian

    def _session(self, session_id: str) -> Session:
        session = self.guardian.sessions.get(session_id)
        if session is None:
            raise CapabilityDenied("unknown session")
        self.guardian.inspect(session_id)
        return session

    def _authorize(self, session: Session, capability: Capability, path: Path | None = None) -> Path | None:
        allowed = capability in session.manifest.capabilities and capability in _STATE_CAPABILITIES[session.state]
        if not allowed:
            self._deny(session, capability, "capability_revoked")
        if path is None:
            return None
        try:
            resolved = path.resolve(strict=capability == Capability.READ)
        except (FileNotFoundError, RuntimeError):
            self._deny(session, capability, "invalid_path")
        if not resolved.is_relative_to(session.manifest.workspace):
            self.guardian.report_violation(session.session_id, "geofence_breach", TrustState.QUARANTINED)
            self._deny(session, capability, "path_outside_workspace")
        return resolved

    def _deny(self, session: Session, capability: Capability, reason: str) -> None:
        self.guardian.ledger.append(
            "CAPABILITY_DENIED", agent=session.manifest.agent_id, session=session.session_id,
            capability=capability.value, state=session.state.name, reason=reason,
        )
        raise CapabilityDenied(reason)

    def read(self, session_id: str, path: Path, max_bytes: int = 1024 * 1024) -> bytes:
        session = self._session(session_id)
        resolved = self._authorize(session, Capability.READ, path)
        assert resolved is not None
        fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            data = os.read(fd, max_bytes + 1)
        finally:
            os.close(fd)
        if len(data) > max_bytes:
            self._deny(session, Capability.READ, "read_limit_exceeded")
        return data

    def write(self, session_id: str, path: Path, data: bytes, max_bytes: int = 1024 * 1024) -> None:
        session = self._session(session_id)
        if len(data) > max_bytes:
            self._deny(session, Capability.WRITE, "write_limit_exceeded")
        resolved = self._authorize(session, Capability.WRITE, path)
        assert resolved is not None
        resolved.parent.mkdir(parents=True, exist_ok=True)
        # Atomic replacement prevents readers from observing a partial write.
        temporary = resolved.with_name(f".{resolved.name}.{os.getpid()}.tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, resolved)

    def execute(self, session_id: str, name: str, args: list[str], timeout: float = 30.0) -> subprocess.CompletedProcess[bytes]:
        session = self._session(session_id)
        self._authorize(session, Capability.EXECUTE)
        expected_hash = session.manifest.allowed_executables.get(name)
        if expected_hash is None:
            self.guardian.report_violation(session_id, "unauthorized_executable", TrustState.QUARANTINED)
            self._deny(session, Capability.EXECUTE, "executable_not_allowlisted")
        executable = Path(name)
        if not executable.is_absolute() or file_sha256(executable) != expected_hash:
            self.guardian.report_violation(session_id, "executable_identity_mismatch", TrustState.QUARANTINED)
            self._deny(session, Capability.EXECUTE, "executable_hash_mismatch")
        return subprocess.run(
            [str(executable), *args], cwd=session.manifest.workspace, env={"PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False, close_fds=True,
        )
