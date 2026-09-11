from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import Path
from time import monotonic


class TrustState(IntEnum):
    TRUSTED = 0
    RESTRICTED = 1
    QUARANTINED = 2
    TERMINATED = 3


class Capability(StrEnum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    SPAWN = "spawn"
    NETWORK = "network"
    SECRETS = "secrets"


@dataclass(frozen=True)
class Manifest:
    agent_id: str
    executable_sha256: str
    root: Path
    workspace: Path
    capabilities: frozenset[Capability]
    allowed_executables: dict[str, str]
    heartbeat_seconds: float = 2.0
    max_missed_heartbeats: int = 3


@dataclass
class Session:
    session_id: str
    manifest: Manifest
    pid: int
    executable: Path
    secret: bytes
    state: TrustState = TrustState.TRUSTED
    last_counter: int = -1
    last_heartbeat: float = field(default_factory=monotonic)
    reason: str = "session_created"

    def degrade(self, target: TrustState, reason: str) -> bool:
        """Apply only equal or more restrictive states; trust never self-recovers."""
        if target <= self.state:
            return False
        self.state = target
        self.reason = reason
        return True
