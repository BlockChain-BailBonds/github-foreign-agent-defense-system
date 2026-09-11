from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any


class TrustState(IntEnum):
    TRUSTED = 0
    RESTRICTED = 1
    QUARANTINED = 2
    TERMINATED = 3

    @classmethod
    def parse(cls, value: str | "TrustState") -> "TrustState":
        if isinstance(value, cls):
            return value
        return cls[value.strip().upper()]

    @property
    def policy_key(self) -> str:
        return self.name.lower()


@dataclass(slots=True)
class Session:
    agent_id: str
    session_id: str
    manifest_path: Path
    manifest_sha256: str
    policy_path: Path
    policy_sha256: str
    workspace: Path
    scratch: Path
    runtime_dir: Path
    broker_socket: Path
    heartbeat_seconds: float
    state: TrustState = TrustState.TRUSTED
    unit_name: str | None = None
    main_pid: int | None = None
    last_heartbeat_monotonic: float = 0.0
    last_counter: int = -1
    metadata: dict[str, Any] = field(default_factory=dict)
