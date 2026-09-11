from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from fads.broker import CapabilityBroker
from fads.guardian import Guardian, file_sha256
from fads.ledger import EvidenceLedger
from fads.models import Capability, Manifest


@pytest.fixture
def system(tmp_path: Path):
    root = tmp_path / "agent"
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    executable = Path(sys.executable).resolve()
    manifest = Manifest(
        agent_id="agent-test",
        executable_sha256=file_sha256(executable),
        root=root.resolve(),
        workspace=workspace.resolve(),
        capabilities=frozenset(Capability),
        allowed_executables={str(executable): file_sha256(executable)},
        heartbeat_seconds=2,
        max_missed_heartbeats=3,
    )
    ledger = EvidenceLedger(tmp_path / "evidence" / "events.jsonl", b"L" * 32)
    guardian = Guardian(ledger)
    session = guardian.create_session(manifest, os.getpid(), executable)
    return guardian, CapabilityBroker(guardian), session, workspace, ledger
