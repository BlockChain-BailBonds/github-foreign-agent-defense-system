from __future__ import annotations

import sys
from pathlib import Path

import pytest

from fads.broker import CapabilityDenied
from fads.models import TrustState


def test_read_and_atomic_write(system):
    _, broker, session, workspace, _ = system
    target = workspace / "result.txt"
    broker.write(session.session_id, target, b"verified")
    assert broker.read(session.session_id, target) == b"verified"


def test_geofence_escape_quarantines(system, tmp_path: Path):
    _, broker, session, _, _ = system
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    with pytest.raises(CapabilityDenied, match="path_outside_workspace"):
        broker.read(session.session_id, outside)
    assert session.state == TrustState.QUARANTINED


def test_symlink_escape_quarantines(system, tmp_path: Path):
    _, broker, session, workspace, _ = system
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (workspace / "link").symlink_to(outside)
    with pytest.raises(CapabilityDenied):
        broker.read(session.session_id, workspace / "link")
    assert session.state == TrustState.QUARANTINED


def test_restricted_session_cannot_write(system):
    guardian, broker, session, workspace, _ = system
    guardian.report_violation(session.session_id, "unknown_child", TrustState.RESTRICTED)
    with pytest.raises(CapabilityDenied, match="capability_revoked"):
        broker.write(session.session_id, workspace / "denied", b"no")


def test_quarantined_session_can_only_read(system):
    guardian, broker, session, workspace, _ = system
    target = workspace / "evidence.txt"
    target.write_text("preserved")
    guardian.report_violation(session.session_id, "identity_mismatch", TrustState.QUARANTINED)
    assert broker.read(session.session_id, target) == b"preserved"
    with pytest.raises(CapabilityDenied):
        broker.execute(session.session_id, str(Path(sys.executable).resolve()), ["-V"])


def test_allowlisted_hash_checked_before_execute(system):
    _, broker, session, _, _ = system
    executable = str(Path(sys.executable).resolve())
    result = broker.execute(session.session_id, executable, ["-c", "print('ok')"])
    assert result.returncode == 0
    assert result.stdout == b"ok\n"


def test_unknown_executable_quarantines(system):
    _, broker, session, _, _ = system
    with pytest.raises(CapabilityDenied, match="executable_not_allowlisted"):
        broker.execute(session.session_id, "/bin/false", [])
    assert session.state == TrustState.QUARANTINED


def test_unknown_session_fails_closed(system):
    _, broker, _, workspace, _ = system
    with pytest.raises(CapabilityDenied, match="unknown session"):
        broker.read("fabricated", workspace / "anything")
