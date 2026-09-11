from __future__ import annotations

from fads.crypto import sign
from fads.models import TrustState


def test_authenticated_heartbeat(system):
    guardian, _, session, _, _ = system
    payload = {"session": session.session_id, "counter": 0, "task": "test"}
    assert guardian.heartbeat(session.session_id, payload, sign(session.secret, payload))
    assert session.state == TrustState.TRUSTED


def test_bad_signature_quarantines(system):
    guardian, _, session, _, _ = system
    payload = {"session": session.session_id, "counter": 0, "task": "test"}
    assert not guardian.heartbeat(session.session_id, payload, "0" * 64)
    assert session.state == TrustState.QUARANTINED


def test_replay_quarantines(system):
    guardian, _, session, _, _ = system
    payload = {"session": session.session_id, "counter": 7, "task": "test"}
    signature = sign(session.secret, payload)
    assert guardian.heartbeat(session.session_id, payload, signature)
    assert not guardian.heartbeat(session.session_id, payload, signature)
    assert session.state == TrustState.QUARANTINED


def test_timeout_restricts(system):
    guardian, _, session, _, _ = system
    guardian.inspect(session.session_id, now=session.last_heartbeat + 7)
    assert session.state == TrustState.RESTRICTED


def test_trust_cannot_self_recover(system):
    guardian, _, session, _, _ = system
    guardian.report_violation(session.session_id, "test", TrustState.QUARANTINED)
    assert not session.degrade(TrustState.TRUSTED, "forged_recovery")
    assert session.state == TrustState.QUARANTINED


def test_termination_is_terminal(system):
    guardian, _, session, _, _ = system
    guardian.terminate(session.session_id)
    payload = {"session": session.session_id, "counter": 1, "task": "resume"}
    assert not guardian.heartbeat(session.session_id, payload, sign(session.secret, payload))
    assert session.state == TrustState.TERMINATED
