from __future__ import annotations

import json

import pytest

from fads.ledger import LedgerError


def test_ledger_chain_verifies(system):
    _, _, _, _, ledger = system
    ledger.append("TEST_EVENT", value=1)
    assert ledger.verify() == 2


def test_ledger_tampering_detected(system):
    _, _, _, _, ledger = system
    ledger.append("TEST_EVENT", value=1)
    lines = ledger.path.read_text().splitlines()
    record = json.loads(lines[0])
    record["pid"] = 999999
    lines[0] = json.dumps(record)
    ledger.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(LedgerError, match="tampered record"):
        ledger.verify()
