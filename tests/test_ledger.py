import json, pytest
from pathlib import Path
from fads.ledger import EvidenceLedger, LedgerError

def test_hash_chain_and_signed_head(tmp_path: Path):
    l=EvidenceLedger(tmp_path/'evidence',b'test-key'); l.append({'event':'ONE'}); l.append({'event':'TWO'}); assert l.verify()['records']==2

def test_event_tamper_detected(tmp_path: Path):
    l=EvidenceLedger(tmp_path/'evidence'); l.append({'event':'ONE'}); p=tmp_path/'evidence'/'events.jsonl'; r=json.loads(p.read_text()); r['event']='ALTERED'; p.write_text(json.dumps(r)+'\n')
    with pytest.raises(LedgerError): l.verify()

def test_truncation_detected(tmp_path: Path):
    l=EvidenceLedger(tmp_path/'evidence'); l.append({'event':'ONE'}); l.append({'event':'TWO'}); p=tmp_path/'evidence'/'events.jsonl'; p.write_text(p.read_text().splitlines()[0]+'\n')
    with pytest.raises(LedgerError): l.verify()
