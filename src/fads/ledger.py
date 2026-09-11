from __future__ import annotations
import hashlib, hmac, json, os, threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .util import ensure_private_dir, stable_json

ZERO_HASH = '0' * 64
class LedgerError(RuntimeError): pass

class EvidenceLedger:
    def __init__(self, directory: str | Path, signing_key: bytes | None = None):
        self.directory = Path(directory).resolve(); ensure_private_dir(self.directory)
        self.events_path = self.directory / 'events.jsonl'; self.head_path = self.directory / 'head.json'
        self.signing_key = signing_key; self._lock = threading.Lock(); self._seq, self._last_hash = self._load_head()
    def _sign(self, seq: int, digest: str) -> str | None:
        return None if not self.signing_key else hmac.new(self.signing_key, f'{seq}:{digest}'.encode(), hashlib.sha256).hexdigest()
    def _load_head(self):
        if not self.head_path.exists():
            if self.events_path.exists() and self.events_path.stat().st_size:
                v = self.verify(); return v['records'], v['last_hash']
            return 0, ZERO_HASH
        head = json.loads(self.head_path.read_text('utf-8')); seq = int(head['sequence']); digest = str(head['hash']); sig = head.get('signature')
        if sig and not self.signing_key: raise LedgerError('ledger head is signed but FADS ledger key is unavailable')
        expected = self._sign(seq, digest)
        if expected and not hmac.compare_digest(str(sig or ''), expected): raise LedgerError('ledger head signature mismatch')
        return seq, digest
    def _write_head(self):
        payload = {'sequence': self._seq, 'hash': self._last_hash, 'signature': self._sign(self._seq, self._last_hash)}
        tmp = self.head_path.with_suffix('.tmp')
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(payload, f, sort_keys=True, separators=(',', ':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, self.head_path)
    def append(self, event: dict[str, Any]):
        with self._lock:
            sequence = self._seq + 1
            core = {'sequence': sequence, 'time': datetime.now(timezone.utc).isoformat().replace('+00:00','Z'), 'previous_hash': self._last_hash, **event}
            digest = hashlib.sha256((self._last_hash + stable_json(core)).encode()).hexdigest(); record = {**core, 'hash': digest}
            with open(self.events_path, 'a', encoding='utf-8') as f:
                f.write(stable_json(record) + '\n'); f.flush(); os.fsync(f.fileno())
            self._seq, self._last_hash = sequence, digest; self._write_head(); return record
    def verify(self):
        previous, count = ZERO_HASH, 0
        if self.events_path.exists():
            for raw in self.events_path.read_text('utf-8').splitlines():
                if not raw.strip(): continue
                count += 1; record = json.loads(raw)
                if record.get('sequence') != count or record.get('previous_hash') != previous: raise LedgerError(f'ledger chain broken at record {count}')
                claimed = record.get('hash'); core = dict(record); core.pop('hash', None)
                expected = hashlib.sha256((previous + stable_json(core)).encode()).hexdigest()
                if claimed != expected: raise LedgerError(f'ledger hash mismatch at record {count}')
                previous = expected
        if self.head_path.exists():
            head = json.loads(self.head_path.read_text('utf-8'))
            if int(head.get('sequence', -1)) != count or head.get('hash') != previous: raise LedgerError('ledger head does not match event chain; truncation or replacement detected')
            sig = head.get('signature')
            if sig and not self.signing_key: raise LedgerError('ledger head is signed but FADS ledger key is unavailable')
            expected = self._sign(count, previous)
            if expected and not hmac.compare_digest(str(sig or ''), expected): raise LedgerError('ledger head signature mismatch')
        return {'valid': True, 'records': count, 'last_hash': previous}
