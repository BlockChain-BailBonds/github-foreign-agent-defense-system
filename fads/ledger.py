from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from .crypto import canonical_json, sha256_bytes, sign, verify


class LedgerError(RuntimeError):
    pass


class EvidenceLedger:
    """Append-only, hash-chained, optionally HMAC-authenticated JSONL ledger."""

    def __init__(self, path: Path, key: bytes):
        if len(key) < 32:
            raise ValueError("ledger key must contain at least 32 bytes")
        self.path = path
        self.key = key
        self._lock = Lock()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)

    def _records(self) -> list[dict[str, Any]]:
        with self.path.open("r", encoding="utf-8") as stream:
            return [json.loads(line) for line in stream if line.strip()]

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            records = self._records()
            previous = records[-1]["record_hash"] if records else "0" * 64
            body = {
                "sequence": len(records),
                "time": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "previous_hash": previous,
                **fields,
            }
            record_hash = sha256_bytes(canonical_json(body))
            record = {**body, "record_hash": record_hash, "hmac": sign(self.key, {**body, "record_hash": record_hash})}
            fd = os.open(self.path, os.O_APPEND | os.O_WRONLY)
            try:
                os.write(fd, canonical_json(record) + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            return record

    def verify(self) -> int:
        previous = "0" * 64
        for expected_sequence, record in enumerate(self._records()):
            supplied_hmac = record.pop("hmac", None)
            supplied_hash = record.pop("record_hash", None)
            if record.get("sequence") != expected_sequence or record.get("previous_hash") != previous:
                raise LedgerError(f"broken chain at sequence {expected_sequence}")
            calculated_hash = sha256_bytes(canonical_json(record))
            signed = {**record, "record_hash": supplied_hash}
            if supplied_hash != calculated_hash or not isinstance(supplied_hmac, str) or not verify(self.key, signed, supplied_hmac):
                raise LedgerError(f"tampered record at sequence {expected_sequence}")
            previous = supplied_hash
        return expected_sequence + 1 if 'expected_sequence' in locals() else 0
