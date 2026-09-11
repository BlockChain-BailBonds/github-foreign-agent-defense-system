from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sign(secret: bytes, value: Any) -> str:
    return hmac.new(secret, canonical_json(value), hashlib.sha256).hexdigest()


def verify(secret: bytes, value: Any, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, value), signature)
