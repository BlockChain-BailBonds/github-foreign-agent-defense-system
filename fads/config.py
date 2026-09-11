from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Capability, Manifest

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def load_manifest(path: Path) -> Manifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {"agent_id", "identity", "sandbox", "capabilities", "allowed_executables", "heartbeat_seconds", "max_missed_heartbeats"}
    if set(data) != required:
        raise ValueError(f"manifest keys must be exactly {sorted(required)}")
    agent_id = data["agent_id"]
    if not isinstance(agent_id, str) or not _ID.fullmatch(agent_id):
        raise ValueError("invalid agent_id")
    executable_hash = data["identity"]["executable_sha256"]
    if not _SHA256.fullmatch(executable_hash):
        raise ValueError("invalid executable SHA-256")
    root = Path(data["sandbox"]["root"]).resolve(strict=True)
    workspace = Path(data["sandbox"]["workspace"]).resolve(strict=True)
    if not workspace.is_relative_to(root):
        raise ValueError("workspace escapes sandbox root")
    capabilities = frozenset(Capability(item) for item in data["capabilities"])
    executables = data["allowed_executables"]
    if not executables or any(not _SHA256.fullmatch(value) for value in executables.values()):
        raise ValueError("every executable requires a SHA-256 allowlist entry")
    return Manifest(
        agent_id=agent_id,
        executable_sha256=executable_hash,
        root=root,
        workspace=workspace,
        capabilities=capabilities,
        allowed_executables=executables,
        heartbeat_seconds=float(data["heartbeat_seconds"]),
        max_missed_heartbeats=int(data["max_missed_heartbeats"]),
    )
