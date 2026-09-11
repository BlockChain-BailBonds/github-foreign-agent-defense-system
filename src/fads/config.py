from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .util import sha256_file


class ConfigError(ValueError):
    pass


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text("utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping")
    return data


def load_manifest(path: str | Path) -> tuple[dict[str, Any], str, Path]:
    p = Path(path).resolve()
    m = _load_yaml(p)
    if m.get("version") != 1:
        raise ConfigError("manifest version must be 1")
    agent_id = m.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in agent_id):
        raise ConfigError("invalid agent_id")
    ident = m.get("identity")
    if not isinstance(ident, dict) or not ident.get("executable") or not ident.get("executable_sha256"):
        raise ConfigError("manifest identity.executable and executable_sha256 are required")
    if not isinstance(m.get("sandbox"), dict) or not m["sandbox"].get("workspace"):
        raise ConfigError("manifest sandbox.workspace is required")
    if not isinstance(m.get("allowed"), dict):
        raise ConfigError("manifest allowed mapping is required")
    if not isinstance(m.get("allowed_executables", []), list):
        raise ConfigError("manifest allowed_executables must be a list")
    hb = m.get("heartbeat_seconds", 2)
    if not isinstance(hb, (int, float)) or hb <= 0:
        raise ConfigError("heartbeat_seconds must be positive")
    return m, sha256_file(p), p


def load_policy(path: str | Path) -> tuple[dict[str, Any], str, Path]:
    p = Path(path).resolve()
    policy = _load_yaml(p)
    if policy.get("version") != 1:
        raise ConfigError("policy version must be 1")
    states = policy.get("states")
    if not isinstance(states, dict):
        raise ConfigError("policy states mapping is required")
    for required in ("trusted", "restricted", "quarantined", "terminated"):
        if required not in states:
            raise ConfigError(f"policy state missing: {required}")
    return policy, sha256_file(p), p
