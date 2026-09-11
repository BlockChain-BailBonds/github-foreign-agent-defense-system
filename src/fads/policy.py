from __future__ import annotations

from typing import Any

from .types import TrustState


CAPABILITIES = {
    "read_workspace",
    "write_project",
    "execute",
    "spawn_process",
    "network",
    "credentials",
    "external_tools",
}


class PolicyEngine:
    def __init__(self, policy: dict[str, Any], manifest: dict[str, Any]):
        self.policy = policy
        self.manifest = manifest

    def capability_allowed(self, state: TrustState, capability: str) -> bool:
        if capability not in CAPABILITIES:
            return False
        ceiling = self.manifest.get("allowed", {}).get(capability, False)
        state_rule = self.policy.get("states", {}).get(state.policy_key, {}).get(capability, False)
        return ceiling is True and state_rule is True

    def response_state(self, event: str, current: TrustState) -> TrustState:
        target_name = self.policy.get("responses", {}).get(event)
        if not target_name:
            return current
        target = TrustState.parse(target_name)
        return max(current, target)

    def transition(self, event: str, current: TrustState) -> tuple[TrustState, bool]:
        new = self.response_state(event, current)
        return new, new != current
