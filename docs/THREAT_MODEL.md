# FADS Threat Model

FADS is a host-side containment and capability-revocation system for AI agents and other untrusted automated processes.

## Trusted computing base

FADS assumes the following remain trusted: the Linux kernel, the root/Guardian administrative boundary, the FADS Guardian process and installed package, policy and manifest before launch, and the systemd/bubblewrap/cgroup enforcement stack.

A compromised kernel, hostile root administrator, or compromised Guardian administrator is outside the FADS protection boundary. FADS does not claim to defend the host from its own trusted computing base.

## Agent threat model

An agent may be buggy, prompt-injected, malicious, or compromised after launch. FADS does not accept the agent's self-reported identity, location, process ownership, or authorization as authoritative.

The Guardian verifies executable and optional model/artifact hashes before launch. Each launch receives a new random session identifier. Broker clients are authenticated first through Linux `SO_PEERCRED` and session-cgroup membership, then through the session identifier and monotonic heartbeat counter.

## Hard boundary

A user-test session uses a systemd transient service and cgroup v2 controls, bubblewrap namespaces, a minimal mounted filesystem, a read-only project workspace, a dedicated scratch directory, a private network namespace, an empty capability set, `NoNewPrivileges`, systemd seccomp-backed syscall filtering, and a Unix-domain capability broker owned by the configured agent UID.

There is no policy-only fallback in `fads run`. Missing hard-containment prerequisites cause launch refusal.

## Incident monotonicity

Within one session trust only moves toward less authority:

`TRUSTED -> RESTRICTED -> QUARANTINED -> TERMINATED`

A healthy heartbeat never promotes an incident session. Recovery requires a new Guardian launch and a new verified session.

## Evidence

Guardian events are appended to a SHA-256 hash chain with a separate head record. If `FADS_LEDGER_HMAC_KEY` is supplied, the head is HMAC-authenticated. This detects event mutation and end-of-log truncation relative to the stored signed head.
