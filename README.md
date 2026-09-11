# GitHub Foreign Agent Defense System

A fail-closed reference implementation for controlling AI agents through an external Guardian, an operating-system sandbox, and a capability broker.

> [!IMPORTANT]
> “Military grade” is not a technical certification. FADS aims for explicit,
> testable controls: deny by default, least privilege, independent OS identity
> checks, monotonic trust degradation, authenticated sessions, and tamper-evident
> evidence. It requires an OS sandbox to provide a real security boundary.

## Implemented Controls

- 256-bit random session identifiers and per-session HMAC keys
- authenticated heartbeat counters with replay rejection
- independent `/proc/<pid>/exe` identity and SHA-256 verification
- one-way state degradation until a new session is created
- broker-enforced read, atomic write, and allowlisted execution
- canonical-path geofencing and symlink escape rejection
- bounded I/O, execution timeouts, minimal child environments, and closed file descriptors
- fsync'd SHA-256/HMAC hash-chained JSONL evidence
- strict manifest loading and fail-closed validation
- negative security tests and credential scanning in CI

## Quick Verification

```bash
python -m pip install -e . pytest
python -m pytest -q

export FADS_LEDGER_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m fads verify-ledger evidence/events.jsonl
```

Never commit ledger keys, session keys, credentials, or production manifests.

## Core Rule

```text
NO VERIFIED SESSION
+ NO VALID LOCATION
+ NO CURRENT AUTHORIZATION
= NO CAPABILITY
```

The agent never decides whether it is trusted. A separate Guardian makes that decision.

## Minimal Architecture

```text
Guardian outside the boundary
Agent inside the boundary
Broker as the only capability path
Evidence ledger as the memory of truth
```

Only three components are required:

| Component | Job |
| --- | --- |
| Guardian | Determines who the agent is, where it is, and whether it remains trusted |
| Sandbox | Prevents the agent from bypassing the Guardian |
| Capability Broker | Controls what the agent can actually do |

The Guardian may contain the foreign-agent detector, beacon verifier, geofence monitor, policy engine, response engine, and logging system in one service.

## Capability Equation

```text
CAPABILITY =
IDENTITY
x SESSION
x LOCATION
x POLICY
x CURRENT_TRUST
```

If any required component becomes zero, capability becomes zero.

## Runtime States

Keep the state machine small and deterministic:

```text
TRUSTED -> RESTRICTED -> QUARANTINED -> TERMINATED
```

| Capability | Trusted | Restricted | Quarantined |
| --- | --- | --- | --- |
| Read workspace | yes | yes | yes |
| Write project | yes | no | no |
| Execute | yes | limited | no |
| Spawn process | yes | no | no |
| Network | policy | no | no |
| Credentials | policy | no | no |
| External tools | policy | no | no |
| Audit/evidence | always | always | always |

## Enforcement Stack

The Guardian remains outside the agent boundary. The agent boundary should include:

```text
container / namespaces
+ cgroups
+ read-only host mounts
+ network namespace
+ seccomp
+ Unix-domain broker socket
```

The agent must not have a second path around the broker. If the agent receives unrestricted host shell access, unrestricted network sockets, raw credentials, or host filesystem permissions, revocation is not real.

## Security Invariants

1. Missing, malformed, stale, replayed, or unauthenticated input is denied.
2. A running session can only retain or lose trust; it cannot regain trust.
3. Every broker decision uses the Guardian's current state at operation time.
4. The OS observation wins when an agent claim conflicts with `/proc`.
5. Paths are resolved and checked against the workspace before use.
6. Executable names alone are insufficient; an absolute path and SHA-256 must match.
7. Every denial and state transition is recorded in the evidence ledger.
8. Recovery creates a new session with new cryptographic material.

## Threat Boundary

The reference code handles policy decisions and brokered operations. A production
deployment must additionally enforce namespaces, cgroups, seccomp, read-only
mounts, dedicated UIDs, network egress denial, key isolation, and broker socket
ownership outside the agent. Python code cannot defend against a compromised host
kernel, Guardian administrator, firmware, or physical platform by itself.

## Guardian Loop

```text
for session in active_agents:
    identity_ok = verify_identity(session)
    heartbeat_ok = verify_heartbeat(session)
    location_ok = verify_geofence(session)
    processes_ok = verify_process_tree(session)
    policy_ok = verify_policy_integrity(session)

    if not policy_ok:
        terminate(session)
    elif not identity_ok:
        quarantine(session)
    elif not location_ok:
        quarantine(session)
    elif not processes_ok:
        restrict(session)
    elif not heartbeat_ok:
        restrict(session)
    else:
        trust(session)

    capability_broker.set_state(session.agent_id, session.state)
    audit(session)
```

## Detection Rules

| Event | Response |
| --- | --- |
| Valid heartbeat | Continue |
| Several missed heartbeats | Restricted |
| Agent exits geofence | Quarantine |
| Unknown child process | Restricted |
| Unauthorized executable | Quarantine |
| Identity/hash mismatch | Quarantine |
| Unauthorized network request | Deny + Restricted |
| Attempt to alter Guardian | Terminate |
| Attempt to alter policy | Quarantine |
| Session replay | Quarantine |
| Valid agent restart | New session |

## Evidence Ledger

Every meaningful event becomes an append-only, hash-chained record:

```json
{
  "time": "2026-09-11T18:40:21Z",
  "agent": "agent-0042",
  "session": "a8916c",
  "pid": 4821,
  "event": "GEOFENCE_BREACH",
  "previous_state": "TRUSTED",
  "new_state": "QUARANTINED",
  "path": "/etc",
  "action": "CAPABILITIES_REVOKED"
}
```

## Recommended Filesystem

```text
/fads/
  guardian/
    guardian
    policy.yaml
    manifests/
  agents/
    agent-0042/
      workspace/
      scratch/
  run/
    broker.sock
  evidence/
    events.log
```

`guardian/`, `policy.yaml`, `manifests/`, and `evidence/` must be unwritable by the agent.

## Minimal Build Order

1. Build the Guardian daemon and immutable policy file.
2. Launch each agent inside an isolated container/cgroup controlled by the Guardian.
3. Add the Unix-socket heartbeat and independently verify PID, executable, ancestry, cgroup, and filesystem location.
4. Put sensitive operations behind the Capability Broker and implement `TRUSTED`, `RESTRICTED`, `QUARANTINED`, and `TERMINATED`.
5. Scan the sandbox process tree for unauthorized executables and automatically downgrade trust when one appears.
6. Write every state transition and denied capability request into the hash-chained evidence ledger.

## One-Sentence Summary

The Guardian continuously verifies the agent, its location, and its process lineage; every meaningful capability passes through a broker, and any loss of trust immediately reduces or eliminates those capabilities.
