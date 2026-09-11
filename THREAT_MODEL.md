# Threat Model

## Assets

Guardian signing keys, policy and manifests, agent workspaces, credentials,
broker authority, and the evidence ledger.

## Adversary

Assume the agent process and all data it controls may be hostile. It may forge or
replay protocol messages, traverse paths, replace symlinks, spawn children, request
unauthorized programs, exhaust resources, and try to modify evidence. The host
kernel and Guardian administrative domain are trusted in this release.

## Mandatory production controls

| Layer | Required control |
| --- | --- |
| Identity | Immutable manifest, executable digest, PID and process lineage checks |
| Isolation | Dedicated UID, user/mount/PID/network namespaces, no host shell |
| Filesystem | Minimal mounts, read-only host, broker-owned socket and policy |
| Process | cgroup limits, seccomp allowlist, no unbrokered process creation |
| Network | Empty network namespace or explicit egress proxy allowlist |
| Secrets | Short-lived brokered credentials, never agent-readable static keys |
| Audit | Remote append-only replication and external ledger head anchoring |
| Operations | Signed releases, reproducible builds, two-person policy changes |

## Fail-closed responses

| Detection | Minimum response |
| --- | --- |
| Heartbeat timeout or unknown child | Restrict |
| Replay, identity mismatch, path escape, unauthorized executable | Quarantine |
| Guardian/policy tamper or broker bypass | Terminate and isolate |

## Known limitations

- The current package is a reference broker library, not a container runtime.
- `/proc` identity monitoring currently verifies the primary process, not every descendant.
- The local ledger detects modification but needs remote replication to resist deletion.
- SHA-256 allowlisting establishes binary identity, not source provenance or safety.
- HMAC keys require a separate root-of-trust and rotation mechanism in production.
