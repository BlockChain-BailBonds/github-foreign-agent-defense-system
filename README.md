# GitHub Foreign Agent Defense System (FADS)

FADS is a standalone Linux Guardian for containing AI agents and other automated processes behind an external trust decision and a capability broker.

Its runtime invariant is:

```text
NO VERIFIED SESSION
+ NO VALID OS CONTEXT
+ NO CURRENT AUTHORIZATION
= NO CAPABILITY
```

The agent does not decide whether it is trusted. The Guardian does.

## What ships in v0.1

- executable, optional model, and additional artifact SHA-256 verification before launch;
- one fresh cryptographic session identifier per launch;
- monotonic `TRUSTED -> RESTRICTED -> QUARANTINED -> TERMINATED` state handling;
- a Unix-domain capability broker authenticated with `SO_PEERCRED`, cgroup membership, session ID, and heartbeat counter;
- brokered workspace reads and atomic writes with relative-path and symlink protections;
- brokered execution of manifest-approved executables inside a fresh hard sandbox;
- systemd transient-unit/cgroup resource limits;
- bubblewrap mount, user, PID, network, IPC, UTS, and cgroup namespace isolation;
- minimal filesystem construction instead of exposing the host root;
- read-only project workspace inside the agent sandbox plus a separate writable scratch directory;
- no raw external network in the contained agent;
- dropped Linux capabilities and `NoNewPrivileges`;
- libseccomp denial of kernel/admin escape-oriented syscalls;
- continuous manifest, policy, executable, model, and identity-artifact integrity checks;
- cgroup process inventory for unexpected executables;
- append-only SHA-256 evidence chaining with truncation detection and optional HMAC-authenticated chain head;
- a privileged end-to-end user acceptance test.

FADS is application-independent. It contains a process; it does not depend on BailBonds, Mermaid, ARC, ADL, GhostBridge, KSIG, a specific model provider, or a particular agent framework.

## Trust states

| Capability | Trusted | Restricted | Quarantined | Terminated |
| --- | --- | --- | --- | --- |
| Read workspace | yes | yes | yes | no |
| Write project through broker | yes | no | no | no |
| Brokered execute | yes | no | no | no |
| Raw external network | no | no | no | no |
| Credentials | no | no | no | no |
| External tools | no | no | no | no |
| Guardian evidence | Guardian only | Guardian only | Guardian only | Guardian only |

The contained process has a read-only workspace and writable scratch area. Project mutations therefore require the broker. Local computation inside the sandbox is not treated as a host capability.

## Hard enforcement boundary

`fads run` has no policy-only fallback. It checks for a real Linux containment stack and refuses to start the agent if required enforcement is unavailable.

The user-test backend requires:

```text
systemd transient service / cgroup v2
            +
bubblewrap namespaces and minimal mounts
            +
read-only project workspace
            +
private network namespace
            +
empty Linux capability set
            +
NoNewPrivileges
            +
libseccomp filter
            +
Unix-domain capability broker
```

FADS assumes the Linux kernel and Guardian/root administrative boundary are trusted. It does **not** claim to defend against a compromised kernel, hostile root administrator, or compromised Guardian administrator. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Install for user testing

Ubuntu/Debian host packages:

```bash
sudo apt update
sudo apt install -y bubblewrap python3 python3-pip python3-yaml
```

Install the CLI from the repository:

```bash
python3 -m pip install --user -e .
```

Check the host from an elevated Guardian context:

```bash
sudo -E env PATH="$PATH" fads doctor
```

Every returned prerequisite must be `true` before a hard-sandbox run is accepted.

## Run the acceptance test

From a normal non-root shell:

```bash
./scripts/user-test.sh
```

The script elevates the Guardian with `sudo`, while the contained agent stays on the original non-root UID. It tests direct-write blocking, network isolation, a valid brokered write, deliberate trust downgrade, immediate write revocation, and evidence-chain verification.

Expected result:

```text
PASS: FADS standalone user test completed
```

Full procedure: [`docs/USER_TESTING.md`](docs/USER_TESTING.md).

## Run your own agent

Create a workspace and manifest. Hash the real executable and any immutable agent/model artifacts rather than editing placeholder hashes manually:

```bash
mkdir -p "$HOME/fads-agent/workspace" "$HOME/fads-agent/scratch"

fads manifest-init \
  --agent-id my-agent \
  --executable /usr/bin/python3 \
  --artifact "$HOME/my-agent/agent.py" \
  --workspace "$HOME/fads-agent/workspace" \
  --scratch "$HOME/fads-agent/scratch" \
  --run-as-uid "$(id -u)" \
  --out "$HOME/fads-agent/manifest.yaml"
```

Place the immutable agent entrypoint where the sandbox can see it, for example in the workspace, then launch the Guardian as root while keeping the agent UID non-root:

```bash
cp "$HOME/my-agent/agent.py" "$HOME/fads-agent/workspace/agent.py"
export FADS_LEDGER_HMAC_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

sudo -E fads run \
  --manifest "$HOME/fads-agent/manifest.yaml" \
  --policy ./policy.yaml \
  --state-dir /var/lib/fads \
  -- /usr/bin/python3 /workspace/agent.py
```

The Guardian injects only two FADS values into the contained environment:

```text
FADS_SESSION_ID
FADS_BROKER_SOCKET=/run/fads/broker.sock
```

Agents can use the small JSON protocol documented in [`docs/BROKER_PROTOCOL.md`](docs/BROKER_PROTOCOL.md).

## Verify evidence

```bash
sudo -E fads verify-ledger --state-dir /var/lib/fads
```

When `FADS_LEDGER_HMAC_KEY` was used to create a signed ledger head, the same key is required to reopen or verify that ledger.

## Developer tests

```bash
python3 -m pip install -e . pytest
python3 -m pytest
python3 -m py_compile src/fads/*.py
```

The repository CI runs the non-privileged unit suite. The privileged `scripts/user-test.sh` test is intentionally run on a real user-test Linux host because hosted CI does not represent the target host trust boundary.
