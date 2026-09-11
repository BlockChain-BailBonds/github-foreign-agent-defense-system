# FADS User Testing

## Supported test host

Use a dedicated modern systemd Linux machine or VM with unified cgroup v2, bubblewrap (`bwrap`), Python 3.11+, PyYAML, root/sudo access for the Guardian, and a non-root account used as the contained agent UID.

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y bubblewrap python3 python3-pip python3-yaml
python3 -m pip install --user -e .
sudo -E env PATH="$PATH" fads doctor
```

Every `doctor` check must be `true`. FADS refuses a hard-sandbox run if required enforcement is unavailable.

## One-command acceptance test

From a normal non-root shell:

```bash
./scripts/user-test.sh
```

The script elevates only the Guardian; the test agent runs as the original non-root UID. The scenario verifies identity/artifact hashing, dedicated cgroup launch, namespace isolation, direct project-write denial, direct external-network denial, a valid brokered project write while `TRUSTED`, denial of an unauthorized network capability request, transition to `RESTRICTED`, immediate revocation of project write, and evidence-ledger verification.

Expected final line:

```text
PASS: FADS standalone user test completed
```

The deliberate restriction causes the internal Guardian run to return code `2`; the outer acceptance script expects that and exits `0` only when the security assertions pass.

Evidence is written under `/tmp/fads-user-test-state/evidence/` by default.
