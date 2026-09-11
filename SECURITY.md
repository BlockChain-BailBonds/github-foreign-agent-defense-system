# Security Policy

## Status

FADS is a defense-in-depth reference implementation. It is not certified,
accredited, or sufficient by itself for classified or safety-critical use.

## Supported version

Security fixes are applied to the latest release and the `main` branch.

## Reporting a vulnerability

Do not open a public issue for an undisclosed vulnerability. Use GitHub's
private vulnerability reporting feature in the repository Security tab.
Include affected versions, reproduction steps, impact, and suggested mitigations.

## Deployment boundary

The Python broker does not create the OS security boundary. Production deployments
must place agents in a separate user and mount namespace, deny direct host and
network access, apply cgroup and seccomp limits, keep Guardian keys outside the
sandbox, and expose only the authenticated broker socket. If an agent has a second
capability path, revocation is not effective.
