# FADS Broker Protocol v1

Transport is one JSON object per Unix-domain socket connection, terminated by a newline. The broker returns one JSON object followed by a newline and closes the connection.

The broker authenticates the Linux peer PID using `SO_PEERCRED` and requires that PID to belong to the active session cgroup before evaluating the supplied session identifier.

Supported v0.1 operations are `heartbeat`, `status`, `read`, `write`, `exec`, and a fail-closed `network` request. Workspace paths must be relative and may not contain `..`; final symlinks are rejected. Project writes are performed by the Guardian while the agent's mounted workspace remains read-only.

Network brokerage is intentionally unavailable in v0.1. A network request is denied and the default policy downgrades the session to `RESTRICTED`.
