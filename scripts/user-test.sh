#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-/usr/bin/python3}"
if [[ "$(id -u)" -ne 0 ]]; then export FADS_TEST_UID="$(id -u)"; exec sudo -E env FADS_TEST_UID="$FADS_TEST_UID" bash "$0" "$@"; fi
TEST_UID="${FADS_TEST_UID:-${SUDO_UID:-}}"
if [[ -z "$TEST_UID" || "$TEST_UID" == "0" ]]; then echo "FAIL: run from a non-root account" >&2; exit 2; fi
export PYTHONPATH="$ROOT/src"
STATE="${FADS_TEST_STATE:-/tmp/fads-user-test-state}"; WORK="${FADS_TEST_WORKSPACE:-/tmp/fads-user-test-workspace}"; SCRATCH="${FADS_TEST_SCRATCH:-/tmp/fads-user-test-scratch}"; MANIFEST="${FADS_TEST_MANIFEST:-/tmp/fads-user-test-manifest.yaml}"
rm -rf "$STATE" "$WORK" "$SCRATCH"; mkdir -p "$WORK" "$SCRATCH"; cp "$ROOT/examples/revocation_agent.py" "$WORK/revocation_agent.py"; chown -R "$TEST_UID" "$WORK" "$SCRATCH"; chmod 0755 "$WORK"
python3 -m fads.cli doctor
python3 -m fads.cli manifest-init --agent-id user-test-agent --executable "$PYTHON" --artifact "$WORK/revocation_agent.py" --workspace "$WORK" --scratch "$SCRATCH" --run-as-uid "$TEST_UID" --out "$MANIFEST"
export FADS_LEDGER_HMAC_KEY="${FADS_LEDGER_HMAC_KEY:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"
set +e; python3 -m fads.cli run --manifest "$MANIFEST" --policy "$ROOT/policy.yaml" --state-dir "$STATE" -- "$PYTHON" /workspace/revocation_agent.py; RC=$?; set -e
[[ "$RC" -eq 2 ]] || { echo "FAIL: expected deliberate restricted exit 2, got $RC" >&2; exit 1; }
[[ -f "$WORK/before-restriction.txt" ]] || exit 1
[[ ! -e "$WORK/after-restriction.txt" ]] || exit 1
[[ ! -e "$WORK/direct-write.txt" ]] || exit 1
python3 -m fads.cli verify-ledger --state-dir "$STATE"
echo "PASS: FADS standalone user test completed"
echo "Evidence: $STATE/evidence/events.jsonl"
