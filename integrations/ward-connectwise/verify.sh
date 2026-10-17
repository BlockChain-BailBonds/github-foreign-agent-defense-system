#!/bin/sh
set -eu
cd "$(dirname "$0")"
python3 -m compileall -q ward_detector.py tests
python3 -m unittest discover -s tests -v
set +e
python3 ward_detector.py fixtures/synthetic_compromise.json --out /tmp/ward-synthetic-test
rc=$?
set -e
if [ "$rc" -ne 2 ]; then
  echo "Expected 2 (findings), got $rc" >&2
  exit 1
fi
python3 - <<'PY'
import json
from pathlib import Path
p = json.loads(Path('/tmp/ward-synthetic-test.json').read_text())
assert p['totalFindings'] == 9, p['totalFindings']
assert p['complete'] is True
print('Fixture smoke test passed: 9 findings, complete source evidence (synthetic).')
PY