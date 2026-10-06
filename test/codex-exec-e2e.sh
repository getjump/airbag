#!/bin/sh
set -eu
[ "$(uname)" = Darwin ] || { echo 'SKIP: named Codex exec requires macOS'; exit 0; }
command -v codex >/dev/null 2>&1 || { echo 'SKIP: Codex is not installed'; exit 0; }
python3 - <<'PYCODE'
import runpy
runpy.run_path('test/codex-daemon-e2e.py')['main']('exec')
PYCODE
