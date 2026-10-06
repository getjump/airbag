#!/bin/sh
set -eu
[ "$(uname)" = Darwin ] || { echo "SKIP: split execution requires macOS"; exit 0; }
command -v codex >/dev/null 2>&1 || { echo "SKIP: Codex is not installed"; exit 0; }
python3 - <<'PYCODE'
import runpy
main = runpy.run_path('test/codex-daemon-e2e.py')['main']
for mode in ['split', 'split-eof', 'split-crash-worker', 'split-crash-parent']:
    main(mode)
PYCODE
