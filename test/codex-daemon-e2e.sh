#!/bin/sh
set -eu
[ "$(uname)" = Darwin ] || { echo "SKIP: macOS daemon regression"; exit 0; }
command -v codex >/dev/null || { echo "SKIP: codex not in PATH"; exit 0; }
exec python3 "$(dirname "$0")/codex-daemon-e2e.py"
