#!/bin/sh
set -eu
[ "$(uname)" = Darwin ] || { echo "SKIP: macOS Claude regression"; exit 0; }
command -v claude >/dev/null || { echo "SKIP: claude not in PATH"; exit 0; }
exec python3 "$(dirname "$0")/claude-mac-e2e.py"
