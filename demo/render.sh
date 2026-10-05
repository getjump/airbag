#!/bin/sh
# Renders recorded casts to animated SVGs: demo/render.sh [NAME...],
# demo by default. The README shows demo/demo.svg: sharp at any zoom and
# smaller than the GIF, which stays for places that do not show SVG.
set -eu
cd "$(dirname "$0")"
[ $# -gt 0 ] || set -- demo
for name in "$@"; do
	npx --yes svg-term-cli@2.1.1 --in "$name.cast" --out "$name.svg" --window --no-cursor
done
