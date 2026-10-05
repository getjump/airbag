#!/bin/sh
# sanitize.sh copies model text from stdin to stdout so that, posted to
# GitHub, it can neither hide anything nor reach anyone:
#
#   - "<!--" becomes "&lt;!--", which renders as written. No hidden HTML
#     comment survives, so neither does a forged <!-- agent: marker; the
#     workflow appends its own marker after this.
#   - A zero-width space follows every "@", so no @mention notifies anyone
#     or reads as a trigger (@claude, @codex).
#
# The output stops at 60000 bytes; GitHub takes a body of 65536
# characters, and the workflows add a few lines around it.
set -eu

zwsp=$(printf '\342\200\213')
sed -e 's/<!--/\&lt;!--/g' -e "s/@/@$zwsp/g" | head -c 60000
