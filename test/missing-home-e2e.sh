#!/bin/sh
# A $HOME that is not there, with --no-home (HOME=/nonexistent, as in CI
# jobs and containers): the session runs, with and without the file
# policy, and airbag makes nothing at that path. Linux: macOS never
# branches $HOME, and e2e.sh checks what it does there.
set -eu
AIRBAG=${AIRBAG:-airbag}
[ "$(uname)" = Linux ] || { echo "SKIP: Linux only"; exit 0; }
T=$(mktemp -d "$HOME/.airbag-nohome-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hello > README.md && git add -A && git commit -qm init
missing="$T/missing-home"

check() {
	out=$(HOME="$missing" "$AIRBAG" run --no-home "$@" -- sh -c 'echo agent > new.txt' 2>&1) || fail "run $*: $out"
	[ ! -e "$missing" ] || fail "run $* made the missing \$HOME: $out"
	[ ! -e new.txt ] || fail "run $* wrote to the real files: $out"
	"$AIRBAG" review --json | grep -q '"path": "new.txt"' || fail "run $*: review misses the agent's file: $("$AIRBAG" review)"
	"$AIRBAG" discard --yes >/dev/null
}
check
if [ -w /dev/fuse ]; then
	check --fs-policy
else
	echo "SKIP: --fs-policy (/dev/fuse unavailable)"
fi
echo PASS
