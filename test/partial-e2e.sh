#!/bin/sh
# Partial apply: accept some changes, keep the rest in the session.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-partial-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo a > a.txt && echo b > b.txt && git add -A && git commit -qm init
"$AIRBAG" run -- sh -c 'echo A > a.txt; echo B > b.txt; echo C > c.txt; git add -A; git commit -qm agent' >/dev/null 2>&1

# units: git internals, a.txt, b.txt, c.txt -> n, y, diff then n, y
out=$(printf 'n\ny\nd\nn\ny\n' | "$AIRBAG" apply -i)
echo "$out" | grep -q '^+B' || fail "diff not shown: $out"
[ "$(cat a.txt)" = A ] || fail "a.txt not applied"
[ "$(cat b.txt)" = b ] || fail "b.txt applied although rejected"
[ "$(cat c.txt)" = C ] || fail "c.txt not applied"
[ "$(git rev-list --count HEAD)" = 1 ] || fail "git internals applied although rejected"
rev=$("$AIRBAG" review)
echo "$rev" | grep -q "~ b.txt" || fail "b.txt left the session: $rev"
echo "$rev" | grep -q "^  [~+] a.txt" && fail "a.txt still in the session: $rev"

"$AIRBAG" apply --only b.txt --yes >/dev/null
[ "$(cat b.txt)" = B ] || fail "--only b.txt not applied"
"$AIRBAG" apply --yes >/dev/null
[ "$(git rev-list --count HEAD)" = 2 ] || fail "commit not applied"
git diff --quiet || fail "working tree differs from the agent's commit"
"$AIRBAG" ls | grep "$T/proj" | grep -q applied || fail "session not marked applied"
echo PASS
