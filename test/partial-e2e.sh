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

# A directory the agent recreates is reviewed against the real files:
# the edit inside it shows as one, an unchanged file does not show, the
# user's files it drops show as deleted. It applies whole, not in part.
mkdir src && printf 'check(token)\nreturn ok\n' > src/auth.go && echo same > src/same.go && echo mine > src/gone.go
git add -A && git commit -qm src
"$AIRBAG" run -- sh -c 'rm -rf src && mkdir src && printf "check(token)\nreturn true\n" > src/auth.go && echo same > src/same.go && echo new > src/new.go' >/dev/null 2>&1
rev=$("$AIRBAG" review)
for want in "! src/" "~ src/auth.go" "+ src/new.go" "- src/gone.go"; do
	echo "$rev" | grep -qF -- "$want" || fail "review lacks '$want': $rev"
done
echo "$rev" | grep -q "^  [-+~!] src/same.go" && fail "review lists the unchanged src/same.go: $rev"
d=$("$AIRBAG" diff)
echo "$d" | grep -q '^-return ok' && echo "$d" | grep -q '^+return true' || fail "diff does not show the edit: $d"
echo "$d" | grep -q '^+check(token)' && fail "diff shows src/auth.go as a new file: $d"
"$AIRBAG" review --json | python3 -c '
import json, sys
c = {(x["path"], x["kind"]) for x in json.load(sys.stdin)["changes"]}
assert ("src/auth.go", "modified") in c and ("src/gone.go", "deleted") in c, c
assert not any(p == "src/same.go" for p, _ in c), c
' || fail "review --json"
"$AIRBAG" apply --only src/auth.go --yes >"$T/only" 2>&1 && fail "--only took part of a replaced directory: $(cat "$T/only")"
grep -q "replaced as a whole" "$T/only" || fail "--only inside a replaced directory: $(cat "$T/only")"
[ -f src/gone.go ] && [ "$(sed -n 2p src/auth.go)" = "return ok" ] || fail "the refused --only changed files"
"$AIRBAG" apply --only src --yes >/dev/null
[ "$(sed -n 2p src/auth.go)" = "return true" ] && [ "$(cat src/same.go)" = same ] && [ -f src/new.go ] && [ ! -e src/gone.go ] ||
	fail "src is not the agent's after apply: $(ls src)"
echo PASS
