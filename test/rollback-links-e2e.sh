#!/bin/sh
# Rollback gives the agent's versions back only inside its branch. After a
# partial apply, a resumed run makes a directory of its branch a link to a
# directory outside; the rollback then writes nothing there, stops, and
# keeps your version from before the apply in the session.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-rollback-links-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

mkdir "$T/proj" "$T/outside" && cd "$T/proj"
mkdir a && echo user > a/b.txt && echo user > other.txt
"$AIRBAG" run -- sh -c 'echo agent > a/b.txt; echo agent > other.txt' >/dev/null 2>&1
id=$("$AIRBAG" ls | awk 'NR==1{print $1}')

"$AIRBAG" apply --only a/b.txt --yes "$id" >/dev/null
[ "$(cat a/b.txt)" = agent ] || fail "a/b.txt not applied"
[ "$(cat other.txt)" = user ] || fail "other.txt applied although not asked for"

# The resumed run replaces a/ in its branch with a link out of it.
"$AIRBAG" run --session "$id" -- sh -c "rm -rf a && ln -s '$T/outside' a" >/dev/null 2>&1

if out=$("$AIRBAG" rollback "$id" 2>&1); then
	fail "the rollback through the branch's link went on: $out"
fi
left=$(ls -A "$T/outside")
[ -z "$left" ] || fail "the rollback wrote outside the session: $left"
echo "$out" | grep -q "return the agent's version" || fail "the rollback stopped for another reason: $out"
[ "$(cat a/b.txt)" = agent ] || fail "a/b.txt changed although the rollback stopped before it"
# The version from before the apply is kept, and discard says so.
if out=$("$AIRBAG" discard --yes "$id" 2>&1); then
	fail "discard deleted the kept version: $out"
fi
echo "$out" | grep -q "holds your versions" || fail "discard refused for another reason: $out"
echo PASS
