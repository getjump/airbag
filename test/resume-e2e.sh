#!/bin/sh
# run --session: a second run continues on the same branch, with the
# same outbox and the labels of the first run; the real files stay
# untouched until apply.
set -eu

AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-resume-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main
git config user.email e2e@example.com && git config user.name e2e
printf 'base\n' > notes.txt && printf 'API_TOKEN=sk-resume-0123456789\n' > .env
git add notes.txt && git commit -qm init

fuse=no
[ -w /dev/fuse ] && fuse=yes

"$AIRBAG" run --allow example.com -- sh -c 'echo run1 >> notes.txt; cat .env >/dev/null; git commit -qam run1; git push origin main 2>/dev/null; true' >/dev/null 2>&1
id=$("$AIRBAG" ls | awk 'NR==1{print $1}')

# shellcheck disable=SC2016 # the script runs in the sandbox
out=$("$AIRBAG" run --session last -- sh -c 'echo "saw: $(tail -1 notes.txt)"; echo run2 >> notes.txt
	curl -s -o /dev/null -w "curl=%{http_connect}\n" --max-time 10 https://example.com/ || true' 2>&1)
echo "$out" | grep -q "resuming session $id (run 2)" || fail "not resumed: $out"
echo "$out" | grep -q "saw: run1" || fail "the second run did not see the first run's branch: $out"
[ "$(cat notes.txt)" = base ] || fail "the real file changed before apply"
if [ $fuse = yes ]; then
	echo "$out" | grep -q "curl=403" || fail "egress open again after the first run read .env: $out"
	"$AIRBAG" log "$id" | grep 'example.com:443' | grep -q 'secret-taint' || fail "the taint did not carry over: $("$AIRBAG" log "$id")"
else
	echo "SKIP: taint carry-over (/dev/fuse not writable)"
fi
n=$("$AIRBAG" ls | grep -c "$id" || true)
[ "$n" = 1 ] || fail "resume made a new session"
"$AIRBAG" review "$id" | grep -q "i-1 .*git push origin main" || fail "the first run's push is not in the outbox"

"$AIRBAG" apply --yes "$id" >/dev/null
[ "$(tail -2 notes.txt | tr '\n' ' ')" = "run1 run2 " ] || fail "apply did not bring both runs: $(cat notes.txt)"
"$AIRBAG" run --session "$id" -- true 2>&1 | grep -q "only a stopped session" || fail "an applied session was resumed"
echo PASS
