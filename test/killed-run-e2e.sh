#!/bin/sh
# A resumed run whose airbag is killed. On Linux the agent goes with it
# (its pid namespace ends with airbag). On macOS nothing ends it: it keeps
# running and holds the session's run lock, which airbag passed to it, so
# a rollback waits for it. Once the agent is gone the rollback goes on
# and marks the session stopped, and the session resumes.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-killed-run-e2e.XXXXXX")
# A duration of its own, to tell the agent's sleep from any other. The
# pattern leaves out airbag's command line, which names it too.
nap=$((3000 + $$ % 1000))
agent="^[^ ]*sleep $nap\$"
pid=''
cleanup() {
	[ -z "$pid" ] || kill -9 "$pid" 2>/dev/null || true
	pkill -9 -f "$agent" 2>/dev/null || true
	rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }
status() { "$AIRBAG" ls | awk -v id="$1" '$1 == id { print $2 }'; }

mkdir "$T/proj" && cd "$T/proj"
echo user > f.txt && echo user > other.txt
"$AIRBAG" run -- sh -c 'echo agent > f.txt; echo agent > other.txt' >/dev/null 2>&1
id=$("$AIRBAG" ls | awk 'NR==1{print $1}')
# A partial apply: the session stays one to resume.
"$AIRBAG" apply --only f.txt --yes "$id" >/dev/null
[ "$(cat f.txt)" = agent ] || fail "f.txt not applied"

# The resumed run's agent sleeps; airbag is killed under it.
"$AIRBAG" run --session "$id" -- sleep "$nap" </dev/null >"$T/out" 2>&1 &
pid=$!
i=0
until pgrep -f "$agent" >/dev/null; do
	i=$((i + 1))
	[ "$i" -lt 100 ] || fail "the agent did not start: $(cat "$T/out")"
	sleep 0.1
done
kill -9 "$pid"
wait "$pid" 2>/dev/null || true
pid=''
[ "$(status "$id")" = running ] || fail "the killed run's session is $(status "$id")"

if [ "$(uname)" = Darwin ]; then
	pgrep -f "$agent" >/dev/null || fail "the agent did not outlive airbag"
	if out=$("$AIRBAG" rollback "$id" 2>&1); then
		fail "rolled back beside the agent: $out"
	fi
	echo "$out" | grep -q "outlive airbag" || fail "the rollback was refused for another reason: $out"
	[ "$(cat f.txt)" = agent ] || fail "the refused rollback changed f.txt"
	pkill -9 -f "$agent"
fi
i=0
while pgrep -f "$agent" >/dev/null; do
	i=$((i + 1))
	[ "$i" -lt 100 ] || fail "the agent outlived its run"
	sleep 0.1
done

"$AIRBAG" rollback "$id" >"$T/out" 2>&1 || fail "the rollback once the agent was gone: $(cat "$T/out")"
[ "$(cat f.txt)" = user ] || fail "f.txt not rolled back"
[ "$(status "$id")" = stopped ] || fail "the session after the rollback is $(status "$id")"
"$AIRBAG" run --session "$id" -- true >"$T/out" 2>&1 || fail "the session did not resume: $(cat "$T/out")"
"$AIRBAG" discard --yes "$id" >/dev/null 2>&1 || true
echo PASS
