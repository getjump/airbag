#!/bin/sh
# Policies: airbag.yaml rules over predicted effects. An "ask" blocks
# the command until the human runs `airbag approve`, then the retry
# passes; a "deny" blocks for good. Run as a regular user.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-policy-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
cat > airbag.yaml <<'YAML'
allow: [example.com]
rules:
  - name: ask-before-sending
    when: effect.kind == "net.egress"
    verdict: ask
    message: data leaves the machine
  - name: no-marker
    when: command.line.contains("forbidden-marker")
    verdict: deny
    message: this command is never allowed
YAML
git add -A && git commit -qm init

cat > "$T/agent.sh" <<'EOF2'
bash -c 'echo forbidden-marker > marker.txt' 2>deny.err && echo "LEAK: deny rule did not block"
grep -q 'no-marker' deny.err || echo "LEAK: deny message missing: $(cat deny.err)"
n=0
until bash -c 'curl -s -o /dev/null --max-time 5 -X POST -d x https://example.com; touch sent.flag' 2>>ask.err; do
	n=$((n+1)); [ $n -gt 100 ] && { echo "LEAK: never approved"; exit 1; }
	sleep 0.2
done
EOF2

"$AIRBAG" run -- sh "$T/agent.sh" > "$T/out.txt" 2>&1 &
pid=$!
i=0
until "$AIRBAG" approve 2>/dev/null | grep -q '^a-1'; do
	i=$((i+1)); [ $i -gt 100 ] && fail "no approval request appeared: $(cat "$T/out.txt")"
	sleep 0.2
done
"$AIRBAG" approve 2>/dev/null | grep -q 'ask-before-sending' || fail "wrong pending request"
"$AIRBAG" approve a-1 >/dev/null
wait $pid || fail "agent failed: $(cat "$T/out.txt")"
grep -q LEAK "$T/out.txt" && fail "$(cat "$T/out.txt")"

"$AIRBAG" diff ask.err | grep -q 'airbag approve a-1' || fail "agent was not told how to get approval"
rev=$("$AIRBAG" review)
echo "$rev" | grep -q "+ sent.flag" || fail "approved command did not run: $rev"
echo "$rev" | grep -q "marker.txt" && fail "denied command ran: $rev"
echo "$rev" | grep -qF "deny" || fail "review does not show the blocked command: $rev"
"$AIRBAG" discard --yes >/dev/null
echo PASS
