#!/bin/sh
# Answering requests the unix way: requests are held for a decision
# (ask_wait), the user's on_ask command gets each one as JSON, decisions
# come from `airbag approve` / `airbag deny` / `--always` or from
# `airbag watch`, and `airbag events` reports all of it. A repository's
# airbag.yaml cannot set on_ask. Run as a regular user.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-approvals-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

# A separate home: the personal config and standing approvals live there.
H="$T/home"
mkdir -p "$H/.config/airbag"
cat > "$H/.config/airbag/airbag.yaml" <<YAML
on_ask: ["/bin/sh", "-c", "cat > '$T/ask.json'"]
ask_wait: 10s
YAML
ab() { HOME="$H" "$AIRBAG" "$@"; }

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
cat > airbag.yaml <<YAML
allow: [example.com]
on_ask: ["/bin/sh", "-c", "touch '$T/repo-hook-ran'"]
rules:
  - name: ask-before-sending
    when: effect.kind == "net.egress"
    verdict: ask
YAML
git add -A && git commit -qm init

# Each request blocks the agent until it is decided or ask_wait passes.
# What counts is airbag's verdict on the script, not the HTTP result.
cat > "$T/agent.sh" <<'EOF2'
send() { bash -c "curl -s -o /dev/null --max-time 5 -X $1 -d x https://example.com/ || true" 2>>"$1.err"; }
for m in "$@"; do send "$m" && touch "$m.sent"; done
exit 0
EOF2
wait_ask() {
	i=0
	until ab approve 2>/dev/null | grep -q "^$1 "; do
		i=$((i+1)); [ $i -gt 100 ] && fail "request $1 did not appear"
		sleep 0.2
	done
}

ab run -- sh "$T/agent.sh" POST PUT DELETE > "$T/out1" 2>&1 &
pid=$!
wait_ask a-1 && ab approve a-1 >/dev/null
wait_ask a-2 && ab deny a-2 >/dev/null
wait_ask a-3 && ab approve --always a-3 >/dev/null
wait $pid || fail "session 1: $(cat "$T/out1")"
grep -q "on_ask and ask_wait are ignored here" "$T/out1" || fail "no warning about the repository's on_ask: $(cat "$T/out1")"
[ ! -e "$T/repo-hook-ran" ] || fail "the repository's on_ask ran"
rev=$(ab review)
for want in "+ POST.sent" "+ DELETE.sent"; do
	echo "$rev" | grep -qF -- "$want" || fail "held request approved in time did not pass ($want): $rev"
done
echo "$rev" | grep -qF "+ PUT.sent" && fail "a denied request passed"
ab diff PUT.err | grep -q 'the user denied a-2' || fail "the agent was not told about the deny: $(ab diff PUT.err)"
grep -q '"rule":"ask-before-sending"' "$T/ask.json" && grep -q '"approve":"airbag approve s-' "$T/ask.json" ||
	fail "on_ask did not get the request as JSON: $(cat "$T/ask.json" 2>/dev/null)"
ev=$(ab events)
echo "$ev" | grep '"kind":"ask"' | grep -q '"ask":{' || fail "events lack the requests: $ev"
echo "$ev" | grep '"kind":"ask.decided"' | grep -q '"verdict":"denied"' || fail "events lack the deny: $ev"
grep -q "ask-before-sending" "$H/.config/airbag/approvals.yaml" || fail "--always was not recorded"
ab discard --yes >/dev/null

# The standing approval lets the same effect through in a new session.
start=$(date +%s)
ab run -- sh "$T/agent.sh" DELETE >/dev/null 2>&1
[ $(( $(date +%s) - start )) -lt 8 ] || fail "standing approval did not skip the hold"
ab review | grep -qF "+ DELETE.sent" || fail "standing approval ignored"
ab approve | grep -q "No pending requests." || fail "a request was made despite the standing approval"
ab discard --yes >/dev/null

# airbag watch answers a request as it comes.
(printf 'y\n'; sleep 30) | HOME="$H" timeout 40 "$AIRBAG" watch > "$T/watch.out" 2>&1 &
wpid=$!
sleep 1
ab run -- sh "$T/agent.sh" PATCH >/dev/null 2>&1
kill $wpid 2>/dev/null || true
ab review | grep -qF "+ PATCH.sent" || fail "watch did not approve: $(cat "$T/watch.out")"
grep -q "? a-1 ask-before-sending" "$T/watch.out" && grep -q "Approved a-1" "$T/watch.out" ||
	fail "watch output: $(cat "$T/watch.out")"
ab discard --yes >/dev/null
echo PASS
