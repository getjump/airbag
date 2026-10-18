#!/bin/sh
# simulation: stubs given with --simulate answer for the hosts they
# name, through the session CA, to real clients under airbag run (curl,
# Python, Node, a Go program, and Claude Code driven by test/mockapi).
# The stubbed hosts are never contacted: every connection airbag's
# proxy opens goes through a trap that records what it was asked for.
# An allowed host without stubs is still reached, and review and the
# effect log list each simulated call. Each client's result is printed.
set -eu

AIRBAG=${AIRBAG:-airbag}
# macOS can run it too (AIRBAG_E2E_ANY_OS=1); CI runs it on Linux.
[ "$(uname -s)" = Linux ] || [ -n "${AIRBAG_E2E_ANY_OS:-}" ] || {
	echo "SKIP: Linux only"
	exit 0
}
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "$HOME/.airbag-sim-e2e.XXXXXX")
E=$(mktemp -d /tmp/airbag-sim-e2e.XXXXXX)
ECHO_PID=
TRAP_PID=
cleanup() {
	[ -z "$ECHO_PID" ] || kill "$ECHO_PID" 2>/dev/null || true
	[ -z "$TRAP_PID" ] || kill "$TRAP_PID" 2>/dev/null || true
	rm -rf "$T" "$E"
}
trap cleanup EXIT
fail() {
	echo "FAIL: $*"
	exit 1
}
wait_file() {
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		[ -s "$1" ] && return 0
		sleep 0.2
	done
	fail "no $1"
}

(cd "$REPO" && CGO_ENABLED=0 go build -o "$T/echotls" ./test/echotls && CGO_ENABLED=0 go build -o "$T/simclient" ./test/simclient)

# The real host for passthrough: an HTTPS server on 127.0.0.1 with its
# own certificate, which the session's bundle carries (airbag adds the
# roots SSL_CERT_FILE names) so the clients inside trust it.
"$T/echotls" -dir "$E" 2>/dev/null &
ECHO_PID=$!
wait_file "$E/port"
PORT=$(cat "$E/port")
export SSL_CERT_FILE="$E/ca.pem"

# The trap is airbag's upstream proxy (HTTPS_PROXY on the host), so it
# sees every connection airbag's proxy opens to a name, with the
# CONNECT line that says to which host. 127.0.0.1 is reached directly:
# Go never sends a loopback address through a proxy.
cat >"$T/trap.py" <<'EOS'
import socket, sys
d = sys.argv[1]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(64)
with open(d + "/trap.port.tmp", "w") as f:
    f.write(str(s.getsockname()[1]))
import os
os.rename(d + "/trap.port.tmp", d + "/trap.port")
while True:
    c, _ = s.accept()
    c.settimeout(3)
    try:
        line = c.makefile("rb").readline().decode(errors="replace").strip()
    except Exception as e:
        line = "? " + str(e)
    with open(d + "/trap.log", "a") as f:
        f.write(line + "\n")
    c.close()
EOS
python3 -I "$T/trap.py" "$E" &
TRAP_PID=$!
wait_file "$E/trap.port"
TRAPPORT=$(cat "$E/trap.port")
: >"$E/trap.log"

# The negative control: outside airbag, the same request to the
# stubbed name through the trap does reach it.
curl -sS --max-time 5 -x "http://127.0.0.1:$TRAPPORT" https://api.pay.test/v1/charges/ch_1 >/dev/null 2>&1 || true
grep -q "^CONNECT api.pay.test:443" "$E/trap.log" || fail "the trap does not see a request outside airbag: $(cat "$E/trap.log")"
: >"$E/trap.log"

mkdir "$T/stubs"
printf '{"id":"ch_sim_1","object":"charge","status":"succeeded","amount":100}\n' >"$T/stubs/charge.json"
cat >"$T/stubs/stubs.yaml" <<'EOS'
simulate:
  - name: charge
    match: {method: POST, host: api.pay.test, path: /v1/charges}
    respond:
      status: 200
      headers: {Content-Type: application/json}
      body_file: charge.json
  - name: charge-get
    match: {method: GET, host: api.pay.test, path: /v1/charges/*}
    respond:
      headers: {Content-Type: application/json}
      body: '{"id":"ch_sim_get","status":"succeeded"}'
  - name: status-down
    match: {host: status.pay.test}
    respond: {status: 503, headers: {Retry-After: "1"}, body: maintenance}
EOS

cp "$E/ca.pem" "$T/own-roots.pem"
cat >"$T/clients.sh" <<EOS
# One line per client: NAME|what it got, on one line, with its exit
# status when not 0. No set -e: each client runs on its own.
one() { out=\$("\$@" 2>&1); code=\$?; printf '%s' "\$out" | tr '\\n' ' '; [ "\$code" = 0 ] || printf ' exit=%s' "\$code"; }
PYCODE='import sys, urllib.request
try:
    r = urllib.request.urlopen(sys.argv[1], timeout=20)
    print(r.status, r.read().decode().strip())
except Exception as e:
    print("ERR", type(e).__name__, e)'
py() { url=\$1; shift; env "\$@" python3 -I -c "\$PYCODE" "\$url"; }
echo "curl-post|\$(one curl -sS --max-time 20 -X POST -d amount=100 https://api.pay.test/v1/charges)"
echo "curl-get|\$(one curl -sS --max-time 20 https://api.pay.test/v1/charges/ch_1)"
echo "curl-503|\$(one curl -sS --max-time 20 -w ' %{http_code}' https://status.pay.test/v1/health)"
echo "curl-http|\$(one curl -sS --max-time 20 -w ' %{http_code}' http://status.pay.test/)"
echo "curl-unmatched|\$(one curl -sS --max-time 20 -w ' %{http_code}' https://api.pay.test/v1/refunds)"
echo "curl-pinned|\$(one curl -sS --max-time 20 --pinnedpubkey 'sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' https://api.pay.test/v1/charges/ch_1)"
echo "curl-own-roots|\$(one curl -sS --max-time 20 --cacert "$T/own-roots.pem" https://api.pay.test/v1/charges/ch_1)"
echo "python|\$(one py https://api.pay.test/v1/charges/ch_2)"
if command -v node >/dev/null; then
	echo "node-version|\$(node -p process.versions.node 2>&1)"
	echo "node|\$(one env NODE_USE_ENV_PROXY=1 NODE_NO_WARNINGS=1 node -e "fetch('https://api.pay.test/v1/charges/ch_3').then(async r => console.log(r.status, (await r.text()).trim())).catch(e => console.log('ERR', (e.cause && (e.cause.code || e.cause.message)) || e.message))")"
fi
echo "go|\$(one "$T/simclient" https://api.pay.test/v1/charges/ch_4)"
echo "go-post|\$(one "$T/simclient" -data amount=100 https://api.pay.test/v1/charges)"
echo "control|\$(one curl -sS --max-time 20 -o /dev/null -w ' %{http_code}' https://control.pay-real.test/)"
echo "pass-curl|\$(one curl -sS --max-time 20 --noproxy '' https://127.0.0.1:$PORT/pass/curl)"
echo "pass-python|\$(one py https://127.0.0.1:$PORT/pass/python NO_PROXY= no_proxy=)"
echo "pass-go|\$(one "$T/simclient" -proxy "\$HTTPS_PROXY" https://127.0.0.1:$PORT/pass/go)"
EOS

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main
unset https_proxy http_proxy HTTP_PROXY NO_PROXY no_proxy
HTTPS_PROXY="http://127.0.0.1:$TRAPPORT" "$AIRBAG" run --simulate "$T/stubs/stubs.yaml" \
	--allow "127.0.0.1:$PORT" --allow control.pay-real.test -- sh "$T/clients.sh" >"$T/out" 2>"$T/err" ||
	fail "run: $(cat "$T/out" "$T/err")"
echo "== per-client results"
cat "$T/out"
grep -q "airbag: simulating api.pay.test, status.pay.test (3 stubs)" "$T/err" || fail "run did not say what it simulates: $(cat "$T/err")"

got() { sed -n "s/^$1|//p" "$T/out"; }
# expect NAME GLOB: the client's line matches the glob.
expect() {
	# shellcheck disable=SC2254 # $2 is a glob on purpose
	case $(got "$1") in
	$2) ;;
	*) fail "$1: got '$(got "$1")', want '$2'" ;;
	esac
}
expect curl-post '{"id":"ch_sim_1","object":"charge","status":"succeeded","amount":100}'
expect curl-get '{"id":"ch_sim_get","status":"succeeded"}'
expect curl-503 'maintenance 503'
expect curl-http 'maintenance 503'
expect curl-unmatched '*no stub matches GET api.pay.test/v1/refunds*not sent* 403'
# A client that pins the host's key, or trusts only roots of its own,
# refuses the session CA's certificate: it gets no answer, stubbed or
# real.
expect curl-pinned '*exit=90'
expect curl-own-roots '*exit=60'
expect python '200 {"id":"ch_sim_get","status":"succeeded"}'
expect go '200 {"id":"ch_sim_get","status":"succeeded"}'
expect go-post '200 {"id":"ch_sim_1","object":"charge","status":"succeeded","amount":100}'
# Node's fetch takes HTTPS_PROXY with NODE_USE_ENV_PROXY=1 in 22.21,
# 24.5 and later; an older one ignores the proxy and fails, having no
# DNS. Either way it gets the stub or nothing, never another answer.
if [ -n "$(got node-version)" ]; then
	nv=$(got node-version)
	major=${nv%%.*}
	minor=${nv#*.}
	minor=${minor%%.*}
	case $(got node) in
	'200 {"id":"ch_sim_get","status":"succeeded"}') ;;
	ERR*)
		if [ "$major" -gt 24 ] || { [ "$major" = 24 ] && [ "$minor" -ge 5 ]; } || { [ "$major" = 22 ] && [ "$minor" -ge 21 ]; }; then
			fail "node $nv with NODE_USE_ENV_PROXY=1: $(got node)"
		fi
		echo "note: node $nv does not use HTTPS_PROXY for fetch: $(got node)"
		;;
	*) fail "node $nv: $(got node)" ;;
	esac
fi
# The control host is not stubbed, so airbag's proxy dials it: through
# the trap, which answers nothing.
expect control '*502*'
grep -q "^CONNECT control.pay-real.test:443" "$E/trap.log" || fail "airbag's proxy did not dial the control host through the trap: $(cat "$E/trap.log")"
grep -iF "pay.test" "$E/trap.log" && fail "a simulated host was contacted: $(cat "$E/trap.log")"
# Passthrough: an allowed host without stubs gets the request and answers.
expect pass-curl 'you sent:*'
expect pass-python '200 you sent:*'
expect pass-go '200 you sent:*'
for p in curl python go; do
	grep -q "^GET /pass/$p " "$E/got" || fail "the real host did not get /pass/$p: $(cat "$E/got" 2>/dev/null)"
done
grep -q "/v1/" "$E/got" && fail "a stubbed request reached a real host: $(cat "$E/got")"

echo "== airbag review"
"$AIRBAG" review >"$T/review" || fail "review"
sed -n '/^Network/,/^Outbox/p' "$T/review"
for want in "Simulated  " "POST api.pay.test/v1/charges ×2  by charge" "GET api.pay.test/v1/charges/ch_1 ×1  by charge-get" \
	"GET status.pay.test/v1/health ×1  by status-down" "GET status.pay.test/ ×1  by status-down" "deny GET api.pay.test/v1/refunds"; do
	grep -qF -- "$want" "$T/review" || fail "review lacks '$want':
$(cat "$T/review")"
done
echo "== airbag review --json: network.simulated and blocked"
"$AIRBAG" review --json >"$T/review.json"
python3 -I - "$T/review.json" <<'EOS'
import json, sys
r = json.load(open(sys.argv[1]))
assert r["schema"] == "airbag.review/v1", r["schema"]
sim = r["network"]["simulated"]
blocked = [b for b in r["blocked"] if b["kind"] == "net.simulated"]
print(json.dumps({"network.simulated": sim, "blocked (net.simulated)": blocked}, indent=2))
by = {(s["target"], s["stub"]): s["count"] for s in sim}
assert by[("POST api.pay.test/v1/charges", "charge")] == 2, by
assert by[("GET status.pay.test/v1/health", "status-down")] == 1, by
assert any(b["target"] == "GET api.pay.test/v1/refunds" and b["reason"] == "no stub matches" for b in blocked), blocked
assert any(b["target"] == "api.pay.test:443" and "TLS" in b["reason"] for b in blocked), blocked
assert not any("pay.test" in h and "control" not in h for h in r["network"]["allowed"]), r["network"]["allowed"]
EOS
echo "== airbag log (net.simulated rows)"
"$AIRBAG" log | grep "net.simulated" || fail "no net.simulated rows in the log"
"$AIRBAG" log --json | grep -q '"kind":"net.simulated","target":"POST api.pay.test/v1/charges","verdict":"allow","reason":"charge"' || fail "log --json lacks the charge row"
"$AIRBAG" log --json | grep -q "amount=100" && fail "a request body reached the log"
"$AIRBAG" discard --yes >/dev/null

# A repository cannot simulate.
printf 'simulate:\n  - match: {host: api.anthropic.com}\n    respond: {body: hi}\n' >airbag.yaml
"$AIRBAG" run -- true >"$T/out2" 2>&1 && fail "a repository's stubs were accepted"
grep -q "a repository must not decide" "$T/out2" || fail "unexpected error: $(cat "$T/out2")"
rm airbag.yaml

# A real agent: Claude Code with test/mockapi as its model, whose one
# tool call charges through the stubbed API.
# The model's log is read from the branch of ~, which macOS has not.
if ! command -v claude >/dev/null || [ "$(uname -s)" != Linux ]; then
	echo "SKIP agent: claude not in PATH, or not Linux"
	echo PASS
	exit 0
fi
(cd "$REPO" && CGO_ENABLED=0 go build -o "$T/mockapi" ./test/mockapi)
cat >"$T/calls.json" <<'JSON'
[{"name":"Bash","input":{"command":"curl -sS -X POST -d amount=100 https://api.pay.test/v1/charges","description":"charge the card"}}]
JSON
: >"$E/trap.log"
to=
command -v timeout >/dev/null && to="timeout 300"
# shellcheck disable=SC2086 # $to is a command and its argument, or nothing
HTTPS_PROXY="http://127.0.0.1:$TRAPPORT" $to "$AIRBAG" run --simulate "$T/stubs/stubs.yaml" -- sh -c "'$T/mockapi' -addr 127.0.0.1:8097 -script '$T/calls.json' -log '$T/model.log' 2>/dev/null & sleep 0.5;
  DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  ANTHROPIC_BASE_URL=http://127.0.0.1:8097 ANTHROPIC_API_KEY=sk-ant-mock \
  claude -p 'charge the card' --dangerously-skip-permissions </dev/null" >"$T/agent.out" 2>&1 || fail "agent run: $(cat "$T/agent.out")"
rev=$("$AIRBAG" review)
id=$(echo "$rev" | head -1 | awk '{print $2}')
log="${AIRBAG_HOME:-/var/tmp/airbag-$(id -u)}/$id/home/upper/${T#"$HOME"/}/model.log"
[ -s "$log" ] || fail "no model log at $log"
grep -q 'ch_sim_1' "$log" || fail "the model was not shown the stubbed answer: $(tail -c 2000 "$log")"
echo "== agent: what the model received from its tool call"
grep -o '.\{0,100\}ch_sim_1.\{0,60\}' "$log" | head -1
echo "$rev" | grep -qF "POST api.pay.test/v1/charges ×1  by charge" || fail "review of the agent's session lacks the simulated call:
$rev"
echo "$rev" | sed -n '/^Simulated/,/^$/p'
grep -iF "pay.test" "$E/trap.log" && fail "a simulated host was contacted in the agent's session: $(cat "$E/trap.log")"
"$AIRBAG" discard --yes >/dev/null
echo PASS
