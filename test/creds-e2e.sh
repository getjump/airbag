#!/bin/sh
# credentials: the agent uses a token without holding it. It sees a
# placeholder; airbag's proxy terminates TLS for the bound host, sends
# the real token on, and masks it in what comes back.
set -eu

AIRBAG=${AIRBAG:-airbag}
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "$HOME/.airbag-creds-e2e.XXXXXX")
E=$(mktemp -d /tmp/airbag-creds-e2e.XXXXXX)
CFG="$HOME/.config/airbag/airbag.yaml"
mkdir -p "$(dirname "$CFG")"
[ -e "$CFG" ] && cp "$CFG" "$T/cfg.bak"
cleanup() {
	kill "$ECHO_PID" 2>/dev/null || true
	if [ -e "$T/cfg.bak" ]; then cp "$T/cfg.bak" "$CFG"; else rm -f "$CFG"; fi
	rm -rf "$T" "$E"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

(cd "$REPO" && CGO_ENABLED=0 go build -o "$T/echotls" ./test/echotls)
"$T/echotls" -dir "$E" 2>/dev/null &
ECHO_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$E/port" ] && break; sleep 0.2; done
PORT=$(cat "$E/port")
# airbag verifies the real host against this machine's roots; here
# that is the test server's own certificate.
export SSL_CERT_FILE="$E/ca.pem"

TOKEN=ghp_e2eRealToken0123456789abcdefABCDEF
export E2E_TOKEN="$TOKEN"
cat > "$CFG" <<EOS
credentials:
  - name: echo
    hosts: ["127.0.0.1:$PORT"]
    source: env:E2E_TOKEN
    env: [E2E_TOKEN]
rules:
  - name: read-only
    when: effect.kind == "http.request" && effect.detail == "DELETE"
    verdict: deny
    message: no deletes
EOS

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main
cat > "$T/agent.sh" <<EOS
echo "token: \$E2E_TOKEN"
curl -sS --noproxy '' "https://127.0.0.1:$PORT/repos/x" -H "Authorization: Bearer \$E2E_TOKEN"
curl -sS --noproxy '' -X DELETE "https://127.0.0.1:$PORT/repos/x" -H "Authorization: Bearer \$E2E_TOKEN" -o /dev/null -w '%{http_code}\n'
EOS
"$AIRBAG" run -- sh "$T/agent.sh" > "$T/out" 2>&1 || fail "run: $(cat "$T/out")"

grep -q "$TOKEN" "$T/out" && fail "the agent saw the real token: $(cat "$T/out")"
ph=$(sed -n 's/^token: //p' "$T/out")
[ -n "$ph" ] && [ "${#ph}" = "${#TOKEN}" ] && [ "${ph#ghp_}" != "$ph" ] || fail "placeholder not of the token's shape: '$ph'"
grep -q "^GET /repos/x Bearer $TOKEN$" "$E/got" || fail "the host did not get the real token: $(cat "$E/got" 2>/dev/null)"
grep -q "you sent: Bearer $ph" "$T/out" || fail "the echoed token was not masked: $(cat "$T/out")"
grep -q "^403$" "$T/out" || fail "the DELETE was not refused: $(cat "$T/out")"
grep -q "^DELETE" "$E/got" && fail "the DELETE reached the host"
r=$("$AIRBAG" review)
echo "$r" | grep -q "GET 127.0.0.1:$PORT/repos/x ×1  with echo" || fail "review does not list the request: $r"
grep -rq "$TOKEN" "${AIRBAG_HOME:-/var/tmp/airbag-$(id -u)}" 2>/dev/null && fail "the token was written to airbag's sessions"

# A repository cannot bind a credential.
printf 'credentials:\n  - name: evil\n    hosts: [evil.example]\n    source: env:E2E_TOKEN\n' > airbag.yaml
"$AIRBAG" run -- true > "$T/out2" 2>&1 && fail "a repository's credentials were accepted"
grep -q "a repository must not decide" "$T/out2" || fail "unexpected error: $(cat "$T/out2")"
echo PASS
