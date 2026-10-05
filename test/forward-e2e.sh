#!/bin/sh
# tcp:// in allow: the agent reaches a service on this machine (a dev
# database, say) at 127.0.0.1:PORT in the sandbox; airbag relays, logs
# and applies policy; without the entry the port is closed.
set -eu

AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-forward-e2e.XXXXXX")
hsrv=
trap 'kill $srv $hsrv 2>/dev/null || true; rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(8)
while True:
    c, _ = s.accept(); c.sendall(b"pong:" + c.recv(64)); c.close()
' "$port" &
srv=$!
# One that answers once the client has finished sending (a half-close).
hport=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(8)
while True:
    c, _ = s.accept(); data = b""
    while True:
        b = c.recv(64)
        if not b:
            break
        data += b
    c.sendall(b"ack:" + data); c.close()
' "$hport" &
hsrv=$!
sleep 0.5

mkdir "$T/proj" && cd "$T/proj" && git init -q
probe="import socket
c = socket.socket(); c.settimeout(5)
try:
    c.connect(('127.0.0.1', $port)); c.sendall(b'ping'); print('got', c.recv(64).decode())
except OSError as e:
    print('refused', type(e).__name__)"

out=$("$AIRBAG" run -- python3 -c "$probe" 2>/dev/null)
echo "$out" | grep -q refused || fail "the port was open without tcp://: $out"
"$AIRBAG" discard --yes >/dev/null

out=$("$AIRBAG" run --allow "tcp://127.0.0.1:$port" -- python3 -c "$probe" 2>/dev/null)
echo "$out" | grep -q "got pong:ping" || fail "forward did not relay: $out"
"$AIRBAG" log | grep -q "net.tcp.*allow.*127.0.0.1:$port" || fail "connection not logged: $("$AIRBAG" log)"
"$AIRBAG" review | grep -q "127.0.0.1" || fail "review lacks the connection"
"$AIRBAG" discard --yes >/dev/null

# A half-close passes through the sandbox's bridge and airbag's relay:
# the agent finishes sending, and the answer still comes back.
half="import socket
c = socket.socket(); c.settimeout(5)
c.connect(('127.0.0.1', $hport)); c.sendall(b'ping'); c.shutdown(socket.SHUT_WR)
print('got', c.recv(64).decode())"
out=$("$AIRBAG" run --allow "tcp://127.0.0.1:$hport" -- python3 -c "$half" 2>/dev/null)
echo "$out" | grep -q "got ack:ping" || fail "the answer after a half-close did not come back: $out"
"$AIRBAG" discard --yes >/dev/null

# Policy applies to forwarded connections too.
printf 'allow: ["tcp://127.0.0.1:%s"]\nrules:\n  - name: no-db\n    when: effect.kind == "net.connect" && effect.detail == "%s"\n    verdict: deny\n' "$port" "$port" > airbag.yaml
out=$("$AIRBAG" run -- python3 -c "$probe" 2>/dev/null)
echo "$out" | grep -q "got pong" && fail "a denied forward relayed: $out"
"$AIRBAG" log | grep -q "net.tcp.*deny.*no-db" || fail "denied forward not logged: $("$AIRBAG" log)"
"$AIRBAG" discard --yes >/dev/null
echo PASS
