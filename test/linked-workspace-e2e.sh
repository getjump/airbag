#!/bin/sh
# A workspace named through a link: its secret files are behind secretfs
# (Linux, needs /dev/fuse) or out of reach (macOS) as in any other
# workspace, and the agent works on a branch, not on the real files.
set -eu
AIRBAG=${AIRBAG:-airbag}
mac=; [ "$(uname)" = Darwin ] && mac=1
[ -n "$mac" ] || [ -w /dev/fuse ] || { echo "SKIP: /dev/fuse not writable"; exit 0; }
T=$(mktemp -d "$HOME/.airbag-linked-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
# printf, not echo: macOS sh turns \x1b in output back into the byte.
fail() { printf 'FAIL: %s\n' "$*"; exit 1; }

mkdir "$T/real"
printf 'API_TOKEN=sk-linked-0123456789\n' > "$T/real/.env"
echo hi > "$T/real/README.md"
ln -s "$T/real" "$T/proj"
cd "$T/proj"

# Through the shell shim, which masks known secret values in output.
cat > "$T/agent.sh" <<'EOF2'
bash -c 'cat .env' > read.out 2>/dev/null || echo unreadable > read.out
echo agent > new.txt
EOF2
out=$("$AIRBAG" run -- sh "$T/agent.sh" 2>&1) || fail "run: $out"
[ ! -e "$T/real/new.txt" ] || fail "the agent wrote to the real files: $out"
[ ! -e "$T/real/read.out" ] || fail "the agent wrote to the real files: $out"
if [ -n "$mac" ]; then
	"$AIRBAG" diff read.out | grep -q unreadable || fail "the secret file was readable: $("$AIRBAG" diff read.out)"
else
	"$AIRBAG" log | grep 'secret.read' | grep -q '\.env' || fail "reading .env was not recorded: $("$AIRBAG" log)"
	"$AIRBAG" diff read.out | grep -q 'sk-linked-0123456789' && fail "secret not masked: $("$AIRBAG" diff read.out)"
fi
"$AIRBAG" discard --yes >/dev/null
[ "$(cat "$T/real/.env")" = "API_TOKEN=sk-linked-0123456789" ] || fail ".env changed"
echo PASS
