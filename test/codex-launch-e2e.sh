#!/bin/sh
set -eu
[ "$(uname)" = Darwin ] || { echo "SKIP: named launchers require macOS"; exit 0; }
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-launch-e2e.XXXXXX")
AIRBAG_HOME=$(mktemp -d /var/tmp/airbag-launch-e2e.XXXXXX)
export AIRBAG_HOME
trap 'rm -rf "$T" "$AIRBAG_HOME"' EXIT
fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
mkdir "$T/bin" "$T/source" "$T/proj"
printf 'host-login\n' > "$T/source/auth.json"
printf 'host-required-mcp\n' > "$T/source/config.toml"
printf 'original\n' > "$T/proj/README.md"
cat > "$T/bin/codex" <<'SH'
#!/bin/sh
set -eu
[ "$1" = --no-daemon ]
[ "$2" = --dangerously-bypass-approvals-and-sandbox ]
shift 2
[ "$1" = -c ]
[ "$2" = allow_login_shell=false ]
shift 2
[ "$CODEX_HOME" != "$SOURCE_HOME" ]
[ "$(cat "$CODEX_HOME/config.toml")" = 'allow_login_shell = false' ]
if [ "$1" = first ]; then
    [ "$(cat "$CODEX_HOME/auth.json")" = host-login ]
    printf 'session-login\n' > "$CODEX_HOME/auth.json"
    printf 'kept\n' > "$CODEX_HOME/resume-state"
    printf 'changed\n' > README.md
    if (printf 'leak\n' > "$SOURCE_HOME/auth.json") 2>/dev/null; then exit 90; fi
    printf 'private-state-ok\n'
    exit 37
fi
[ "$1" = second ]
[ "$(cat "$CODEX_HOME/auth.json")" = session-login ]
[ "$(cat "$CODEX_HOME/resume-state")" = kept ]
[ "$(cat README.md)" = changed ]
printf 'resume-ok\n'
SH
chmod +x "$T/bin/codex"
export PATH="$T/bin:$PATH" CODEX_HOME="$T/source" SOURCE_HOME="$T/source"
cd "$T/proj"
git init -q -b main
git config user.email e2e@example.com
git config user.name e2e
git add README.md
git commit -qm init
code=0
"$AIRBAG" codex yolo /usr/bin/true > "$T/out" 2>&1 || code=$?
[ "$code" = 2 ] || { cat "$T/out"; fail "malformed launcher exited $code, want 2"; }
[ ! -e "$AIRBAG_HOME/last" ] || fail "malformed launcher created a session"
code=0
"$AIRBAG" codex yolo --allow-trustd=false -- first > "$T/out" 2>&1 || code=$?
[ "$code" = 37 ] || { cat "$T/out"; fail "exit $code, want 37"; }
grep -q private-state-ok "$T/out" || fail "private state check did not run"
[ "$(cat README.md)" = original ] || fail "host workspace changed"
[ "$(cat "$T/source/auth.json")" = host-login ] || fail "host login changed"
"$AIRBAG" review --json > "$T/review.json"
python3 - "$T/review.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
assert any(c['path'] == 'README.md' and c['kind'] == 'modified' for c in r['changes']), r
assert not any(c['layer'] == 'home' for c in r['changes']), r
PY
"$AIRBAG" codex yolo --session last -- second > "$T/out" 2>&1 || { cat "$T/out"; fail resume; }
grep -q resume-ok "$T/out" || fail "resume check did not run"
! grep -q "egress .*trustd" "$T/out" || fail "resume widened trustd access"
"$AIRBAG" discard --yes > /dev/null
echo PASS
