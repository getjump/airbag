#!/bin/sh
# Execution boundary through the installed CLI: a requirement the backend
# cannot meet stops `run` before any session file exists, a saved one stops
# `run --session` before the session changes, `capabilities --json` parses,
# and a session reports the egress it really has (--nix-daemon). Nothing
# falls back.
set -eu

AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-isolation-e2e.XXXXXX")
# Sessions of their own, outside $HOME, so "no session was created" can be
# checked; the directory itself must not exist before the first real run.
R=$(mktemp -d /var/tmp/airbag-isolation.XXXXXX)
AIRBAG_HOME=$R/sessions
export AIRBAG_HOME
id='' id2='' id3='' id4=''
cleanup() {
	for s in $id $id2 $id3 $id4; do "$AIRBAG" discard --yes "$s" >/dev/null 2>&1 || true; done
	rm -rf "$T" "$R"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }
session_of() { sed -n 's/^airbag: session \(s-[0-9a-f]*\) .*/\1/p' "$1" | head -n 1; }
# Every entry of the session and every file's checksum. Overlayfs leaves
# work directories the user cannot list; their names still show.
snap() { (cd "$AIRBAG_HOME/$id" && { find . 2>/dev/null || true; } | LC_ALL=C sort &&
	{ find . -type f -exec cksum {} + 2>/dev/null || true; } | LC_ALL=C sort); }

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main
echo base > notes.txt

"$AIRBAG" capabilities --json > "$T/caps.json" || fail "capabilities --json failed"
python3 - "$T/caps.json" <<'EOF' || fail "capabilities --json: $(cat "$T/caps.json")"
import json, sys
b = json.load(open(sys.argv[1]))
assert b["schema"] == 1 and b["name"] == "native" and b["isolation"] == "shared-kernel", b
assert b["egress"] == "allowlist-proxy", b
assert any("--nix-daemon" in l for l in b["limitations"]), b
EOF
[ ! -e "$AIRBAG_HOME" ] || fail "capabilities created session files"

# Each refusal for its own reason: an unknown flag exits 2 as well.
while IFS='|' read -r flag reason; do
	code=0
	"$AIRBAG" run "$flag" -- true </dev/null >"$T/out" 2>&1 || code=$?
	[ "$code" = 2 ] || fail "run $flag exited $code: $(cat "$T/out")"
	grep -qF -- "$reason" "$T/out" || fail "run $flag was not refused for \"$reason\": $(cat "$T/out")"
	[ ! -e "$AIRBAG_HOME" ] || fail "run $flag created session files: $(cat "$T/out")"
done <<'REFUSALS'
--require-isolation=virtual-machine|but virtual-machine was required (no fallback)
--require-isolation=application-kernel|but application-kernel was required (no fallback)
--require-isolation=typo|unknown isolation requirement "typo"
--backend=microvm|execution backend "microvm" is unavailable
--backend=typo|execution backend "typo" is unavailable
REFUSALS

"$AIRBAG" run --require-isolation=shared-kernel -- sh -c 'echo run1 >> notes.txt' >"$T/out" 2>&1 ||
	fail "a met requirement was refused: $(cat "$T/out")"
grep -q "isolation shared-kernel · egress allowlist-proxy$" "$T/out" ||
	fail "run did not report its boundary: $(cat "$T/out")"
id=$(session_of "$T/out")
[ -n "$id" ] || fail "no session in: $(cat "$T/out")"
meta=$AIRBAG_HOME/$id/meta.json
grep -q '"require_isolation": "shared-kernel"' "$meta" || fail "requirement not saved: $(cat "$meta")"
grep -q '"egress": "allowlist-proxy"' "$meta" || fail "egress not saved: $(cat "$meta")"

# An unmet requirement on resume.
before=$(snap)
code=0
"$AIRBAG" run --session "$id" --require-isolation=virtual-machine -- true >"$T/out" 2>&1 || code=$?
[ "$code" != 0 ] || fail "resume met an unmet requirement: $(cat "$T/out")"
[ "$(snap)" = "$before" ] || fail "a refused resume changed the session"

# A saved requirement this backend cannot meet, as a build with a VM backend
# would save it: resume with no flag must not drop it.
sed 's/"require_isolation": "shared-kernel"/"require_isolation": "virtual-machine"/' "$meta" > "$T/meta"
cat "$T/meta" > "$meta"
grep -q '"require_isolation": "virtual-machine"' "$meta" || fail "could not save the requirement"
before=$(snap)
code=0
"$AIRBAG" run --session "$id" -- true >"$T/out" 2>&1 || code=$?
[ "$code" != 0 ] || fail "resume discarded the saved requirement: $(cat "$T/out")"
grep -q virtual-machine "$T/out" || fail "refused for another reason: $(cat "$T/out")"
[ "$(snap)" = "$before" ] || fail "a refused resume changed the session"

# The same session resumes once its requirement can be met: the refusal
# above was the requirement's.
sed 's/"require_isolation": "virtual-machine"/"require_isolation": "shared-kernel"/' "$meta" > "$T/meta"
cat "$T/meta" > "$meta"
"$AIRBAG" run --session "$id" -- true >"$T/out" 2>&1 || fail "resume refused: $(cat "$T/out")"
grep -q "resuming session $id (run 2)" "$T/out" || fail "not resumed: $(cat "$T/out")"
[ "$(cat notes.txt)" = base ] || fail "the real file changed before apply"

# A default run's output stays as it was: no boundary line.
"$AIRBAG" run -- true >"$T/out" 2>&1 || fail "default run: $(cat "$T/out")"
id3=$(session_of "$T/out")
! grep -q "^airbag: backend" "$T/out" || fail "a default run printed its boundary: $(cat "$T/out")"

# --nix-daemon: the daemon's builds reach the network outside the proxy,
# and the session says so.
"$AIRBAG" run --nix-daemon -- true >"$T/out" 2>&1 || fail "run --nix-daemon: $(cat "$T/out")"
id2=$(session_of "$T/out")
[ -n "$id2" ] || fail "no session in: $(cat "$T/out")"
grep -q "egress allowlist-proxy+nix-daemon$" "$T/out" || fail "run --nix-daemon reported proxy-only egress: $(cat "$T/out")"
grep -q '"egress": "allowlist-proxy+nix-daemon"' "$AIRBAG_HOME/$id2/meta.json" ||
	fail "session saved proxy-only egress: $(cat "$AIRBAG_HOME/$id2/meta.json")"

# A tcp:// forward is a path around the proxy: airbag dials HOST:PORT.
"$AIRBAG" run --allow tcp://127.0.0.1:47123 -- true >"$T/out" 2>&1 || fail "run with a forward: $(cat "$T/out")"
id4=$(session_of "$T/out")
[ -n "$id4" ] || fail "no session in: $(cat "$T/out")"
grep -q "egress allowlist-proxy+tcp-forward$" "$T/out" || fail "run with a forward reported proxy-only egress: $(cat "$T/out")"
grep -q '"egress": "allowlist-proxy+tcp-forward"' "$AIRBAG_HOME/$id4/meta.json" ||
	fail "session with a forward saved proxy-only egress: $(cat "$AIRBAG_HOME/$id4/meta.json")"
# A resume can add a forward: the session's egress says so from then on.
"$AIRBAG" run --session "$id" --allow tcp://127.0.0.1:47124 -- true >"$T/out" 2>&1 || fail "resume with a forward: $(cat "$T/out")"
grep -q "egress allowlist-proxy+tcp-forward$" "$T/out" || fail "resume with a forward reported proxy-only egress: $(cat "$T/out")"
grep -q '"egress": "allowlist-proxy+tcp-forward"' "$meta" || fail "resume with a forward saved proxy-only egress: $(cat "$meta")"
echo PASS
