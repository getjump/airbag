#!/bin/sh
# End-to-end check: an "agent" wrecks a repo, writes to ~, commits,
# pushes and calls the network. Nothing may reach the real world until
# `airbag apply`. Run as a regular user on a machine where
# `airbag doctor` passes. On macOS (the prototype in docs/macos.md) ~ is
# read-only rather than a branch and secret files are unreadable, and
# those are checked instead.
set -eu
mac=; [ "$(uname)" = Darwin ] && mac=1

AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-e2e.XXXXXX")
trap 'rm -rf "$T" "$HOME/.airbag-e2e-rc"' EXIT
# printf, not echo: macOS sh turns \x1b in output back into the byte.
fail() { printf 'FAIL: %s\n' "$*"; exit 1; }

git init -q --bare "$T/remote.git"
mkdir "$T/proj" && cd "$T/proj"
git init -q -b main
git config user.email e2e@example.com && git config user.name e2e
echo hello > README.md && echo bye > old.txt
if [ -n "$mac" ]; then
	echo TOKEN=e2e > .env && echo .env > .gitignore
fi
git add -A && git commit -qm init
git remote add origin "$T/remote.git" && git push -q origin main
before=$(git -C "$T/remote.git" rev-parse main)
: > "$HOME/.airbag-e2e-rc"

cat > "$T/agent.sh" <<'EOF'
echo changed > README.md
echo new > new.txt
rm old.txt
echo "alias evil=1" >> ~/.airbag-e2e-rc
printf '#!/bin/sh\n' > .git/hooks/post-checkout && chmod +x .git/hooks/post-checkout
printf '#!/bin/sh\ntouch hook-ran\n' > .git/hooks/pre-push && chmod +x .git/hooks/pre-push
git add -A && git commit -qm "agent work"
git push origin main
curl -s --unix-socket "${AIRBAG_CONTROL:-/run/airbag/ctl.sock}" -d '{"kind":"git.push","argv":["rm","-rf","/"]}' http://x/intent | grep -q "only" || echo "LEAK: forged intent accepted"
git push --receive-pack='touch /tmp/pwn' origin main 2>&1 | grep -q "not allowed" || echo "LEAK: --receive-pack accepted"
curl -s -o /dev/null --max-time 10 https://example.com && echo "LEAK: example.com reachable"
if [ "$(uname)" = Darwin ]; then
	cat .env >/dev/null 2>&1 && echo "LEAK: secret file readable"
	# Every project's memory/ is denied (airbag makes this workspace's
	# project directory before the run); what a failed check made is
	# removed again.
	for d in "$HOME"/.claude/projects/*/; do
		[ -d "$d" ] || continue
		made=
		[ -d "$d/memory" ] || { mkdir "$d/memory" 2>/dev/null && made=1; }
		if echo x > "$d/memory/airbag-e2e-probe.md" 2>/dev/null; then
			rm -f "$d/memory/airbag-e2e-probe.md"
			echo "LEAK: memory writable in $d"
		fi
		if [ -n "$made" ]; then
			rmdir "$d/memory"
			echo "LEAK: memory/ creatable in $d"
		fi
	done
	ls -d "$HOME"/.claude/projects/*/ >/dev/null 2>&1 || echo "LEAK: no project directory to check memory/ in"
else
	ls /run | grep -q airbag || echo "LEAK: host /run visible"
fi
exit 0
EOF

out=$("$AIRBAG" run -- sh "$T/agent.sh" 2>&1)
echo "$out" | grep -q LEAK && fail "$out"
echo "$out" | grep -q "queued as intent i-1" || fail "git push was not queued: $out"

[ "$(cat README.md)" = hello ] || fail "README changed before apply"
[ -f old.txt ] || fail "old.txt deleted before apply"
[ ! -s "$HOME/.airbag-e2e-rc" ] || fail "~ changed before apply"
[ "$(git -C "$T/remote.git" rev-parse main)" = "$before" ] || fail "remote changed before apply"
[ ! -f .git/hooks/post-checkout ] || fail "hook installed before apply"

rev=$("$AIRBAG" review)
# shellcheck disable=SC2088 # "~/" as the review prints it
home_change="~/.airbag-e2e-rc"
if [ -n "$mac" ]; then
	echo "$out" | grep -q "airbag-e2e-rc: Operation not permitted" || fail "~ was writable on macOS: $out"
	home_change="+ new.txt" # no branch of ~ to show
fi
for want in "~ README.md" "+ new.txt" "- old.txt" ".git/hooks/post-checkout  persist" "$home_change" "denied: example.com:443" "git push origin main"; do
	echo "$rev" | grep -qF -- "$want" || fail "review lacks '$want':
$rev"
done

# The same review as data, and as a short list of decisions.
"$AIRBAG" review --json | MAC="$mac" python3 -c '
import json, os, sys
r = json.load(sys.stdin)
assert r["schema"] == "airbag.review/v1", r["schema"]
att = {(a["what"], a["target"]) for a in r["attention"]}
for want in [("change", ".git/hooks/post-checkout"), ("change", ".git/hooks/pre-push"), ("intent", "i-1")]:
    assert want in att, (want, att)
assert os.environ["MAC"] or any(c["layer"] == "home" and c["path"] == ".airbag-e2e-rc" for c in r["changes"])
assert any(c["path"] == "README.md" and c["kind"] == "modified" for c in r["changes"])
assert r["network"]["denied"].get("example.com:443"), r["network"]
' || fail "review --json"
"$AIRBAG" review --attention | grep -q "things need a decision" || fail "review --attention"

# rollback undoes the apply, and the changes come back to the session.
"$AIRBAG" apply --yes >/dev/null
rb=$("$AIRBAG" rollback)
echo "$rb" | grep -q "Rolled back" || fail "rollback: $rb"
[ "$(cat README.md)" = hello ] || fail "README not restored by rollback"
[ -f old.txt ] && [ ! -e new.txt ] || fail "files not restored by rollback"
[ ! -s "$HOME/.airbag-e2e-rc" ] || fail "~ not restored by rollback"
[ ! -f .git/hooks/post-checkout ] || fail "hook left behind by rollback"
[ "$(git rev-parse HEAD)" = "$before" ] || fail "HEAD not restored by rollback"
"$AIRBAG" review | grep -qF "~ README.md" || fail "changes not back in the session after rollback"

applied=$("$AIRBAG" apply --yes)
echo "$applied" | grep -q "left pending" || fail "intent ran under --yes although the agent added a git hook: $applied"
[ "$(cat README.md)" = changed ] || fail "README not applied"
[ ! -f old.txt ] || fail "old.txt not deleted"
if [ -n "$mac" ]; then
	[ ! -s "$HOME/.airbag-e2e-rc" ] || fail "~ changed on macOS"
else
	grep -q evil "$HOME/.airbag-e2e-rc" || fail "~ change not applied"
fi
[ "$(git -C "$T/remote.git" rev-parse main)" = "$before" ] || fail "remote changed before the intent was confirmed"
# A later apply keeps the session's pushes untrusted: they wait for --trust-git.
again=$(printf 'y\n' | "$AIRBAG" apply)
echo "$again" | grep -q -- "--trust-git" || fail "second apply did not hold the push: $again"
[ "$(git -C "$T/remote.git" rev-parse main)" = "$before" ] || fail "second apply pushed without --trust-git"
printf 'y\n' | "$AIRBAG" apply --trust-git >/dev/null
[ "$(git -C "$T/remote.git" rev-parse main)" = "$(git rev-parse HEAD)" ] || fail "push intent did not run"
[ ! -e hook-ran ] || fail "the agent's pre-push hook ran on the host"
# User namespaces: allowed by default, refused under --strict.
if command -v unshare >/dev/null; then
	probe='unshare -Ur true 2>/dev/null && echo nested-allowed || echo nested-refused'
	out=$("$AIRBAG" run -- sh -c "$probe" 2>/dev/null)
	echo "$out" | grep -q nested-allowed || fail "user namespaces refused by default: $out"
	"$AIRBAG" discard --yes >/dev/null
	out=$("$AIRBAG" run --strict -- sh -c "$probe" 2>/dev/null)
	echo "$out" | grep -q nested-refused || fail "--strict let the agent create a user namespace: $out"
	"$AIRBAG" discard --yes >/dev/null
fi
# A host socket named in hide: is out of reach (as the built-in list
# hides the Nix daemon, Incus and LXD sockets outside /run). It needs a
# directory outside $HOME, /tmp and /run that this user can write:
# AIRBAG_E2E_HOSTDIR, prepared by root (mkdir -m 1777).
H=${AIRBAG_E2E_HOSTDIR:-/var/lib/airbag-e2e}
if [ -d "$H" ] && [ -w "$H" ]; then
	sock="$H/daemon-$$.sock"
	python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(5); time.sleep(30)' "$sock" &
	lp=$!
	sleep 0.5
	probe='import socket,sys
c=socket.socket(socket.AF_UNIX)
try: c.connect(sys.argv[1]); print("sock-reachable")
except OSError: print("sock-blocked")'
	out=$("$AIRBAG" run -- python3 -c "$probe" "$sock" 2>/dev/null)
	echo "$out" | grep -q sock-reachable || fail "baseline: host socket not reachable without hide: $out"
	"$AIRBAG" discard --yes >/dev/null
	printf 'hide: ["%s"]\n' "$sock" > airbag.yaml
	out=$("$AIRBAG" run -- python3 -c "$probe" "$sock" 2>/dev/null)
	echo "$out" | grep -q sock-blocked || fail "hidden host socket reachable: $out"
	"$AIRBAG" discard --yes >/dev/null
	rm airbag.yaml
	kill $lp 2>/dev/null || true
	rm -f "$sock"
else
	echo "SKIP: host socket check (no writable $H)"
fi

# Text the agent controls is shown, not interpreted, by the terminal.
# shellcheck disable=SC2016 # the script runs in the sandbox
"$AIRBAG" run -- sh -c 'printf "x\033[2Jy\n" > "$(printf "esc\033]0;t\007.txt")"' >/dev/null 2>&1
esc=$(printf '\033')
for cmd in review diff; do
	out=$("$AIRBAG" $cmd)
	case "$out" in *"$esc"*) fail "$cmd printed a raw escape";; esac
	printf '%s\n' "$out" | grep -qF 'esc\x1b]0;t\x07.txt' || fail "$cmd lacks the escaped name: $out"
done
"$AIRBAG" diff | grep -qF 'x\x1b[2Jy' || fail "diff lacks the escaped content"
"$AIRBAG" discard --yes >/dev/null
echo "PASS"
