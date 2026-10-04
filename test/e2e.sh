#!/bin/sh
# End-to-end check: an "agent" wrecks a repo, writes to ~, commits,
# pushes and calls the network. Nothing may reach the real world until
# `airbag apply`. Run as a regular user on a machine where
# `airbag doctor` passes.
set -eu

AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-e2e.XXXXXX")
trap 'rm -rf "$T" "$HOME/.airbag-e2e-rc"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

git init -q --bare "$T/remote.git"
mkdir "$T/proj" && cd "$T/proj"
git init -q -b main
git config user.email e2e@example.com && git config user.name e2e
echo hello > README.md && echo bye > old.txt
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
git add -A && git commit -qm "agent work"
git push origin main
curl -s --unix-socket /run/airbag/ctl.sock -d '{"kind":"git.push","argv":["rm","-rf","/"]}' http://x/intent | grep -q "only" || echo "LEAK: forged intent accepted"
git push --receive-pack='touch /tmp/pwn' origin main 2>&1 | grep -q "not allowed" || echo "LEAK: --receive-pack accepted"
curl -s -o /dev/null --max-time 10 https://example.com && echo "LEAK: example.com reachable"
ls /run | grep -q airbag || echo "LEAK: host /run visible"
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
for want in "~ README.md" "+ new.txt" "- old.txt" ".git/hooks/post-checkout  persist" "~/.airbag-e2e-rc" "denied: example.com:443" "git push origin main"; do
	echo "$rev" | grep -qF -- "$want" || fail "review lacks '$want':
$rev"
done

applied=$("$AIRBAG" apply --yes)
echo "$applied" | grep -q "left pending" || fail "intent ran under --yes although the agent added a git hook: $applied"
[ "$(cat README.md)" = changed ] || fail "README not applied"
[ ! -f old.txt ] || fail "old.txt not deleted"
grep -q evil "$HOME/.airbag-e2e-rc" || fail "~ change not applied"
[ "$(git -C "$T/remote.git" rev-parse main)" = "$before" ] || fail "remote changed before the intent was confirmed"
printf 'y\n' | "$AIRBAG" apply >/dev/null
[ "$(git -C "$T/remote.git" rev-parse main)" = "$(git rev-parse HEAD)" ] || fail "push intent did not run"
# The agent may not create user namespaces unless the session allows it.
if command -v unshare >/dev/null; then
	probe='unshare -Ur true 2>/dev/null && echo nested-allowed || echo nested-refused'
	out=$("$AIRBAG" run -- sh -c "$probe" 2>/dev/null)
	echo "$out" | grep -q nested-refused || fail "the agent created a user namespace: $out"
	"$AIRBAG" discard --yes >/dev/null
	out=$("$AIRBAG" run --allow-userns -- sh -c "$probe" 2>/dev/null)
	echo "$out" | grep -q nested-allowed || fail "--allow-userns did not allow user namespaces: $out"
	"$AIRBAG" discard --yes >/dev/null
fi
echo "PASS"
