#!/bin/sh
# apply --branch: the agent's result lands on a new branch of the real
# repository; the working tree, the index, .git/config and hooks stay as
# the user left them, including the user's own uncommitted edits.
set -eu

AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-branch-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main
git config user.email e2e@example.com && git config user.name e2e
printf 'one\n' > a.txt && printf 'gone\n' > old.txt && printf 'dist/\n' > .gitignore
git add -A && git commit -qm init
base=$(git rev-parse HEAD)
# The user keeps working while the agent runs: an uncommitted edit.
printf 'user edit\n' > mine.txt

cat > "$T/agent.sh" <<'EOS'
printf 'two\n' > a.txt
git add a.txt && git -c user.email=agent@example.com -c user.name=agent commit -qm "agent: a.txt"
printf 'later\n' > b.txt
rm old.txt
mkdir -p dist && printf 'built\n' > dist/app.js
printf '#!/bin/sh\ntouch hook-ran\n' > .git/hooks/pre-push && chmod +x .git/hooks/pre-push
git config core.sshCommand 'touch ssh-ran; ssh'
git push origin main 2>/dev/null || true
exit 0
EOS
"$AIRBAG" run -- sh "$T/agent.sh" >/dev/null 2>&1

out=$("$AIRBAG" apply --branch agent-work)
echo "$out" | grep -q "Branch agent-work" || fail "no branch made: $out"
echo "$out" | grep -q "1 commits by the agent" || fail "agent commit not counted: $out"

# The real working tree, index and config are as the user left them.
[ "$(git rev-parse HEAD)" = "$base" ] || fail "HEAD moved"
[ "$(cat a.txt)" = one ] || fail "a.txt changed in the working tree"
[ -f old.txt ] || fail "old.txt deleted in the working tree"
[ ! -e b.txt ] || fail "b.txt appeared in the working tree"
[ "$(cat mine.txt)" = "user edit" ] || fail "the user's edit changed"
[ -z "$(git diff --cached --name-only)" ] || fail "the index changed"
[ ! -e .git/hooks/pre-push ] || fail "the agent's hook reached .git/hooks"
[ -z "$(git config core.sshCommand || true)" ] || fail "the agent's git config reached .git/config"

# The branch holds the agent's commit and then what it left uncommitted.
[ "$(git log --format=%an -1 agent-work~1)" = agent ] || fail "the agent's commit is not on the branch"
[ "$(git rev-parse agent-work~2)" = "$base" ] || fail "branch does not start at the base"
[ "$(git show agent-work:a.txt)" = two ] || fail "a.txt on the branch"
[ "$(git show agent-work:b.txt)" = later ] || fail "b.txt on the branch"
git cat-file -e agent-work:old.txt 2>/dev/null && fail "old.txt still on the branch"
git cat-file -e agent-work:dist/app.js 2>/dev/null && fail "an ignored file went onto the branch"
git cat-file -e agent-work:mine.txt 2>/dev/null && fail "the user's uncommitted file went onto the branch"

# The queued push names the agent's branch, not this one: it waits.
echo "$out" | grep -q "left pending: the session's work is on branch agent-work" || fail "push not held: $out"
[ ! -e hook-ran ] && [ ! -e ssh-ran ] || fail "the agent's hook or ssh command ran on the host"
"$AIRBAG" apply --branch agent-work 2>&1 | grep -q "already exists" || fail "a second --branch did not refuse"
echo PASS
