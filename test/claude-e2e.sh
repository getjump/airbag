#!/bin/sh
# The real Claude Code binary inside airbag, driven by test/mockapi, a
# scripted stand-in for the Messages API (no model, no credentials).
# Checks: hooks attribute changes to tool calls, git push from the Bash
# tool is queued, airbag's managed settings are read-only for the agent.
set -eu
AIRBAG=${AIRBAG:-airbag}
command -v claude >/dev/null || { echo "SKIP: claude not in PATH"; exit 0; }
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "$HOME/.airbag-claude-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

(cd "$REPO" && CGO_ENABLED=0 go build -o "$T/mockapi" ./test/mockapi)
git init -q --bare "$T/remote.git"
mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hello > README.md && git add -A && git commit -qm init
git remote add origin "$T/remote.git" && git push -q origin main

cat > "$T/calls.json" <<JSON
[
 {"name":"Bash","input":{"command":"echo from-claude > claude.txt","description":"write"}},
 {"name":"Write","input":{"file_path":"$T/proj/notes.md","content":"# notes\\n"}},
 {"name":"Bash","input":{"command":"(echo x > /etc/claude-code/managed-settings.d/90-airbag.json && echo WRITABLE || echo RO) > ro.txt 2>/dev/null","description":"tamper"}},
 {"name":"Bash","input":{"command":"git add -A && git commit -qm 'claude work' && git push origin main","description":"push"}}
]
JSON

"$AIRBAG" run -- sh -c "'$T/mockapi' -addr 127.0.0.1:8099 -script '$T/calls.json' 2>/dev/null & sleep 0.5;
  DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  ANTHROPIC_BASE_URL=http://127.0.0.1:8099 ANTHROPIC_API_KEY=sk-ant-mock \
  claude -p 'do the task' --dangerously-skip-permissions </dev/null" >/dev/null 2>&1

[ ! -e claude.txt ] || fail "claude.txt reached the real workspace"
rev=$("$AIRBAG" review)
for want in "4 tool calls" "Bash   echo from-claude > claude.txt" "+claude.txt" "Write" "+notes.md" "git push origin main"; do
	echo "$rev" | grep -qF -- "$want" || fail "review lacks '$want':
$rev"
done
"$AIRBAG" diff ro.txt | grep -q "^+RO" || fail "managed settings were writable for the agent"
"$AIRBAG" discard --yes >/dev/null
echo "PASS"
