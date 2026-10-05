#!/bin/sh
# The real Codex CLI inside airbag, driven by test/mockapi's Responses
# API stand-in. Checks: managed hooks from /etc/codex/requirements.toml
# attribute changes to tool calls (Codex reports exec_command as Bash)
# and carry policy denies, Codex state folds into one review line,
# git push is queued, the requirements file is read-only for the agent.
set -eu
AIRBAG=${AIRBAG:-airbag}
command -v codex >/dev/null || { echo "SKIP: codex not in PATH"; exit 0; }
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "$HOME/.airbag-codex-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

(cd "$REPO" && CGO_ENABLED=0 go build -o "$T/mockapi" ./test/mockapi)
git init -q --bare "$T/remote.git"
mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hello > README.md
printf 'rules:\n  - name: no-marker\n    when: command.line.contains("forbidden-marker")\n    verdict: deny\n' > airbag.yaml
git add -A && git commit -qm init
git remote add origin "$T/remote.git" && git push -q origin main

cat > "$T/calls.json" <<'JSON'
[
 {"name":"exec_command","input":{"cmd":"echo from-codex > codex.txt"}},
 {"name":"exec_command","input":{"cmd":"(echo x >> /etc/codex/requirements.toml && echo WRITABLE || echo RO) > ro.txt 2>/dev/null"}},
 {"name":"exec_command","input":{"cmd":"echo forbidden-marker > marker.txt"}},
 {"name":"exec_command","input":{"cmd":"git add -A && git commit -qm 'codex work' && git push origin main"}}
]
JSON

"$AIRBAG" run -- sh -c "'$T/mockapi' -addr 127.0.0.1:8099 -script '$T/calls.json' -log '$T/model.log' 2>/dev/null & sleep 0.5;
  OPENAI_API_KEY=sk-mock codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox \
  -c model_provider=mock -c model_providers.mock.name=mock -c model_providers.mock.base_url=http://127.0.0.1:8099/v1 \
  -c model_providers.mock.wire_api=responses -c model_providers.mock.env_key=OPENAI_API_KEY -m mock-model \
  'do the task' </dev/null" >"$T/out" 2>&1 || { cat "$T/out"; fail "airbag run failed"; }

[ ! -e codex.txt ] || fail "codex.txt reached the real workspace"
rev=$("$AIRBAG" review)
# shellcheck disable=SC2088 # "~/" as the review prints it
for want in "3 tool calls" "Bash   echo from-codex > codex.txt" "~/.codex/… (agent state, not applied)" "+codex.txt" "git push origin main"; do
	echo "$rev" | grep -qF -- "$want" || fail "review lacks '$want':
$rev"
done
"$AIRBAG" diff ro.txt | grep -q "^+RO" || fail "requirements.toml was writable for the agent"
id=$(echo "$rev" | head -1 | awk '{print $2}')
log="${AIRBAG_HOME:-/var/tmp/airbag-$(id -u)}/$id/home/upper/${T#"$HOME"/}/model.log"
[ -s "$log" ] || fail "no model log at $log"
grep -q 'blocked by policy' "$log" || fail "the PreToolUse deny did not reach the model"
echo "$rev" | grep -q "^  + marker.txt" && fail "a command denied by policy ran"
"$AIRBAG" discard --yes >/dev/null
echo "PASS"
