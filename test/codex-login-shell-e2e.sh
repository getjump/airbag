#!/bin/sh
# Codex model shell tools must not run login shells under airbag: a login
# profile that rebuilds PATH would put the real git ahead of the shims, and
# the model's git push would skip the outbox. airbag's managed
# /etc/codex/requirements.toml sets allow_login_shell = false. The profile
# is written inside the session (the branch of $HOME), never on the host.
set -eu
AIRBAG=${AIRBAG:-airbag}
[ "$(uname)" = Linux ] || { echo "SKIP: managed Codex settings are Linux-only"; exit 0; }
command -v codex >/dev/null || { echo "SKIP: codex not in PATH"; exit 0; }
[ ! -e /etc/codex/requirements.toml ] || { echo "SKIP: the host has its own /etc/codex/requirements.toml, which airbag keeps"; exit 0; }
real_git=$(command -v git)
git_dir=$(dirname "$real_git")
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "$HOME/.airbag-codex-login-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

(cd "$REPO" && CGO_ENABLED=0 go build -o "$T/mockapi" ./test/mockapi)
git init -q --bare "$T/remote.git"
mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hello > README.md
git add -A && git commit -qm init
git remote add origin "$T/remote.git" && git push -q origin main
before=$(git -C "$T/remote.git" rev-parse main)

cat > "$T/calls.json" <<'JSON'
[
 {"name":"exec_command","input":{"cmd":"command -v git > model-git.txt; git commit -q --allow-empty -m login && git push origin main"}}
]
JSON

# Inside the session, before Codex starts (so a shell snapshot taken at
# startup sees it too): a login profile that resets PATH, and controls that
# show a login shell finds the real git while a nonlogin one finds the shim.
"$AIRBAG" run -- sh -c "printf 'export PATH=$git_dir:/bin\n' >> \"\$HOME/.bash_profile\";
  printf 'export PATH=$git_dir:/bin\n' >> \"\$HOME/.profile\";
  bash -lc 'command -v git' > login-git.txt; command -v git > shim-git.txt;
  '$T/mockapi' -addr 127.0.0.1:8098 -script '$T/calls.json' -log '$T/model.log' 2>/dev/null & sleep 0.5;
  OPENAI_API_KEY=sk-mock SHELL=/bin/bash codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox \
  -c model_provider=mock -c model_providers.mock.name=mock -c model_providers.mock.base_url=http://127.0.0.1:8098/v1 \
  -c model_providers.mock.wire_api=responses -c model_providers.mock.env_key=OPENAI_API_KEY -m mock-model \
  'do the task' </dev/null" >"$T/out" 2>&1 || { cat "$T/out"; fail "airbag run failed"; }

# Negative control: without the setting the profile would win.
"$AIRBAG" diff login-git.txt | grep -qx "+$real_git" || fail "control: a login shell in the session did not find $real_git"
"$AIRBAG" diff shim-git.txt | grep -q "^+" || fail "control: no nonlogin git recorded"
"$AIRBAG" diff shim-git.txt | grep -qx "+$real_git" && fail "control: the shim is not first in a nonlogin shell"
"$AIRBAG" diff model-git.txt | grep -qx "+$real_git" && fail "the model's shell found $real_git: it ran a login shell"
rev=$("$AIRBAG" review)
echo "$rev" | grep -qF "git push origin main" || fail "the model's git push did not reach the outbox:
$rev"
[ "$(git -C "$T/remote.git" rev-parse main)" = "$before" ] || fail "the push reached the real remote"
"$AIRBAG" discard --yes >/dev/null
echo "PASS"
