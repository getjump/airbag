#!/bin/sh
# The label layer, reused beyond secrets: pulling content from a web
# host labels the session "untrusted", and a rule over `session.labels`
# then keeps that session from driving an irreversible effect (git push).
# This is the information-flow shape: data of a kind must not reach an
# effect of a kind. Run as a regular user.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-taint-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

git init -q --bare "$T/remote.git"
mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hi > README.md
cat > airbag.yaml <<'YAML'
allow: [httpbin.org]
rules:
  - name: no-push-after-untrusted
    when: '"untrusted" in session.labels && effect.kind == "intent.git_push"'
    verdict: deny
    message: content came from the web; a human must review the push
YAML
git add -A && git commit -qm init
git remote add origin "$T/remote.git" && git push -q origin main
head=$(git rev-parse HEAD)

# Pull web content (labels the session untrusted), then try to push.
# The push runs in a nested shell so it is judged at run time, after
# the fetch has set the label.
"$AIRBAG" run -- sh -c '
  curl -s -o /dev/null --max-time 10 https://httpbin.org/get
  echo A >> README.md && git add -A && git commit -qm change
  bash -c "git push origin main" 2> push.err && echo LEAK-PUSH-RAN
' > "$T/out" 2>&1 || true

grep -q LEAK-PUSH-RAN "$T/out" && fail "push ran after untrusted input: $(cat "$T/out")"
rev=$("$AIRBAG" review)
echo "$rev" | grep -q "Untrusted  input pulled from: httpbin.org" || fail "review does not show untrusted input:
$rev"
"$AIRBAG" diff push.err | grep -q 'no-push-after-untrusted' || fail "push not denied by the label rule: $("$AIRBAG" diff push.err)"
"$AIRBAG" log | grep 'proc.exec' | grep -q 'deny.*git push origin main.*no-push-after-untrusted' || fail "deny not in the log: $("$AIRBAG" log | grep proc.exec)"
echo "$rev" | grep -q "Outbox     0" || fail "an intent was queued despite the deny:
$rev"
[ "$(git -C "$T/remote.git" rev-parse main)" = "$head" ] || fail "the remote moved"
"$AIRBAG" discard --yes >/dev/null
echo PASS
