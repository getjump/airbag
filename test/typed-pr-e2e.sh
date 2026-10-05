#!/bin/sh
# Real sandbox capture/apply with a host-only fake GitHub API. No PRs are
# actually published; the POST and exact JSON bytes are recorded for assertions.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-typed-pr-e2e.XXXXXX")
L=$(mktemp -d /tmp/airbag-typed-pr-e2e.XXXXXX)
trap 'rm -rf "$T" "$L"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
mkdir "$T/bin" "$T/proj"
cd "$T/proj"
git init -q -b main
git config user.email e2e@example.com
git config user.name e2e
printf 'defer: [gh pr create]\n' > airbag.yaml
printf 'base\n' > code.txt
git add -A && git commit -qm base

# /tmp is private inside the sandbox, so premature API use cannot write L.
cat > "$T/bin/gh" <<EOS
#!/bin/sh
set -eu
echo "\$*" >> "$L/calls"
branch=\$(cat "$L/branch")
sha=\$(git -C "$T/proj" rev-parse "refs/heads/\$branch")
# As gh api --include does: a status line, headers, a blank line, the body.
printf 'HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n'
if [ "\$5" = GET ]; then
    printf '{"object":{"sha":"%s"}}\n' "\$sha"
else
    cat > "$L/payload"
    [ "\$(cat "$L/mode")" = race ] && sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    python3 - "\$sha" "$L/payload" <<'PY'
import json, sys
p = json.load(open(sys.argv[2]))
print(json.dumps(dict(number=7, html_url='https://github.com/getjump/airbag/pull/7',
    title=p['title'], body=p['body'], draft=p['draft'],
    head=dict(sha=sys.argv[1], ref=p['head'], repo=dict(full_name='getjump/airbag')),
    base=dict(ref=p['base'], repo=dict(full_name='getjump/airbag')))))
PY
fi
EOS
chmod +x "$T/bin/gh"
PATH="$T/bin:$PATH"
export PATH
newest() { "$AIRBAG" ls | awk 'NR==1{print $1}'; }

cat > "$T/agent.sh" <<'EOS'
set -e
git checkout -qb work
printf 'agent code\n' > code.txt
printf 'reviewed body\n' > notes.md
git add -A && git commit -qm fix
gh pr create --repo getjump/airbag --base main --head work --title Fix --body-file notes.md --draft
printf 'changed after capture\n' > notes.md
# Incomplete create must be refused, with no legacy host-command fallback.
gh pr create --fill && exit 1
exit 0
EOS
"$AIRBAG" run --no-home -- sh "$T/agent.sh" > "$T/run" 2>&1 || fail "run: $(cat "$T/run")"
s1=$(newest)
grep -q '"outcome":"queued"' "$T/run" || fail "no explicit queued result"
grep -q 'unsupported typed PR option' "$T/run" || fail "implicit create was not refused"
[ ! -e "$L/calls" ] || fail "GitHub API ran while agent worked"
"$AIRBAG" outbox "$s1" --json > "$L/preview"
python3 - "$L/preview" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
assert len(rows) == 1
p = rows[0]['preview']
assert p['request']['pull_request']['body'] == 'reviewed body\n'
assert p['request_digest'].startswith('sha256:')
PY
[ ! -e "$L/calls" ] || fail "preview contacted GitHub"
echo work > "$L/branch"
echo ok > "$L/mode"
# Import git metadata and one file while another file remains in the session.
# The full commit ref exists now, but that partial selection cannot publish it.
"$AIRBAG" apply "$s1" --only .git --yes > "$L/partial-git"
printf 'y\ny\n' | "$AIRBAG" apply "$s1" --only code.txt > "$L/partial-code"
grep -q 'has not been fully applied' "$L/partial-code" || fail "partial import authorized the complete commit"
[ ! -e "$L/calls" ] || fail "partial import contacted GitHub"
"$AIRBAG" apply "$s1" --yes > "$L/apply"
[ ! -e "$L/calls" ] || fail "--yes published the request"
grep -q 'changed after capture' notes.md || fail "files not imported"
printf 'y\n' | "$AIRBAG" apply "$s1" > "$L/publish"
"$AIRBAG" review "$s1" --json > "$L/review"
python3 - "$L/payload" "$L/review" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
assert p['body'] == 'reviewed body\n' and p['head'] == 'work' and p['draft']
assert not p['maintainer_can_modify']
r = json.load(open(sys.argv[2]))
assert r['outbox'][0]['status'] == 'done'
assert r['outbox'][0]['result']['outcome'] == 'completed'
assert r['outbox'][0]['result']['value'] == 'https://github.com/getjump/airbag/pull/7'
PY
"$AIRBAG" apply "$s1" --yes >/dev/null
[ "$(grep -c -- '--method POST' "$L/calls")" = 1 ] || fail "published twice"

# Import onto a differently named branch, then detect a remote race after POST.
cat > "$T/agent2.sh" <<'EOS'
set -e
git checkout -qb work2
printf 'second change\n' > code.txt
git add -A && git commit -qm second
gh pr create --repo getjump/airbag --base main --head work2 --title Second --body 'second body'
EOS
"$AIRBAG" run --no-home -- sh "$T/agent2.sh" > "$T/run2" 2>&1 || fail "run2: $(cat "$T/run2")"
s2=$(newest)
"$AIRBAG" apply "$s2" --branch selected-2 --yes >/dev/null
echo selected-2 > "$L/branch"
echo race > "$L/mode"
printf 'y\n' | "$AIRBAG" apply "$s2" > "$L/race"
grep -q 'unknown' "$L/race" || fail "remote race was claimed as success"
"$AIRBAG" apply "$s2" --yes >/dev/null
[ "$(grep -c -- '--method POST' "$L/calls")" = 2 ] || fail "retried unknown publication"
echo PASS
