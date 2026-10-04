#!/bin/sh
# defer: calls a `defer:` entry in airbag.yaml names wait in the outbox
# and run on the host after review, each confirmed, on the files as
# they were queued; other calls of the same program run in the sandbox.
set -eu

AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-defer-e2e.XXXXXX")
# Calls are recorded under /tmp: on the host it is the real one, in the
# sandbox a private one, so a call made in the sandbox leaves no record.
L=$(mktemp -d /tmp/airbag-defer-e2e.XXXXXX)
trap 'rm -rf "$T" "$L"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

mkdir "$T/bin"
cat > "$T/bin/pubtool" <<EOS
#!/bin/sh
mkdir -p "$L" && echo "\$*" >> "$L/ran"
[ "\${1:-}" = status ] && echo here > status-ran
exit 0
EOS
chmod +x "$T/bin/pubtool"
PATH="$T/bin:$PATH"
export PATH

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main
git config user.email e2e@example.com && git config user.name e2e
cat > airbag.yaml <<'EOS'
defer: [pubtool release]
rules:
  - name: no-v9
    when: effect.kind == "intent.cmd" && command.argv.exists(a, a == "v9")
    verdict: deny
    message: not v9
EOS
printf 'base\n' > a.txt && git add -A && git commit -qm init

newest() { "$AIRBAG" ls | awk 'NR==1{print $1}'; }

cat > "$T/agent.sh" <<'EOS'
printf 'notes v1\n' > notes.md
pubtool release v1 --notes notes.md
pubtool status
printf 'body\n' > /tmp/body.md
pubtool release v2 --notes /tmp/body.md || echo "exit $?"
pubtool release v9 || echo "exit $?"
sh -c 'pubtool release v3'
exit 0
EOS
"$AIRBAG" run -- sh "$T/agent.sh" > "$T/out" 2>&1 || fail "run: $(cat "$T/out")"
s1=$(newest)
grep -q "queued as intent i-1" "$T/out" || fail "release v1 not queued: $(cat "$T/out")"
grep -q "outside the workspace" "$T/out" || fail "a file outside the workspace was accepted: $(cat "$T/out")"
grep -q "not v9" "$T/out" || fail "the deny rule did not apply: $(cat "$T/out")"
grep -q "queued as intent i-2" "$T/out" || fail "release v3 through sh -c not queued: $(cat "$T/out")"
[ ! -e "$L/ran" ] || fail "something ran on the host during the session: $(cat "$L/ran")"
[ ! -e status-ran ] || fail "the sandbox wrote to the real workspace"

r=$("$AIRBAG" review "$s1")
echo "$r" | grep -q "pubtool release v1 --notes notes.md" || fail "review does not list the intent: $r"
echo "$r" | grep -q "runs only on these as queued: notes.md" || fail "review does not show the pinned file: $r"
"$AIRBAG" review --json "$s1" | grep -q '"kind": "cmd"' || fail "json review lacks the intent kind"

out=$("$AIRBAG" apply --yes "$s1")
echo "$out" | grep -q "without --yes" || fail "--yes did not hold the commands: $out"
[ -e status-ran ] || fail "the call that runs in the sandbox did not run there"
[ ! -e "$L/ran" ] || fail "--yes ran a deferred command: $(cat "$L/ran")"

out=$(printf 'y\nn\n' | "$AIRBAG" apply "$s1")
grep -q "^release v1 --notes notes.md$" "$L/ran" || fail "release v1 did not run on the host: $out"
grep -q "v3" "$L/ran" && fail "a rejected command ran"
"$AIRBAG" review "$s1" | grep -q "i-2 .*rejected" || fail "i-2 not rejected: $("$AIRBAG" review "$s1")"

# A file the command names changed after it was queued: it does not run.
cat > "$T/agent2.sh" <<'EOS'
printf 'notes v4\n' > notes.md
pubtool release v4 --notes notes.md
EOS
"$AIRBAG" run -- sh "$T/agent2.sh" >/dev/null 2>&1
s2=$(newest)
"$AIRBAG" apply --yes "$s2" >/dev/null
printf 'edited after apply\n' > notes.md
out=$(printf 'y\n' | "$AIRBAG" apply "$s2")
echo "$out" | grep -q "notes.md is not what it was" || fail "changed file not caught: $out"
grep -q v4 "$L/ran" && fail "release v4 ran on changed notes"

# apply --branch leaves the working tree as it was, so commands wait.
cat > "$T/agent3.sh" <<'EOS'
printf 'v5\n' > v5.txt
pubtool release v5
EOS
git add -A && git commit -qm "user: notes"
"$AIRBAG" run -- sh "$T/agent3.sh" >/dev/null 2>&1
out=$("$AIRBAG" apply --branch v5 "$(newest)")
echo "$out" | grep -q "left pending: the session's work is on branch v5" || fail "command not held for --branch: $out"
grep -q v5 "$L/ran" && fail "release v5 ran"
echo "PASS"
