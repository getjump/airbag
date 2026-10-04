#!/bin/sh
# Package managers inside the sandbox go through http://airbag.mirror:
# every package and version lands in the effect log, artifacts are
# cached across sessions. Parts whose tool is missing are skipped.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-mirror-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hi > README.md && git add -A && git commit -qm init

want=""
script=""
if command -v go >/dev/null; then
	script="$script mkdir gm && cd gm && go mod init example.com/x >/dev/null 2>&1 && GOTOOLCHAIN=local GOFLAGS=-modcacherw GOMODCACHE=\$PWD/.modcache go get golang.org/x/text@v0.14.0 >/dev/null 2>&1 || echo 'LEAK: go get failed'; cd ..;"
	want="$want|go golang.org/x/text@v0.14.0"
fi
if command -v npm >/dev/null; then
	script="$script npm pack --silent left-pad@1.3.0 >/dev/null 2>&1 || echo 'LEAK: npm pack failed';"
	want="$want|npm left-pad left-pad-1.3.0.tgz"
fi
if python3 -m pip --version >/dev/null 2>&1; then
	script="$script python3 -m pip download -q --no-deps six==1.16.0 -d dl >/dev/null 2>&1 || echo 'LEAK: pip download failed';"
	want="$want|pypi six-1.16.0"
fi
[ -n "$script" ] || { echo "SKIP: no go, npm or pip"; exit 0; }

out=$("$AIRBAG" run -- sh -c "$script" 2>&1)
echo "$out" | grep -q LEAK && fail "$out"
rev=$("$AIRBAG" review)
echo "$want" | tr '|' '\n' | while read -r w; do
	[ -z "$w" ] && continue
	echo "$rev" | grep -qF "$w" || fail "review lacks '$w': $rev"
done
"$AIRBAG" log | grep -q 'net.egress.*proxy.golang.org\|net.egress.*registry.npmjs.org' && fail "a package manager bypassed the mirror"
"$AIRBAG" discard --yes >/dev/null

# Second session: the same artifacts come from the cache.
"$AIRBAG" run -- sh -c "$script" >/dev/null 2>&1
"$AIRBAG" log | grep 'pkg.fetch' | grep -qv cached && fail "artifacts fetched again: $("$AIRBAG" log | grep pkg.fetch)"
"$AIRBAG" discard --yes >/dev/null
echo PASS
